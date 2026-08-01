// Package correlation implements the engine that merges raw observations
// from multiple providers into canonical device records.
//
// File:    apps/discovery-service/internal/correlation/engine.go
// Version: 1.3
package correlation

import (
    "context"
    "log/slog"
    "time"

    "github.com/user/lias-dis/apps/discovery-service/internal/api"
    "github.com/user/lias-dis/apps/discovery-service/internal/discovery"
    "github.com/user/lias-dis/apps/discovery-service/internal/inventory"
    "github.com/user/lias-dis/shared/models"
)

// EnrichmentOrchestrator defines the interface for triggering on-demand enrichment.
type EnrichmentOrchestrator interface {
    TriggerEnrichment(pdid string, force bool)
}

// Engine consumes observations from discovery providers, correlates them
// into canonical device records, and updates the inventory cache.
type Engine struct {
    cache  *inventory.Cache
    broker *api.Broker
    orch   EnrichmentOrchestrator
}

// NewEngine initializes the correlation engine.
func NewEngine(cache *inventory.Cache, broker *api.Broker) *Engine {
    return &Engine{
        cache:  cache,
        broker: broker,
    }
}

// SetOrchestrator wires the enrichment orchestrator to the engine.
func (e *Engine) SetOrchestrator(orch EnrichmentOrchestrator) {
    e.orch = orch
}

// Run starts the engine, listening to all provided discovery channels.
func (e *Engine) Run(ctx context.Context, providers []discovery.DiscoveryProvider) {
    for _, p := range providers {
        go e.consume(ctx, p.Events())
    }
}

func (e *Engine) consume(ctx context.Context, ch <-chan discovery.Observation) {
    for {
        select {
        case <-ctx.Done():
            return
        case obs, ok := <-ch:
            if !ok {
                return
            }
            e.processObservation(obs)
        }
    }
}

// findDevice searches the cache for a device matching the given MAC or IP.
func (e *Engine) findDevice(mac, ip string) *models.Device {
    devs := e.cache.List()
    for i := range devs {
        d := &devs[i]
        if mac != "" {
            for _, m := range d.MACs {
                if m == mac {
                    return d
                }
            }
        }
        if ip != "" {
            for _, i := range d.IPs {
                if i == ip {
                    return d
                }
            }
        }
    }
    return nil
}

func (e *Engine) processObservation(obs discovery.Observation) {
    macStr := ""
    if obs.MAC != nil {
        macStr = obs.MAC.String()
    }
    ipStr := ""
    if obs.IP != nil {
        ipStr = obs.IP.String()
    }

    // Handle explicit offline events (e.g., netlink RTM_DELNEIGH)
    if !obs.Online {
        // Must have at least a MAC or IP to identify the device
        if macStr == "" && ipStr == "" {
            return
        }
        
        d := e.findDevice(macStr, ipStr)
        if d != nil && d.Online {
            d.Online = false
            d.LastSeen = time.Now()
            e.cache.Upsert(d)
            e.broker.Broadcast(models.NewEvent(models.EventDeviceOffline, d.PDID, models.DeviceEventPayload{
                PDID:      d.PDID,
                Timestamp: time.Now(),
            }))
        }
        return
    }

    // Handle online events
    // Must have at least a MAC or IP to proceed
    if macStr == "" && ipStr == "" {
        return
    }

    d := e.findDevice(macStr, ipStr)
    if d == nil {
        // New device
        pdid := inventory.GeneratePDID(macStr, obs.Hostname, obs.Vendor)
        d = &models.Device{
            PDID:       pdid,
            Hostname:   obs.Hostname,
            Vendor:     obs.Vendor,
            Model:      obs.Model,
            Online:     true,
            Confidence: obs.Confidence,
            SourceInfo: make(map[string]models.SourceMeta),
        }
        d.AddMAC(macStr)
        d.AddIP(ipStr)
        for _, svc := range obs.Services {
            d.AddService(svc)
        }
        d.Touch(time.Now())
        e.cache.Upsert(d)
        slog.Info("Device added", "pdid", pdid, "mac", macStr, "ip", ipStr)
        e.broker.Broadcast(models.NewEvent(models.EventDeviceAdded, d.PDID, d))

        // Trigger enrichment for new device
        if e.orch != nil {
            go e.orch.TriggerEnrichment(d.PDID, false)
        }
        return
    }

    // Existing device
    changed := false
    var eventTypes []models.EventType
    payload := models.DeviceEventPayload{
        PDID:      d.PDID,
        Timestamp: time.Now(),
    }

    // If device was offline, mark it online
    if !d.Online {
        d.Online = true
        changed = true
        eventTypes = append(eventTypes, models.EventDeviceOnline)
    }

    if macStr != "" && d.CurrentMAC != macStr {
        payload.OldMAC = d.CurrentMAC
        d.AddMAC(macStr)
        payload.MAC = macStr
        changed = true
        eventTypes = append(eventTypes, models.EventMACChanged)
    }

    if ipStr != "" && d.CurrentIP != ipStr {
        payload.OldIP = d.CurrentIP
        d.AddIP(ipStr)
        payload.IP = ipStr
        changed = true
        eventTypes = append(eventTypes, models.EventIPChanged)
    }

    if obs.Hostname != "" && d.Hostname != obs.Hostname {
        payload.OldHost = d.Hostname
        d.Hostname = obs.Hostname
        payload.Hostname = obs.Hostname
        changed = true
        eventTypes = append(eventTypes, models.EventHostnameChanged)
    }

    // Merge other fields based on confidence hierarchy (§3.4)
    if obs.Vendor != "" && (d.Vendor == "" || obs.Confidence > d.Confidence) {
        d.Vendor = obs.Vendor
        changed = true
        eventTypes = append(eventTypes, models.EventFingerprintUpdated)
    }
    if obs.Model != "" && (d.Model == "" || obs.Confidence > d.Confidence) {
        d.Model = obs.Model
        changed = true
        eventTypes = append(eventTypes, models.EventFingerprintUpdated)
    }

    d.Touch(time.Now())
    if changed {
        e.cache.Upsert(d)
        for _, et := range eventTypes {
            e.broker.Broadcast(models.NewEvent(et, d.PDID, payload))
        }
    }

    // Scheduled validation check: If device is unknown (no vendor/type), 
    // and we haven't checked recently, trigger enrichment.
    // This satisfies the "Unknown device (no vendor/type identified after 30 seconds)" rule.
    if d.Vendor == "" && d.DeviceType == "" && e.orch != nil {
        // We use a simple non-blocking trigger. The orchestrator handles skipping
        // if it's already running or already known.
        go func(pdid string) {
            time.Sleep(30 * time.Second)
            e.orch.TriggerEnrichment(pdid, false)
        }(d.PDID)
    }
}
