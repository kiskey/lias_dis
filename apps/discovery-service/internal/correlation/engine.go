// Package correlation implements the engine that merges raw observations
// from multiple providers into canonical device records.
//
// File:    apps/discovery-service/internal/correlation/engine.go
// Version: 1.4
package correlation

import (
	"context"
	"log/slog"
	"strings"
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

// Run starts the engine, listening to all provided discovery channels concurrently.
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

// findDevice searches the cache for an existing device record matching MAC or IP.
func (e *Engine) findDevice(macStr, ipStr string) *models.Device {
	devs := e.cache.List()
	for i := range devs {
		d := &devs[i]
		if macStr != "" {
			for _, m := range d.MACs {
				if inventory.NormalizeMAC(m) == macStr {
					return d
				}
			}
		}
		if ipStr != "" {
			for _, ip := range d.IPs {
				if strings.TrimSpace(ip) == ipStr {
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
		macStr = inventory.NormalizeMAC(obs.MAC.String())
	}
	ipStr := ""
	if obs.IP != nil {
		ipStr = strings.TrimSpace(obs.IP.String())
	}

	if macStr == "" && ipStr == "" {
		return
	}

	// 1. Handle explicit offline events (e.g. Netlink RTM_DELNEIGH or ARP failure)
	if !obs.Online {
		d := e.findDevice(macStr, ipStr)
		if d != nil && d.Online {
			d.Online = false
			d.LastSeen = time.Now()
			e.cache.Upsert(d)
			e.broker.Broadcast(models.NewEvent(models.EventDeviceOffline, d.PDID, models.DeviceEventPayload{
				PDID:      d.PDID,
				MAC:       macStr,
				IP:        ipStr,
				Timestamp: time.Now(),
			}))
			slog.Info("Device transitioned offline", "pdid", d.PDID, "mac", macStr, "ip", ipStr)
		}
		return
	}

	// 2. Handle online observation
	d := e.findDevice(macStr, ipStr)
	if d == nil {
		// Create new device record with deterministic PDID
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
		slog.Info("New device correlated", "pdid", pdid, "mac", macStr, "ip", ipStr, "vendor", obs.Vendor)
		e.broker.Broadcast(models.NewEvent(models.EventDeviceAdded, d.PDID, d))

		// Trigger asynchronous enrichment for newly added device
		if e.orch != nil {
			go e.orch.TriggerEnrichment(d.PDID, false)
		}
		return
	}

	// 3. Update existing device
	changed := false
	var eventTypes []models.EventType
	payload := models.DeviceEventPayload{
		PDID:      d.PDID,
		Timestamp: time.Now(),
	}

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

	if obs.Vendor != "" && (d.Vendor == "" || obs.Confidence >= d.Confidence) {
		if d.Vendor != obs.Vendor {
			d.Vendor = obs.Vendor
			changed = true
			eventTypes = append(eventTypes, models.EventFingerprintUpdated)
		}
	}

	if obs.Model != "" && (d.Model == "" || obs.Confidence >= d.Confidence) {
		if d.Model != obs.Model {
			d.Model = obs.Model
			changed = true
			eventTypes = append(eventTypes, models.EventFingerprintUpdated)
		}
	}

	d.Touch(time.Now())
	if changed {
		e.cache.Upsert(d)
		for _, et := range eventTypes {
			e.broker.Broadcast(models.NewEvent(et, d.PDID, payload))
		}
	}

	// Trigger enrichment if device remains unclassified
	if (d.Vendor == "" || d.DeviceType == "") && e.orch != nil {
		go e.orch.TriggerEnrichment(d.PDID, false)
	}
}
