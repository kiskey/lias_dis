// Package correlation implements the engine that merges raw observations
// from multiple providers into canonical device records.
//
// File:    apps/discovery-service/internal/correlation/engine.go
// Version: 1.7
package correlation

import (
	"context"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/user/lias-dis/apps/discovery-service/internal/api"
	"github.com/user/lias-dis/apps/discovery-service/internal/discovery"
	"github.com/user/lias-dis/apps/discovery-service/internal/inventory"
	"github.com/user/lias-dis/shared/models"
)

type EnrichmentOrchestrator interface {
	TriggerEnrichment(pdid string, force bool)
}

type Engine struct {
	cache       *inventory.Cache
	broker      *api.Broker
	orch        EnrichmentOrchestrator
	dedupMu     sync.Mutex
	lastSeenObs map[string]time.Time
}

func NewEngine(cache *inventory.Cache, broker *api.Broker) *Engine {
	return &Engine{
		cache:       cache,
		broker:      broker,
		lastSeenObs: make(map[string]time.Time),
	}
}

func (e *Engine) SetOrchestrator(orch EnrichmentOrchestrator) {
	e.orch = orch
}

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

func (e *Engine) isDuplicateObservation(macStr, ipStr string, online bool) bool {
	key := macStr + "|" + ipStr
	now := time.Now()

	e.dedupMu.Lock()
	defer e.dedupMu.Unlock()

	if last, found := e.lastSeenObs[key]; found {
		if now.Sub(last) < 2*time.Second {
			return true
		}
	}

	e.lastSeenObs[key] = now

	if len(e.lastSeenObs) > 1000 {
		for k, t := range e.lastSeenObs {
			if now.Sub(t) > 10*time.Second {
				delete(e.lastSeenObs, k)
			}
		}
	}

	return false
}

func (e *Engine) processObservation(obs discovery.Observation) {
	// Filter Multicast and Loopback targets
	if discovery.IsMulticastOrBroadcast(obs.MAC, obs.IP) {
		return
	}

	macStr := ""
	if obs.MAC != nil {
		macStr = inventory.NormalizeMAC(obs.MAC.String())
	}
	ipStr := ""
	if obs.IP != nil {
		ipStr = obs.IP.String()
	}

	if macStr == "" && ipStr == "" {
		return
	}

	if e.isDuplicateObservation(macStr, ipStr, obs.Online) {
		return
	}

	cleanHost := discovery.UnescapeHostname(obs.Hostname)

	// Handle offline event
	if !obs.Online {
		d := e.cache.GetByMACOrIP(macStr, ipStr)
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

	// Handle online observation
	d := e.cache.GetByMACOrIP(macStr, ipStr)
	if d == nil {
		pdid := inventory.GeneratePDID(macStr, cleanHost, obs.Vendor)
		d = &models.Device{
			PDID:       pdid,
			Hostname:   cleanHost,
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

		// Auto-classify Gateway Routers and Amazon Alexa devices
		ApplySmartClassifications(d)

		e.cache.Upsert(d)
		slog.Info("New device correlated", "pdid", pdid, "mac", macStr, "ip", ipStr, "vendor", d.Vendor, "type", d.DeviceType)
		e.broker.Broadcast(models.NewEvent(models.EventDeviceAdded, d.PDID, d))

		if e.orch != nil {
			go e.orch.TriggerEnrichment(d.PDID, false)
		}
		return
	}

	// Update existing device
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

	if cleanHost != "" && d.Hostname != cleanHost {
		payload.OldHost = d.Hostname
		d.Hostname = cleanHost
		payload.Hostname = cleanHost
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

	ApplySmartClassifications(d)

	d.Touch(time.Now())
	if changed {
		e.cache.Upsert(d)
		for _, et := range eventTypes {
			e.broker.Broadcast(models.NewEvent(et, d.PDID, payload))
		}
	}

	if (d.Vendor == "" || d.DeviceType == "") && e.orch != nil {
		go e.orch.TriggerEnrichment(d.PDID, false)
	}
}

// ApplySmartClassifications automatically categorizes routers and Amazon Echo devices.
func ApplySmartClassifications(d *models.Device) {
	if d == nil {
		return
	}

	// 1. Gateway Router Detection (192.168.x.1 or .254)
	if d.CurrentIP != "" {
		ip := net.ParseIP(d.CurrentIP)
		if ip != nil && ip.To4() != nil {
			ip4 := ip.To4()
			if ip4[3] == 1 || ip4[3] == 254 {
				d.DeviceType = "infrastructure"
				if d.FriendlyName == "" {
					d.FriendlyName = "Network Gateway Router"
				}
			}
		}
	}

	// 2. Amazon Echo / Alexa Device Detection
	if strings.HasPrefix(d.Hostname, "amzn.") || strings.Contains(d.Hostname, "amzn.dmgr") {
		d.Vendor = "Amazon Technologies Inc."
		d.DeviceType = "iot"
		if d.FriendlyName == "" {
			d.FriendlyName = "Amazon Alexa Device"
		}
	}
}
