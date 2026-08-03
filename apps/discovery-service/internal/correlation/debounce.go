// Package correlation implements the correlation, identity, and enrichment engine for DIS.
//
// File:    apps/discovery-service/internal/correlation/debounce.go
// Version: 2.0
package correlation

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/user/lias-dis/apps/discovery-service/internal/api"
	"github.com/user/lias-dis/apps/discovery-service/internal/discovery"
	"github.com/user/lias-dis/shared/models"
)

// PendingChange tracks a state change awaiting confirmation before broadcast.
type PendingChange struct {
	PDID                  string
	EventType             models.EventType
	Payload               models.DeviceEventPayload
	FirstSeen             time.Time
	LastSeen              time.Time
	Confirmations         int
	RequiredConfirmations int
	Sources               map[string]bool
	SourceGroups          map[discovery.ProviderGroup]bool
	ConfirmedBy           []string
}

// Debouncer manages coalescing, confirmation windows, and revert suppression for events.
type Debouncer struct {
	mu            sync.Mutex
	broker        *api.Broker
	pending       map[string]*PendingChange // Key: pdid + ":" + event_type
	recentValues  map[string]string         // Key: pdid + ":" + field -> recent value for revert suppression
	recentValTime map[string]time.Time
}

// NewDebouncer initializes the event debouncer.
func NewDebouncer(broker *api.Broker) *Debouncer {
	return &Debouncer{
		broker:        broker,
		pending:       make(map[string]*PendingChange),
		recentValues:  make(map[string]string),
		recentValTime: make(map[string]time.Time),
	}
}

// Run starts the 5-second coalescing flush loop.
func (d *Debouncer) Run(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			d.Flush()
		}
	}
}

// Submit receives a candidate state delta and applies confirmation/revert suppression rules (§7.2, §7.3).
func (d *Debouncer) Submit(pdid string, eventType models.EventType, source string, group discovery.ProviderGroup, payload models.DeviceEventPayload) {
	d.mu.Lock()
	defer d.mu.Unlock()

	now := time.Now()
	key := pdid + ":" + string(eventType)

	// Revert Suppression check (§7.4)
	switch eventType {
	case models.EventHostnameChanged:
		valKey := pdid + ":hostname"
		if prevVal, exists := d.recentValues[valKey]; exists {
			if HostnamesAreEquivalent(payload.Hostname, prevVal) && now.Sub(d.recentValTime[valKey]) < 60*time.Second {
				slog.Debug("Suppressed transient hostname suffix revert event", "pdid", pdid, "host", payload.Hostname)
				delete(d.pending, key)
				return
			}
		}
		d.recentValues[valKey] = payload.OldHost
		d.recentValTime[valKey] = now

	case models.EventIPChanged:
		valKey := pdid + ":ip"
		if prevVal, exists := d.recentValues[valKey]; exists {
			if payload.IP == prevVal && now.Sub(d.recentValTime[valKey]) < 30*time.Second {
				slog.Debug("Suppressed transient IP revert event", "pdid", pdid, "ip", payload.IP)
				delete(d.pending, key)
				return
			}
		}
		d.recentValues[valKey] = payload.OldIP
		d.recentValTime[valKey] = now
	}

	p, exists := d.pending[key]
	if !exists {
		reqConf := 1
		if eventType == models.EventHostnameChanged || eventType == models.EventMACChanged || eventType == models.EventDeviceOnline {
			reqConf = 2
		}

		p = &PendingChange{
			PDID:                  pdid,
			EventType:             eventType,
			Payload:               payload,
			FirstSeen:             now,
			LastSeen:              now,
			Confirmations:         0,
			RequiredConfirmations: reqConf,
			Sources:               make(map[string]bool),
			SourceGroups:          make(map[discovery.ProviderGroup]bool),
		}
		d.pending[key] = p
	}

	p.LastSeen = now

	// Track layer independence across provider groups (§7.3)
	if group != "" {
		p.SourceGroups[group] = true
	}

	if !p.Sources[source] {
		p.Sources[source] = true
		p.ConfirmedBy = append(p.ConfirmedBy, source)
	}

	// Confirmations count unique independent provider groups (§7.3)
	if len(p.SourceGroups) > 0 {
		p.Confirmations = len(p.SourceGroups)
	} else {
		p.Confirmations = len(p.Sources)
	}
}

// Flush evaluates confirmed pending changes and broadcasts enriched events.
func (d *Debouncer) Flush() {
	d.mu.Lock()
	defer d.mu.Unlock()

	now := time.Now()
	for key, p := range d.pending {
		if p.Confirmations >= p.RequiredConfirmations || now.Sub(p.FirstSeen) > 10*time.Second {
			p.Payload.ConfirmedBy = p.ConfirmedBy
			evt := models.NewEvent(p.EventType, p.PDID, p.Payload)
			d.broker.Broadcast(evt)
			delete(d.pending, key)
		}
	}

	// Clean up stale revert suppression history
	for k, t := range d.recentValTime {
		if now.Sub(t) > 5*time.Minute {
			delete(d.recentValues, k)
			delete(d.recentValTime, k)
		}
	}
}
