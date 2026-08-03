// Package correlation implements the correlation, identity, and enrichment engine for DIS.
//
// File:    apps/discovery-service/internal/correlation/debounce.go
// Version: 2.3
package correlation

import (
    "context"
    "encoding/json"
    "log/slog"
    "strings"
    "sync"
    "time"

    "github.com/user/lias-dis/apps/discovery-service/internal/api"
    "github.com/user/lias-dis/apps/discovery-service/internal/discovery"
    "github.com/user/lias-dis/shared/models"
)

// PendingEventStore defines the interface for persisting pending events.
type PendingEventStore interface {
    SavePendingEvent(pdid, eventType string, payload []byte, firstSeen, lastSeen time.Time, confirmations int, sources string) error
    DeletePendingEvent(pdid, eventType string) error
}

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
    store         PendingEventStore
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

// SetStore attaches a storage backend for crash recovery.
func (d *Debouncer) SetStore(store PendingEventStore) {
    d.mu.Lock()
    defer d.mu.Unlock()
    d.store = store
}

// LoadPending loads pending events from storage into memory on startup.
func (d *Debouncer) LoadPending(records []PendingEventRecord) {
    d.mu.Lock()
    defer d.mu.Unlock()

    for _, r := range records {
        var payload models.DeviceEventPayload
        if err := json.Unmarshal(r.Payload, &payload); err != nil {
            continue
        }

        reqConf := 1
        evtType := models.EventType(r.EventType)
        if evtType == models.EventHostnameChanged || evtType == models.EventMACChanged || evtType == models.EventDeviceOnline {
            reqConf = 2
        }

        sources := strings.Split(r.Sources, ",")
        srcMap := make(map[string]bool)
        confirmedBy := []string{}
        for _, s := range sources {
            if s != "" {
                srcMap[s] = true
                confirmedBy = append(confirmedBy, s)
            }
        }

        d.pending[r.PDID+":"+r.EventType] = &PendingChange{
            PDID:                  r.PDID,
            EventType:             evtType,
            Payload:               payload,
            FirstSeen:             r.FirstSeen,
            LastSeen:              r.LastSeen,
            Confirmations:         r.Confirmations,
            RequiredConfirmations: reqConf,
            Sources:               srcMap,
            ConfirmedBy:           confirmedBy,
        }
    }
}

// PendingEventRecord is duplicated here to avoid import cycles if storage imports correlation.
// In practice, it's defined in storage and passed here.
type PendingEventRecord struct {
    PDID          string
    EventType     string
    Payload       []byte
    FirstSeen     time.Time
    LastSeen      time.Time
    Confirmations int
    Sources       string
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

    if group != "" {
        p.SourceGroups[group] = true
    }

    if !p.Sources[source] {
        p.Sources[source] = true
        p.ConfirmedBy = append(p.ConfirmedBy, source)
    }

    if len(p.SourceGroups) > 0 {
        p.Confirmations = len(p.SourceGroups)
    } else {
        p.Confirmations = len(p.Sources)
    }

    // GAP-D11: Persist pending state for crash recovery
    if d.store != nil {
        payloadBytes, _ := json.Marshal(p.Payload)
        sourcesStr := strings.Join(p.ConfirmedBy, ",")
        _ = d.store.SavePendingEvent(p.PDID, string(p.EventType), payloadBytes, p.FirstSeen, p.LastSeen, p.Confirmations, sourcesStr)
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

            // GAP-D11: Remove from storage once broadcasted
            if d.store != nil {
                _ = d.store.DeletePendingEvent(p.PDID, string(p.EventType))
            }
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
