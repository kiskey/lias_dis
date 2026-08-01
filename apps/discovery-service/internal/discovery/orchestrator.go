// Package discovery implements the core observation, enrichment, and
// correlation logic for the Discovery Intelligence Service.
//
// File:    apps/discovery-service/internal/discovery/orchestrator.go
// Version: 1.0
package discovery

import (
    "context"
    "log/slog"
    "sync"
    "time"

    disAPI "github.com/user/lias-dis/apps/discovery-service/internal/api"
    "github.com/user/lias-dis/apps/discovery-service/internal/inventory"
    "github.com/user/lias-dis/shared/models"
)

// Orchestrator manages on-demand enrichment, implementing the failover and
// fallback logic. It ensures primary interfaces are tried first, and Nmap
// is only used as a secondary backup fallback if primary yields no results.
type Orchestrator struct {
    cache     *inventory.Cache
    broker    *disAPI.Broker
    primaries []Enricher // Avahi, SSDP, NetBIOS
    fallback  Enricher   // Nmap
}

// NewOrchestrator initializes the enrichment orchestrator.
func NewOrchestrator(cache *inventory.Cache, broker *disAPI.Broker, primaries []Enricher, fallback Enricher) *Orchestrator {
    return &Orchestrator{
        cache:     cache,
        broker:    broker,
        primaries: primaries,
        fallback:  fallback,
    }
}

// TriggerEnrichment executes the enrichment pipeline for a device.
// If force is false, it skips enrichment if the device already has vendor/type data.
func (o *Orchestrator) TriggerEnrichment(pdid string, force bool) {
    dev := o.cache.Get(pdid)
    if dev == nil {
        return
    }

    // Skip if already known and not forced
    if !force && dev.Vendor != "" && dev.DeviceType != "" {
        return
    }

    slog.Info("Triggering enrichment pipeline", "pdid", pdid, "force", force, "current_vendor", dev.Vendor)

    // 1. Run primary enrichers concurrently
    var wg sync.WaitGroup
    primaryResults := make(chan *models.Enrichment, len(o.primaries))

    for _, e := range o.primaries {
        wg.Add(1)
        go func(enr Enricher) {
            defer wg.Done()
            res, err := enr.Enrich(context.Background(), dev)
            if err != nil {
                slog.Debug("Primary enricher failed", "enricher", enr.Name(), "error", err)
                return
            }
            primaryResults <- res
        }(e)
    }

    wg.Wait()
    close(primaryResults)

    changed := false
    for res := range primaryResults {
        if res != nil {
            changed = applyEnrichment(dev, res) || changed
        }
    }

    // 2. Fallback to Nmap if still unknown (no vendor/type) or if no primary results
    if (!changed || dev.Vendor == "" || dev.DeviceType == "") && o.fallback != nil {
        slog.Info("Primary enrichment insufficient, falling back to Nmap", "pdid", pdid)
        res, err := o.fallback.Enrich(context.Background(), dev)
        if err != nil {
            slog.Debug("Fallback enricher failed", "enricher", o.fallback.Name(), "error", err)
        } else if res != nil {
            changed = applyEnrichment(dev, res) || changed
        }
    }

    // 3. Update cache and broadcast if changed
    if changed {
        dev.Touch(time.Now())
        o.cache.Upsert(dev)
        o.broker.Broadcast(models.NewEvent(models.EventFingerprintUpdated, dev.PDID, dev))
        slog.Info("Enrichment pipeline completed with updates", "pdid", pdid)
    } else {
        slog.Info("Enrichment pipeline completed, no changes", "pdid", pdid)
    }
}

// applyEnrichment safely merges an Enrichment result into a Device based on
// industry-standard confidence hierarchy (higher confidence overwrites lower).
// Returns true if the device struct was modified.
func applyEnrichment(dev *models.Device, enr *models.Enrichment) bool {
    changed := false
    
    if enr.Hostname != "" && (dev.Hostname == "" || enr.Confidence > dev.Confidence) {
        dev.Hostname = enr.Hostname
        changed = true
    }
    if enr.FriendlyName != "" && dev.FriendlyName != enr.FriendlyName {
        dev.FriendlyName = enr.FriendlyName
        changed = true
    }
    if enr.Manufacturer != "" && (dev.Manufacturer == "" || enr.Confidence > dev.Confidence) {
        dev.Manufacturer = enr.Manufacturer
        changed = true
    }
    if enr.Vendor != "" && (dev.Vendor == "" || enr.Confidence > dev.Confidence) {
        dev.Vendor = enr.Vendor
        changed = true
    }
    if enr.Model != "" && (dev.Model == "" || enr.Confidence > dev.Confidence) {
        dev.Model = enr.Model
        changed = true
    }
    if enr.DeviceType != "" && (dev.DeviceType == "" || enr.Confidence > dev.Confidence) {
        dev.DeviceType = enr.DeviceType
        changed = true
    }
    
    for _, svc := range enr.Services {
        dev.AddService(svc)
        changed = true
    }
    
    return changed
}
