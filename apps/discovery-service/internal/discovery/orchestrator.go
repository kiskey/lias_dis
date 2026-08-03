// Package discovery implements the core observation, enrichment, and
// correlation logic for the Discovery Intelligence Service.
//
// File:    apps/discovery-service/internal/discovery/orchestrator.go
// Version: 1.3
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

const (
    // Minimum cool-down interval before re-attempting enrichment on an unidentified device
    enrichmentCooldown = 1 * time.Hour
)

// IdentityPromoter allows the Orchestrator to trigger PDID promotion in the Engine.
type IdentityPromoter interface {
    PromoteDeviceIdentity(pdid string) *models.Device
}

// Orchestrator manages on-demand enrichment with concurrency locking and failure backoff per PDID.
type Orchestrator struct {
    cache          *inventory.Cache
    broker         *disAPI.Broker
    primaries      []Enricher // Avahi, SSDP, NetBIOS
    fallback       Enricher   // Nmap
    activeLocks    sync.Map   // Prevents duplicate concurrent enrichments for the same PDID
    lastAttemptMap sync.Map   // Maps PDID -> time.Time to enforce 1-hour backoff on stubborn unknown devices
    promoter       IdentityPromoter
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

// SetIdentityPromoter attaches the engine promoter interface.
func (o *Orchestrator) SetIdentityPromoter(p IdentityPromoter) {
    o.promoter = p
}

// TriggerEnrichment executes the enrichment pipeline for a target device.
// Enforces a 1-hour cool-down period for stubborn unknown devices to avoid continuous network probing.
func (o *Orchestrator) TriggerEnrichment(pdid string, force bool) {
    if pdid == "" {
        return
    }

    dev := o.cache.Get(pdid)
    if dev == nil {
        return
    }

    // 1. Skip immediately if device is ALREADY fully classified (Vendor + DeviceType known)
    if !force && dev.Vendor != "" && dev.DeviceType != "" {
        return
    }

    // 2. Cool-Down Safeguard: If enrichment failed previously, do NOT probe again within 1 hour
    if !force {
        if lastAttempt, found := o.lastAttemptMap.Load(pdid); found {
            if time.Since(lastAttempt.(time.Time)) < enrichmentCooldown {
                slog.Debug("Device in 1-hour enrichment cool-down, skipping scan", "pdid", pdid)
                return
            }
        }
    }

    // 3. Deduplicate in-flight concurrent triggers for the same PDID
    if _, loaded := o.activeLocks.LoadOrStore(pdid, struct{}{}); loaded {
        slog.Debug("Enrichment already in progress, skipping duplicate trigger", "pdid", pdid)
        return
    }
    defer o.activeLocks.Delete(pdid)

    // Record attempt timestamp for cool-down tracking
    o.lastAttemptMap.Store(pdid, time.Now())

    slog.Info("Executing enrichment pipeline", "pdid", pdid, "force", force, "ip", dev.CurrentIP)

    // 4. Run primary enrichers (Avahi, SSDP, NetBIOS) concurrently
    var wg sync.WaitGroup
    primaryResults := make(chan *models.Enrichment, len(o.primaries))

    for _, e := range o.primaries {
        wg.Add(1)
        go func(enr Enricher) {
            defer wg.Done()
            ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
            defer cancel()

            res, err := enr.Enrich(ctx, dev)
            if err != nil {
                slog.Debug("Primary enricher failed", "enricher", enr.Name(), "error", err)
                return
            }
            if res != nil {
                primaryResults <- res
            }
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

    // 5. Fall back to Nmap if device remains unclassified
    if (!changed || dev.Vendor == "" || dev.DeviceType == "") && o.fallback != nil {
        slog.Info("Primary enrichment incomplete, executing Nmap fallback", "pdid", pdid)
        ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
        res, err := o.fallback.Enrich(ctx, dev)
        cancel()

        if err != nil {
            slog.Debug("Fallback enricher failed", "enricher", o.fallback.Name(), "error", err)
        } else if res != nil {
            changed = applyEnrichment(dev, res) || changed
        }
    }

    // 6. Persist modifications and broadcast event
    if changed {
        dev.Touch(time.Now())
        
        var finalDev *models.Device = dev
        // Network Engineer Fix: Trigger identity promotion if enrichment provided new L7 data
        if o.promoter != nil {
            promotedDev := o.promoter.PromoteDeviceIdentity(dev.PDID)
            if promotedDev != nil {
                finalDev = promotedDev
            }
        }
        
        o.cache.Upsert(finalDev)
        o.broker.Broadcast(models.NewEvent(models.EventFingerprintUpdated, finalDev.PDID, finalDev))
        slog.Info("Enrichment pipeline completed with device updates", "pdid", finalDev.PDID, "type", finalDev.DeviceType, "vendor", finalDev.Vendor)
    } else {
        slog.Debug("Enrichment pipeline completed without new findings", "pdid", pdid)
    }
}

// applyEnrichment merges enrichment findings using confidence hierarchy rules.
func applyEnrichment(dev *models.Device, enr *models.Enrichment) bool {
    if dev == nil || enr == nil {
        return false
    }

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
