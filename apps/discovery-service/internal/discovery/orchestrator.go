// Package discovery implements the core observation, enrichment, and
// correlation logic for the Discovery Intelligence Service.
//
// File:    apps/discovery-service/internal/discovery/orchestrator.go
// Version: 2.1
package discovery

import (
    "context"
    "log/slog"
    "strings"
    "sync"
    "time"

    disAPI "github.com/user/lias-dis/apps/discovery-service/internal/api"
    "github.com/user/lias-dis/apps/discovery-service/internal/inventory"
    "github.com/user/lias-dis/shared/models"
)

const (
    enrichmentCooldown = 1 * time.Hour
)

// DeviceManager allows the Orchestrator to trigger PDID promotion and persistence in the Engine.
type DeviceManager interface {
    PromoteDeviceIdentity(pdid string) *models.Device
    PersistDevice(pdid string)
}

// Orchestrator manages on-demand enrichment with concurrency locking and failure backoff per PDID.
type Orchestrator struct {
    cache          *inventory.Cache
    broker         *disAPI.Broker
    primaries      []Enricher
    fallback       Enricher
    activeLocks    sync.Map
    lastAttemptMap sync.Map
    manager        DeviceManager
}

func NewOrchestrator(cache *inventory.Cache, broker *disAPI.Broker, primaries []Enricher, fallback Enricher) *Orchestrator {
    return &Orchestrator{
        cache:     cache,
        broker:    broker,
        primaries: primaries,
        fallback:  fallback,
    }
}

func (o *Orchestrator) SetDeviceManager(m DeviceManager) {
    o.manager = m
}

func (o *Orchestrator) TriggerEnrichment(pdid string, force bool) {
    if pdid == "" {
        return
    }

    dev := o.cache.Get(pdid)
    if dev == nil {
        return
    }

    if !force {
        if lastAttempt, found := o.lastAttemptMap.Load(pdid); found {
            if time.Since(lastAttempt.(time.Time)) < enrichmentCooldown {
                if dev.Vendor != "" && dev.DeviceType != "" && dev.FriendlyName != "" {
                    return
                }
                return
            }
        }
    }

    if _, loaded := o.activeLocks.LoadOrStore(pdid, struct{}{}); loaded {
        slog.Debug("Enrichment already in progress, skipping duplicate trigger", "pdid", pdid)
        return
    }
    defer o.activeLocks.Delete(pdid)

    o.lastAttemptMap.Store(pdid, time.Now())

    slog.Info("Executing enrichment pipeline", "pdid", pdid, "force", force, "ip", dev.CurrentIP)

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

    if changed {
        dev.Touch(time.Now())
        o.cache.Upsert(dev)
        
        var finalDev *models.Device = dev
        if o.manager != nil {
            promotedDev := o.manager.PromoteDeviceIdentity(dev.PDID)
            if promotedDev != nil {
                finalDev = promotedDev
            }
        }
        
        o.cache.Upsert(finalDev)
        
        if o.manager != nil {
            o.manager.PersistDevice(finalDev.PDID)
        }
        
        o.broker.Broadcast(models.NewEvent(models.EventFingerprintUpdated, finalDev.PDID, finalDev))
        slog.Info("Enrichment pipeline completed with device updates", "pdid", finalDev.PDID, "type", finalDev.DeviceType, "vendor", finalDev.Vendor)
    } else {
        slog.Debug("Enrichment pipeline completed without new findings", "pdid", pdid)
    }
}

// isGenericHostname checks if a hostname looks like a default MAC-based or DHCP ID string.
// Fix: Enhanced strict validation for MAC addresses, asterisks, and numeric strings.
func isGenericHostname(host string) bool {
    h := strings.ToLower(strings.TrimSpace(host))
    if h == "" || h == "*" { return true } // DHCP missing hostname
    if strings.HasPrefix(h, "android-") { return true }
    if strings.HasPrefix(h, "iphone") || strings.HasPrefix(h, "ipad") { return true }
    if strings.HasPrefix(h, "desktop-") || strings.HasPrefix(h, "localhost") { return true }
    if strings.Contains(h, "unknown") { return true }
    
    // Strict Hex MAC address check (12 chars, 0-9 a-f)
    if len(h) == 12 {
        isHex := true
        for _, c := range h {
            if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
                isHex = false
                break
            }
        }
        if isHex { return true }
    }
    
    // Check if it's purely numeric (some IoT devices use IDs)
    isNumeric := true
    for _, c := range h {
        if !(c >= '0' && c <= '9') {
            isNumeric = false
            break
        }
    }
    if isNumeric { return true }
    
    return false
}

// applyEnrichment strictly applies only material changes.
func applyEnrichment(dev *models.Device, enr *models.Enrichment) bool {
    if dev == nil || enr == nil {
        return false
    }

    changed := false

    // FriendlyName: Update if it's different (handles renames)
    if enr.FriendlyName != "" && dev.FriendlyName != enr.FriendlyName {
        dev.FriendlyName = enr.FriendlyName
        changed = true
    }

    // Hostname: Update if empty, OR if current is generic AND new is NOT generic, OR strictly better confidence
    if enr.Hostname != "" {
        shouldUpdate := false
        if dev.Hostname == "" {
            shouldUpdate = true
        } else if isGenericHostname(dev.Hostname) && !isGenericHostname(enr.Hostname) {
            shouldUpdate = true
        } else if enr.Confidence > dev.Confidence {
            shouldUpdate = true
        }

        if shouldUpdate && dev.Hostname != enr.Hostname {
            dev.Hostname = enr.Hostname
            changed = true
        }
    }

    // Manufacturer: Update if empty or strictly better confidence
    if enr.Manufacturer != "" && (dev.Manufacturer == "" || enr.Confidence > dev.Confidence) {
        if dev.Manufacturer != enr.Manufacturer {
            dev.Manufacturer = enr.Manufacturer
            changed = true
        }
    }
    
    // Vendor: Update if empty or strictly better confidence
    if enr.Vendor != "" && (dev.Vendor == "" || enr.Confidence > dev.Confidence) {
        if dev.Vendor != enr.Vendor {
            dev.Vendor = enr.Vendor
            changed = true
        }
    }
    
    // Model: Update if empty or strictly better confidence
    if enr.Model != "" && (dev.Model == "" || enr.Confidence > dev.Confidence) {
        if dev.Model != enr.Model {
            dev.Model = enr.Model
            changed = true
        }
    }
    
    // DeviceType: Update if empty or strictly better confidence
    if enr.DeviceType != "" && (dev.DeviceType == "" || enr.Confidence > dev.Confidence) {
        if dev.DeviceType != enr.DeviceType {
            dev.DeviceType = enr.DeviceType
            changed = true
        }
    }

    // Services: AddService returns true ONLY if the service was not already in the list
    for _, svc := range enr.Services {
        if dev.AddService(svc) {
            changed = true
        }
    }

    return changed
}
