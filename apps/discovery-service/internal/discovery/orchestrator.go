// Package discovery implements the core observation, enrichment, and
// correlation logic for the Discovery Intelligence Service.
//
// File:    apps/discovery-service/internal/discovery/orchestrator.go
// Version: 2.3 (Fixed Cooldown Bypass & Implemented Nmap Negative Cache)
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
    nmapCooldownPeriod = 24 * time.Hour
    maxNmapRetries     = 3
)

type DeviceManager interface {
    PromoteDeviceIdentity(pdid string) *models.Device
    PersistDevice(pdid string)
}

type Orchestrator struct {
    cache              *inventory.Cache
    broker             *disAPI.Broker
    primaries          []Enricher
    fallback           Enricher
    activeLocks        sync.Map
    lastAttemptMap     sync.Map
    manager            DeviceManager
    validationInterval time.Duration
}

func NewOrchestrator(cache *inventory.Cache, broker *disAPI.Broker, primaries []Enricher, fallback Enricher, validationInterval time.Duration) *Orchestrator {
    o := &Orchestrator{
        cache:              cache,
        broker:             broker,
        primaries:          primaries,
        fallback:           fallback,
        validationInterval: validationInterval,
    }
    go o.cleanupLoop()
    if validationInterval > 0 {
        go o.runValidationSweep()
    }
    return o
}

func (o *Orchestrator) SetDeviceManager(m DeviceManager) {
    o.manager = m
}

// P3-FIX: Periodic cleanup of lastAttemptMap to prevent unbounded memory growth
func (o *Orchestrator) cleanupLoop() {
    ticker := time.NewTicker(10 * time.Minute)
    defer ticker.Stop()

    for {
        select {
        case <-ticker.C:
            cutoff := time.Now().Add(-enrichmentCooldown * 2)
            o.lastAttemptMap.Range(func(key, value any) bool {
                if value.(time.Time).Before(cutoff) {
                    o.lastAttemptMap.Delete(key)
                }
                return true
            })
        }
    }
}

// P3-FIX: Periodic validation sweep to re-enrich all known devices
func (o *Orchestrator) runValidationSweep() {
    // Initial delay to avoid clashing with startup
    time.Sleep(1 * time.Minute)
    
    ticker := time.NewTicker(o.validationInterval)
    defer ticker.Stop()

    for {
        select {
        case <-ticker.C:
            slog.Info("Starting periodic validation sweep for all devices")
            devs := o.cache.List()
            for _, d := range devs {
                // Force enrichment to bypass cooldowns, but respect active locks
                go o.TriggerEnrichment(d.PDID, true)
            }
        }
    }
}

func (o *Orchestrator) TriggerEnrichment(pdid string, force bool) {
    if pdid == "" {
        return
    }

    dev := o.cache.Get(pdid)
    if dev == nil {
        return
    }

    // P0-FIX: Cooldown applies to ALL devices, not just complete ones
    if !force {
        if lastAttempt, found := o.lastAttemptMap.Load(pdid); found {
            if time.Since(lastAttempt.(time.Time)) < enrichmentCooldown {
                slog.Debug("Enrichment skipped due to cooldown", "pdid", pdid, 
                    "remaining", enrichmentCooldown - time.Since(lastAttempt.(time.Time)))
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

    nmapStateUpdated := false
    shouldRunNmap := o.shouldRunNmap(dev, force)
    if shouldRunNmap && o.fallback != nil {
        slog.Info("Executing Nmap fallback", "pdid", pdid, "attempt", dev.NmapAttemptCount+1, "force", force)
        
        ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
        res, err := o.fallback.Enrich(ctx, dev)
        cancel()

        // Update nmap tracking fields regardless of success/failure
        dev.LastNmapScanAt = time.Now()
        dev.NmapAttemptCount++
        nmapStateUpdated = true

        if err != nil {
            slog.Debug("Nmap fallback failed or produced no results", "pdid", pdid, "attempt", dev.NmapAttemptCount, "error", err)
        } else if res != nil {
            changed = applyEnrichment(dev, res) || changed
            if changed {
                dev.NmapAttemptCount = 0 // Reset attempt count on success
            }
        }
    }

    // Update fully identified flag
    dev.IsFullyIdentified = dev.Vendor != "" && dev.DeviceType != "" && 
        (dev.FriendlyName != "" || dev.Hostname != "")
    dev.LastEnrichedAt = time.Now()

    if changed || nmapStateUpdated {
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
        
        if changed {
            o.broker.Broadcast(models.NewEvent(models.EventFingerprintUpdated, finalDev.PDID, finalDev))
            slog.Info("Enrichment pipeline completed with device updates", "pdid", finalDev.PDID, "type", finalDev.DeviceType, "vendor", finalDev.Vendor)
        } else {
            slog.Debug("Enrichment state updated (negative cache persisted)", "pdid", pdid)
        }
    } else {
        slog.Debug("Enrichment pipeline completed without new findings", "pdid", pdid)
    }
}

// P1-FIX: Proper Nmap gating with cooldown, retry limit, and completeness check
func (o *Orchestrator) shouldRunNmap(d *models.Device, force bool) bool {
    if force {
        return true
    }

    // Rule 1: Already fully identified - never scan
    if d.IsFullyIdentified {
        return false
    }
    if d.Vendor != "" && d.DeviceType != "" && (d.FriendlyName != "" || d.Hostname != "") {
        return false
    }

    // Rule 2: Max retries reached without new attributes
    if d.NmapAttemptCount >= maxNmapRetries {
        return false
    }

    // Rule 3: Enforce 24-hour cooldown between Nmap scans
    if !d.LastNmapScanAt.IsZero() && time.Since(d.LastNmapScanAt) < nmapCooldownPeriod {
        return false
    }

    return true
}

func isGenericHostname(host string) bool {
    h := strings.ToLower(strings.TrimSpace(host))
    if h == "" || h == "*" { return true }
    if strings.HasPrefix(h, "android-") { return true }
    if strings.HasPrefix(h, "iphone") || strings.HasPrefix(h, "ipad") { return true }
    if strings.HasPrefix(h, "desktop-") || strings.HasPrefix(h, "localhost") { return true }
    if strings.Contains(h, "unknown") { return true }
    
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

// ENR-02 Fix: Source rank heuristic to replace flawed aggregate confidence comparison.
func sourceRank(source string) int {
    switch source {
    case "netlink":
        return 100
    case "avahi":
        return 90
    case "ssdp":
        return 85
    case "tls":
        return 80
    case "dhcp":
        return 70
    case "netbios":
        return 60
    case "nmap":
        return 50
    case "pihole":
        return 40
    default:
        return 0
    }
}

// applyEnrichment strictly applies only material changes.
func applyEnrichment(dev *models.Device, enr *models.Enrichment) bool {
    if dev == nil || enr == nil {
        return false
    }

    changed := false

    if enr.FriendlyName != "" && dev.FriendlyName != enr.FriendlyName {
        dev.FriendlyName = enr.FriendlyName
        changed = true
    }

    if enr.Hostname != "" {
        shouldUpdate := false
        if dev.Hostname == "" {
            shouldUpdate = true
        } else if isGenericHostname(dev.Hostname) && !isGenericHostname(enr.Hostname) {
            shouldUpdate = true
        } else if sourceRank(enr.Source) > sourceRank(dev.SourceInfo["hostname"].Source) {
            shouldUpdate = true
        }

        if shouldUpdate && dev.Hostname != enr.Hostname {
            dev.Hostname = enr.Hostname
            if dev.SourceInfo == nil {
                dev.SourceInfo = make(map[string]models.SourceMeta)
            }
            dev.SourceInfo["hostname"] = models.SourceMeta{
                Source:     enr.Source,
                Confidence: enr.Confidence,
                Timestamp:  time.Now(),
            }
            changed = true
        }
    }

    if enr.Manufacturer != "" && (dev.Manufacturer == "" || sourceRank(enr.Source) > sourceRank(dev.SourceInfo["manufacturer"].Source)) {
        if dev.Manufacturer != enr.Manufacturer {
            dev.Manufacturer = enr.Manufacturer
            if dev.SourceInfo == nil { dev.SourceInfo = make(map[string]models.SourceMeta) }
            dev.SourceInfo["manufacturer"] = models.SourceMeta{Source: enr.Source, Confidence: enr.Confidence, Timestamp: time.Now()}
            changed = true
        }
    }
    
    if enr.Vendor != "" && (dev.Vendor == "" || sourceRank(enr.Source) > sourceRank(dev.SourceInfo["vendor"].Source)) {
        if dev.Vendor != enr.Vendor {
            dev.Vendor = enr.Vendor
            if dev.SourceInfo == nil { dev.SourceInfo = make(map[string]models.SourceMeta) }
            dev.SourceInfo["vendor"] = models.SourceMeta{Source: enr.Source, Confidence: enr.Confidence, Timestamp: time.Now()}
            changed = true
        }
    }
    
    if enr.Model != "" && (dev.Model == "" || sourceRank(enr.Source) > sourceRank(dev.SourceInfo["model"].Source)) {
        if dev.Model != enr.Model {
            dev.Model = enr.Model
            if dev.SourceInfo == nil { dev.SourceInfo = make(map[string]models.SourceMeta) }
            dev.SourceInfo["model"] = models.SourceMeta{Source: enr.Source, Confidence: enr.Confidence, Timestamp: time.Now()}
            changed = true
        }
    }
    
    if enr.DeviceType != "" && (dev.DeviceType == "" || sourceRank(enr.Source) > sourceRank(dev.SourceInfo["device_type"].Source)) {
        if dev.DeviceType != enr.DeviceType {
            dev.DeviceType = enr.DeviceType
            if dev.SourceInfo == nil { dev.SourceInfo = make(map[string]models.SourceMeta) }
            dev.SourceInfo["device_type"] = models.SourceMeta{Source: enr.Source, Confidence: enr.Confidence, Timestamp: time.Now()}
            changed = true
        }
    }

    for _, svc := range enr.Services {
        if dev.AddService(svc) {
            changed = true
        }
    }

    return changed
}
