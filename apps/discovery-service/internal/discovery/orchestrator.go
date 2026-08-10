// Package discovery implements the core observation, enrichment, and
// correlation logic for the Discovery Intelligence Service.
//
// File:    apps/discovery-service/internal/discovery/orchestrator.go
// Version: 3.0 (Bounded Queue, Workers, Timeouts, and Lifecycle)
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
	defaultQueueSize   = 128
	defaultWorkers     = 2
	defaultPrimaryTTL  = 5 * time.Second
	defaultFallbackTTL = 20 * time.Second
)

// OrchestratorOptions bounds enrichment work. Values at or below zero use safe
// defaults sized for a small LAN appliance.
type OrchestratorOptions struct {
	WorkerCount     int
	QueueSize       int
	PrimaryTimeout  time.Duration
	FallbackTimeout time.Duration
}

type DeviceManager interface {
    PromoteDeviceIdentity(pdid string) *models.Device
    PersistDevice(pdid string)
}

type Orchestrator struct {
    cache              *inventory.Cache
    broker             *disAPI.Broker
    primaries          []Enricher
    fallback           Enricher
    lastAttemptMap     sync.Map
    manager            DeviceManager
    validationInterval time.Duration
	primaryTimeout     time.Duration
	fallbackTimeout    time.Duration
	ctx                context.Context
	cancel             context.CancelFunc
	queue              chan enrichmentRequest
	pendingMu          sync.Mutex
	pending            map[string]bool
	wg                 sync.WaitGroup
	stopOnce           sync.Once
}

type enrichmentRequest struct {
	pdid string
}

func NewOrchestrator(cache *inventory.Cache, broker *disAPI.Broker, primaries []Enricher, fallback Enricher, validationInterval time.Duration) *Orchestrator {
	return NewOrchestratorWithOptions(cache, broker, primaries, fallback, validationInterval, OrchestratorOptions{})
}

func NewOrchestratorWithOptions(cache *inventory.Cache, broker *disAPI.Broker, primaries []Enricher, fallback Enricher, validationInterval time.Duration, opts OrchestratorOptions) *Orchestrator {
	if opts.WorkerCount <= 0 {
		opts.WorkerCount = defaultWorkers
	}
	if opts.WorkerCount > 8 {
		opts.WorkerCount = 8
	}
	if opts.QueueSize <= 0 {
		opts.QueueSize = defaultQueueSize
	}
	if opts.QueueSize > 4096 {
		opts.QueueSize = 4096
	}
	if opts.PrimaryTimeout <= 0 {
		opts.PrimaryTimeout = defaultPrimaryTTL
	}
	if opts.FallbackTimeout <= 0 {
		opts.FallbackTimeout = defaultFallbackTTL
	}

	ctx, cancel := context.WithCancel(context.Background())
    o := &Orchestrator{
        cache:              cache,
        broker:             broker,
        primaries:          primaries,
        fallback:           fallback,
        validationInterval: validationInterval,
		primaryTimeout:     opts.PrimaryTimeout,
		fallbackTimeout:    opts.FallbackTimeout,
		ctx:                ctx,
		cancel:             cancel,
		queue:              make(chan enrichmentRequest, opts.QueueSize),
		pending:            make(map[string]bool),
	}
	for i := 0; i < opts.WorkerCount; i++ {
		o.wg.Add(1)
		go o.worker()
	}
	o.wg.Add(1)
    go o.cleanupLoop()
    if validationInterval > 0 {
		o.wg.Add(1)
        go o.runValidationSweep()
    }
    return o
}

// Stop terminates workers and periodic loops. It is safe to call more than once.
func (o *Orchestrator) Stop() {
	o.stopOnce.Do(o.cancel)
	o.wg.Wait()
}

func (o *Orchestrator) SetDeviceManager(m DeviceManager) {
    o.manager = m
}

// P3-FIX: Periodic cleanup of lastAttemptMap to prevent unbounded memory growth
func (o *Orchestrator) cleanupLoop() {
	defer o.wg.Done()
    ticker := time.NewTicker(10 * time.Minute)
    defer ticker.Stop()

    for {
        select {
		case <-o.ctx.Done():
			return
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
	defer o.wg.Done()
	delay := time.NewTimer(1 * time.Minute)
	defer delay.Stop()
	select {
	case <-o.ctx.Done():
		return
	case <-delay.C:
	}
    
    ticker := time.NewTicker(o.validationInterval)
    defer ticker.Stop()

    for {
        select {
		case <-o.ctx.Done():
			return
        case <-ticker.C:
            slog.Info("Starting periodic validation sweep for all devices")
            devs := o.cache.List()
            for _, d := range devs {
				// Queueing is bounded; no goroutine is created per device.
				o.TriggerEnrichment(d.PDID, true)
            }
        }
    }
}

// TriggerEnrichment queues work without blocking callers. Duplicate queued or
// active work is coalesced; a force request upgrades an existing normal request.
func (o *Orchestrator) TriggerEnrichment(pdid string, force bool) {
    if pdid == "" {
        return
    }

    dev := o.cache.Get(pdid)
    if dev == nil {
        return
    }

	// Cooldown applies before queue admission to avoid consuming scarce slots.
    if !force {
        if lastAttempt, found := o.lastAttemptMap.Load(pdid); found {
            if time.Since(lastAttempt.(time.Time)) < enrichmentCooldown {
                slog.Debug("Enrichment skipped due to cooldown", "pdid", pdid, 
                    "remaining", enrichmentCooldown - time.Since(lastAttempt.(time.Time)))
                return
            }
        }
    }

	o.pendingMu.Lock()
	if existingForce, exists := o.pending[pdid]; exists {
		o.pending[pdid] = existingForce || force
		o.pendingMu.Unlock()
		slog.Debug("Enrichment request coalesced", "pdid", pdid, "force", force)
        return
    }
	o.pending[pdid] = force
	o.pendingMu.Unlock()

	select {
	case o.queue <- enrichmentRequest{pdid: pdid}:
	case <-o.ctx.Done():
		o.clearPending(pdid)
	default:
		o.clearPending(pdid)
		slog.Warn("Enrichment queue full; request dropped", "pdid", pdid, "queue_capacity", cap(o.queue))
	}
}

func (o *Orchestrator) clearPending(pdid string) {
	o.pendingMu.Lock()
	delete(o.pending, pdid)
	o.pendingMu.Unlock()
}

func (o *Orchestrator) worker() {
	defer o.wg.Done()
	for {
		select {
		case <-o.ctx.Done():
			return
		case req := <-o.queue:
			o.pendingMu.Lock()
			force, exists := o.pending[req.pdid]
			o.pendingMu.Unlock()
			if exists {
				o.execute(req.pdid, force)
			}
			o.clearPending(req.pdid)
		}
	}
}

func (o *Orchestrator) execute(pdid string, force bool) {
	dev := o.cache.Get(pdid)
	if dev == nil {
                return
            }

	// Recheck cooldown because a request may have waited in the queue.
	if !force {
		if lastAttempt, found := o.lastAttemptMap.Load(pdid); found && time.Since(lastAttempt.(time.Time)) < enrichmentCooldown {
			return
            }
    }
	o.lastAttemptMap.Store(pdid, time.Now())

	slog.Info("Executing enrichment pipeline", "pdid", pdid, "force", force, "ip", dev.CurrentIP)

	// Primary enrichers run sequentially inside a bounded worker. This caps the
	// total active enrichers at WorkerCount and avoids fan-out goroutine storms.
    changed := false
	for _, e := range o.primaries {
		ctx, cancel := context.WithTimeout(o.ctx, o.primaryTimeout)
		res, err := e.Enrich(ctx, dev)
		cancel()
		if err != nil {
			slog.Debug("Primary enricher failed", "enricher", e.Name(), "error", err)
			continue
		}
        if res != nil {
            changed = applyEnrichment(dev, res) || changed
        }
    }

    nmapStateUpdated := false
    shouldRunNmap := o.shouldRunNmap(dev, force)
    if shouldRunNmap && o.fallback != nil {
        slog.Info("Executing Nmap fallback", "pdid", pdid, "attempt", dev.NmapAttemptCount+1, "force", force)
        
		ctx, cancel := context.WithTimeout(o.ctx, o.fallbackTimeout)
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
    // Rule 1: Already fully identified - NEVER scan, even with force=true.
    // Nmap is strictly for discovering missing attributes. If we have them, don't scan.
    if d.IsFullyIdentified {
        return false
    }
    if d.Vendor != "" && d.DeviceType != "" && (d.FriendlyName != "" || d.Hostname != "") {
        return false
    }

    // If force=true (manual UI refresh), bypass time-based and retry limits
    if force {
        return true
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
	if h == "" || h == "*" {
		return true
	}
	if strings.HasPrefix(h, "android-") {
		return true
	}
	if strings.HasPrefix(h, "iphone") || strings.HasPrefix(h, "ipad") {
		return true
	}
	if strings.HasPrefix(h, "desktop-") || strings.HasPrefix(h, "localhost") {
		return true
	}
	if strings.Contains(h, "unknown") {
		return true
	}
    
    if len(h) == 12 {
        isHex := true
        for _, c := range h {
            if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
                isHex = false
                break
            }
        }
		if isHex {
			return true
		}
    }
    
    isNumeric := true
    for _, c := range h {
        if !(c >= '0' && c <= '9') {
            isNumeric = false
            break
        }
    }
	if isNumeric {
		return true
	}
    
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
	case "tls", "tls_metadata":
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
			if dev.SourceInfo == nil {
				dev.SourceInfo = make(map[string]models.SourceMeta)
			}
            dev.SourceInfo["manufacturer"] = models.SourceMeta{Source: enr.Source, Confidence: enr.Confidence, Timestamp: time.Now()}
            changed = true
        }
    }
    
    if enr.Vendor != "" && (dev.Vendor == "" || sourceRank(enr.Source) > sourceRank(dev.SourceInfo["vendor"].Source)) {
        if dev.Vendor != enr.Vendor {
            dev.Vendor = enr.Vendor
			if dev.SourceInfo == nil {
				dev.SourceInfo = make(map[string]models.SourceMeta)
			}
            dev.SourceInfo["vendor"] = models.SourceMeta{Source: enr.Source, Confidence: enr.Confidence, Timestamp: time.Now()}
            changed = true
        }
    }
    
    if enr.Model != "" && (dev.Model == "" || sourceRank(enr.Source) > sourceRank(dev.SourceInfo["model"].Source)) {
        if dev.Model != enr.Model {
            dev.Model = enr.Model
			if dev.SourceInfo == nil {
				dev.SourceInfo = make(map[string]models.SourceMeta)
			}
            dev.SourceInfo["model"] = models.SourceMeta{Source: enr.Source, Confidence: enr.Confidence, Timestamp: time.Now()}
            changed = true
        }
    }
    
    if enr.DeviceType != "" && (dev.DeviceType == "" || sourceRank(enr.Source) > sourceRank(dev.SourceInfo["device_type"].Source)) {
        if dev.DeviceType != enr.DeviceType {
            dev.DeviceType = enr.DeviceType
			if dev.SourceInfo == nil {
				dev.SourceInfo = make(map[string]models.SourceMeta)
			}
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
