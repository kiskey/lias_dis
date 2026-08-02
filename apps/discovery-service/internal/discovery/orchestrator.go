// Package discovery implements the core observation, enrichment, and
// correlation logic for the Discovery Intelligence Service.
//
// File:    apps/discovery-service/internal/discovery/orchestrator.go
// Version: 1.1
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

// Orchestrator manages on-demand enrichment with concurrency locking per PDID.
type Orchestrator struct {
	cache       *inventory.Cache
	broker      *disAPI.Broker
	primaries   []Enricher // Avahi, SSDP, NetBIOS
	fallback    Enricher   // Nmap
	activeLocks sync.Map   // Prevents duplicate concurrent enrichments for the same PDID
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

// TriggerEnrichment executes the enrichment pipeline for a target device.
// Deduplicates concurrent executions for the same PDID automatically.
func (o *Orchestrator) TriggerEnrichment(pdid string, force bool) {
	if pdid == "" {
		return
	}

	// Deduplicate: Check if enrichment is already in-flight for this PDID
	if _, loaded := o.activeLocks.LoadOrStore(pdid, struct{}{}); loaded {
		slog.Debug("Enrichment already in progress, skipping duplicate trigger", "pdid", pdid)
		return
	}
	defer o.activeLocks.Delete(pdid)

	dev := o.cache.Get(pdid)
	if dev == nil {
		return
	}

	// Skip if already categorized and force flag is false
	if !force && dev.Vendor != "" && dev.DeviceType != "" {
		return
	}

	slog.Info("Executing enrichment pipeline", "pdid", pdid, "force", force, "ip", dev.CurrentIP)

	// 1. Run primary enrichers (Avahi, SSDP, NetBIOS) concurrently
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

	// 2. Fall back to Nmap if still unclassified (missing Vendor or DeviceType)
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

	// 3. Persist modifications and broadcast event
	if changed {
		dev.Touch(time.Now())
		o.cache.Upsert(dev)
		o.broker.Broadcast(models.NewEvent(models.EventFingerprintUpdated, dev.PDID, dev))
		slog.Info("Enrichment pipeline completed with device updates", "pdid", pdid, "type", dev.DeviceType, "vendor", dev.Vendor)
	} else {
		slog.Debug("Enrichment pipeline completed, no changes detected", "pdid", pdid)
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
