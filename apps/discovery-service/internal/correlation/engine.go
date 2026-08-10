// Package correlation implements the correlation, identity, and enrichment engine for DIS.
//
// File:    apps/discovery-service/internal/correlation/engine.go
// Version: 5.5 (Fixed Duplicate Case Syntax Error)
package correlation

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/user/lias-dis/apps/discovery-service/internal/api"
	"github.com/user/lias-dis/apps/discovery-service/internal/discovery"
	identitycore "github.com/user/lias-dis/apps/discovery-service/internal/identity"
	"github.com/user/lias-dis/apps/discovery-service/internal/inventory"
	"github.com/user/lias-dis/apps/discovery-service/internal/storage"
	"github.com/user/lias-dis/shared/models"
)

type EnrichmentOrchestrator interface {
	TriggerEnrichment(pdid string, force bool)
}

type Engine struct {
	cache       *inventory.Cache
	broker      *api.Broker
	debouncer   *Debouncer
	store       *storage.Storage
	orch        EnrichmentOrchestrator
	dedupMu     sync.Mutex
	lastSeenObs map[string]time.Time

	dirtyMu      sync.Mutex
	dirtyDevices map[string]struct{}

	deferredMu     sync.Mutex
	deferredOnline map[string]time.Time

	promoteMu  sync.Mutex
	identityMu sync.Mutex
	aliasMu    sync.RWMutex
	aliases    map[identityAliasKey]identityAliasActivity
	macClaims  [64]sync.Mutex
}

func NewEngine(cache *inventory.Cache, broker *api.Broker) *Engine {
	deb := NewDebouncer(broker)
	return &Engine{
		cache:          cache,
		broker:         broker,
		debouncer:      deb,
		lastSeenObs:    make(map[string]time.Time),
		dirtyDevices:   make(map[string]struct{}),
		deferredOnline: make(map[string]time.Time),
		aliases:        make(map[identityAliasKey]identityAliasActivity),
	}
}

func (e *Engine) SetOrchestrator(orch EnrichmentOrchestrator) {
	e.orch = orch
}

func (e *Engine) SetStorage(store *storage.Storage) {
	e.store = store
	e.debouncer.SetStore(store)

	if store != nil {
		e.loadIdentityAliasActivity(store)
		if owners, err := store.LoadHostnameOwners(); err == nil {
			e.cache.LoadHostnameOwners(owners)
		}
		e.cache.SetHostnameOwnerListener(func(host, pdid string, isDelete bool) {
			if isDelete {
				_ = store.DeleteHostnameOwner(host)
			} else {
				_ = store.SaveHostnameOwner(host, pdid)
			}
		})

		if pending, err := store.LoadPendingEvents(); err == nil {
			e.debouncer.LoadPending(pending)
			if len(pending) > 0 {
				slog.Info("Loaded pending events from storage for recovery", "count", len(pending))
			}
		}
	}
}

func (e *Engine) Run(ctx context.Context, providers []discovery.DiscoveryProvider) {
	go e.debouncer.Run(ctx)
	for _, p := range providers {
		go e.consume(ctx, p.Events())
	}
	go e.runStalenessSweep(ctx)
	go e.runDedupSweep(ctx)
	go e.runDirtyFlusher(ctx)
	go e.runDeferredOnlineSweep(ctx)
}

func (e *Engine) runDirtyFlusher(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			e.flushDirty()
		}
	}
}

func (e *Engine) flushDirty() {
	e.dirtyMu.Lock()
	if len(e.dirtyDevices) == 0 {
		e.dirtyMu.Unlock()
		return
	}
	pdids := make([]string, 0, len(e.dirtyDevices))
	for pdid := range e.dirtyDevices {
		pdids = append(pdids, pdid)
	}
	e.dirtyDevices = make(map[string]struct{})
	e.dirtyMu.Unlock()

	devs := make([]*models.Device, 0, len(pdids))
	for _, pdid := range pdids {
		d := e.cache.Get(pdid)
		if d != nil {
			devs = append(devs, d)
		}
	}

	if e.store != nil && len(devs) > 0 {
		if err := e.store.SaveDevicesBatch(devs); err != nil {
			slog.Error("Failed to flush dirty devices batch to storage", "count", len(devs), "error", err)
			e.dirtyMu.Lock()
			for _, d := range devs {
				e.dirtyDevices[d.PDID] = struct{}{}
			}
			e.dirtyMu.Unlock()
		}
	}
}

func (e *Engine) markDirty(pdid string) {
	if e.store == nil || pdid == "" {
		return
	}
	e.dirtyMu.Lock()
	e.dirtyDevices[pdid] = struct{}{}
	e.dirtyMu.Unlock()
}

func (e *Engine) runDedupSweep(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			e.dedupMu.Lock()
			now := time.Now()
			for k, t := range e.lastSeenObs {
				if now.Sub(t) > 5*time.Minute {
					delete(e.lastSeenObs, k)
				}
			}
			e.dedupMu.Unlock()
		}
	}
}

func (e *Engine) runStalenessSweep(ctx context.Context) {
	ticker := time.NewTicker(20 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			changedPDIDs := e.cache.DemoteStale()
			for _, pdid := range changedPDIDs {
				d := e.cache.Get(pdid)
				if d == nil {
					continue
				}
				e.broker.Broadcast(models.NewEvent(models.EventDeviceOffline, d.PDID, models.DeviceEventPayload{
					PDID:      d.PDID,
					MAC:       d.CurrentMAC,
					IP:        d.CurrentIP,
					Timestamp: time.Now(),
				}))
				slog.Info("Device transitioned offline via staleness sweep", "pdid", d.PDID, "mac", d.CurrentMAC, "ip", d.CurrentIP)
			}
		}
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

func (e *Engine) isDuplicateObservation(obs discovery.Observation, macStr, ipStr, canonicalHost string) bool {
	services := append([]string(nil), obs.Services...)
	sort.Strings(services)
	key := fmt.Sprintf("%s|%s|%s|%s|%s|%t|%s", obs.Source, obs.Group, macStr, ipStr, canonicalHost, obs.Online, strings.Join(services, ","))
	now := time.Now()

	e.dedupMu.Lock()
	defer e.dedupMu.Unlock()

	if last, found := e.lastSeenObs[key]; found {
		if now.Sub(last) < 2*time.Second {
			return true
		}
	}

	e.lastSeenObs[key] = now
	return false
}

func canUpdateCurrentIP(source string) bool {
	switch source {
	case "netlink", "dhcp", "openwrt_neigh":
		return true
	default:
		return false
	}
}

func canTriggerOnline(source string) bool {
	switch source {
	case "netlink", "openwrt_ap", "openwrt_neigh":
		return true
	default:
		return false
	}
}

func hasL2AndL3Confirmation(sources []string) bool {
	hasL2 := false
	hasL3 := false
	for _, s := range sources {
		switch s {
		case "netlink", "openwrt_ap":
			hasL2 = true
		case "dhcp", "pihole":
			hasL3 = true
		case "openwrt_neigh":
			hasL2 = true
			hasL3 = true
		}
	}
	return hasL2 && hasL3
}

func (e *Engine) processObservation(obs discovery.Observation) {
	if discovery.IsMulticastOrBroadcast(obs.MAC, obs.IP) {
		return
	}

	macStr := ""
	if obs.MAC != nil {
		macStr = inventory.NormalizeMAC(obs.MAC.String())
	}
	ipStr := ""
	if obs.IP != nil {
		ipStr = strings.TrimSpace(obs.IP.String())
	}

	cleanHost := discovery.UnescapeHostname(obs.Hostname)
	canonicalHost := CanonicalizeHostname(cleanHost)

	if obs.Source == "pihole" && ipStr != "" {
		if existing := e.cache.GetByIP(ipStr); existing != nil {
			ipAlreadyKnown := false
			for _, ip := range existing.IPs {
				if ip == ipStr {
					ipAlreadyKnown = true
					break
				}
			}
			if !ipAlreadyKnown {
				existing.AddIP(ipStr)
				e.cache.Upsert(existing)
				e.markDirty(existing.PDID)
			}
			return
		}
	}

	if macStr == "" && canonicalHost == "" {
		return
	}

	if e.isDuplicateObservation(obs, macStr, ipStr, canonicalHost) {
		return
	}
	if macStr != "" {
		unlock := e.lockMACClaim(macStr)
		defer unlock()
	}

	signals := identitycore.ObservationSignals(obs, macStr, canonicalHost)
	d := e.resolveVerifiedObservation(signals)
	verifiedResolution := d != nil
	macOwner := e.cache.GetByMAC(macStr)
	if d != nil && macOwner != nil && macOwner.PDID != d.PDID {
		details := fmt.Sprintf("authenticated identity %s observed with MAC owned by %s", d.PDID, macOwner.PDID)
		e.broker.Broadcast(models.NewEvent(models.EventSecurityAlert, d.PDID, models.SecurityAlertPayload{
			AlertType: "mac_identity_conflict", PDID: d.PDID, Details: details, Timestamp: time.Now(),
		}))
		slog.Warn("Rejected conflicting authenticated MAC observation", "identity_pdid", d.PDID,
			"mac_owner_pdid", macOwner.PDID, "mac", macStr, "source", obs.Source)
		return
	}
	if d == nil {
		d = macOwner
	}
	if d == nil && macStr != "" && e.store != nil {
		ownerPDID, err := e.store.LookupPDIDByMAC(macStr)
		if err != nil {
			slog.Warn("Failed durable MAC owner lookup", "mac", macStr, "error", err)
			return
		}
		if ownerPDID != "" {
			d = e.cache.Get(ownerPDID)
			if d == nil {
				slog.Error("Durable MAC owner missing from identity registry", "mac", macStr, "pdid", ownerPDID)
				return
			}
		}
	}
	if d == nil && macStr == "" {
		d = e.cache.GetByIP(ipStr)
	}
	var candidateTarget *models.Device
	var candidateDecision identitycore.Decision
	if d == nil && macStr != "" && ipStr != "" {
		if existing := e.cache.GetByIP(ipStr); existing != nil && !existing.HasMAC(macStr) {
			candidateTarget = existing
			candidateDecision = identitycore.ScorePassive(identitycore.PassiveInput{
				SameIP: true, CanonicalHostname: canonicalHost,
				ExistingHostname: existing.CanonicalHostname,
				Services:         obs.Services, ExistingServices: existing.Services,
				Vendor: obs.Vendor, ExistingVendor: existing.Vendor,
				NewMAC: macStr, ExistingMAC: existing.CurrentMAC,
				ExistingOnline: existing.Online, ExistingLastSeen: existing.LastSeen,
				ObservedAt: normalizedObservationTime(obs.Timestamp),
			})
			// IP reuse is not identity proof. Remove the stale index mapping
			// while retaining a reviewable scored relationship.
			e.cache.RemoveIPIndex(ipStr)
			e.markDirty(existing.PDID)
		}
	}
	materialDirty := false

	if macStr != "" && d != nil && d.HasMAC(macStr) && d.CurrentMAC != macStr {
		d.CurrentMAC = macStr
		materialDirty = true
	}

	if macStr != "" && d != nil && !d.HasMAC(macStr) {
		if verifiedResolution {
			oldMAC := d.CurrentMAC
			d.AddMAC(macStr)
			d.CurrentMAC = macStr
			d.IdentityAssurance = models.IdentityVerified
			d.IdentityProbability = 1
			d.IdentityAmbiguous = false
			e.debouncer.Submit(d.PDID, models.EventMACChanged, obs.Source, obs.Group, models.DeviceEventPayload{
				PDID: d.PDID, MAC: macStr, OldMAC: oldMAC, Timestamp: time.Now(),
			})
			materialDirty = true
		} else {
			candidateTarget = d
			candidateDecision = identitycore.ScorePassive(identitycore.PassiveInput{
				SameIP: d.CurrentIP == ipStr, CanonicalHostname: canonicalHost,
				ExistingHostname: d.CanonicalHostname, Services: obs.Services,
				ExistingServices: d.Services, Vendor: obs.Vendor, ExistingVendor: d.Vendor,
				NewMAC: macStr, ExistingMAC: d.CurrentMAC, ExistingOnline: d.Online,
				ExistingLastSeen: d.LastSeen, ObservedAt: normalizedObservationTime(obs.Timestamp),
			})
			d = nil
		}
	}

	if canonicalHost != "" {
		if d != nil {
			ownerPDID, exists := e.cache.GetHostnameOwner(canonicalHost)
			if exists && ownerPDID != d.PDID {
				acqRes := e.cache.AcquireHostname(canonicalHost, d.PDID)
				if acqRes == inventory.AcquireReject {
					slog.Debug("Hostname ownership lock rejected claim", "host", canonicalHost, "pdid", d.PDID, "claimant", obs.Source)
					canonicalHost = ""
					cleanHost = ""
				}
			}
		} else {
			if e.cache.IsHostnameActivelyOwned(canonicalHost) {
				slog.Debug("Hostname ownership lock rejected claim for new device", "host", canonicalHost, "claimant", obs.Source)
				canonicalHost = ""
				cleanHost = ""
			}
		}
	}

	if d == nil {
		tier, anchor := inventory.DeriveTierAndAnchor(macStr, canonicalHost, obs.Vendor)
		deviceID, pdid, err := inventory.NewPermanentIdentity()
		if err != nil {
			slog.Error("Failed to allocate permanent identity", "error", err)
			return
		}

		assurance := models.IdentityUnverified
		probability := 0.0
		if macStr != "" && !inventory.IsLocallyAdministeredMAC(macStr) {
			assurance = models.IdentityStrong
			probability = 0.999
		}
		ambiguous := false
		if candidateTarget != nil && candidateDecision.Probability >= identitycore.PassiveCandidateThreshold {
			assurance = models.IdentityCandidate
			probability = candidateDecision.Probability
			ambiguous = true
		}

		d = &models.Device{
			DeviceID:            deviceID,
			PDID:                pdid,
			IdentityTier:        tier,
			IdentityAnchor:      anchor,
			CanonicalHostname:   canonicalHost,
			Hostname:            cleanHost,
			Vendor:              obs.Vendor,
			Model:               obs.Model,
			Online:              false,
			Confidence:          obs.Confidence,
			SourceInfo:          make(map[string]models.SourceMeta),
			IdentityAssurance:   assurance,
			IdentityProbability: probability,
			IdentityAmbiguous:   ambiguous,
		}
		d.AddMAC(macStr)
		if obs.Source != "pihole" {
			d.AddIP(ipStr)
		}
		for _, svc := range obs.Services {
			d.AddService(svc)
		}
		seenAt := normalizedObservationTime(obs.Timestamp)
		d.Touch(seenAt)
		recordObservationSource(d, obs, seenAt)

		if obs.Online && canTriggerOnline(obs.Source) {
			d.PendingOnlineObs = append(d.PendingOnlineObs, obs.Source)
			ApplySmartClassifications(d)
			isAuthoritativeL2 := obs.Source == "openwrt_ap" || obs.Source == "openwrt_neigh"
			isInfra := d.HasTag("infrastructure") || d.DeviceType == "infrastructure"
			if isAuthoritativeL2 || isInfra {
				d.Online = true
				d.PendingOnlineObs = nil
			}
		}

		if e.store != nil {
			if err := e.store.SaveDevice(d); err != nil {
				var conflict *storage.MACOwnershipConflict
				if errors.As(err, &conflict) {
					slog.Warn("Prevented duplicate permanent identity", "mac", conflict.MAC,
						"owner_pdid", conflict.OwnerPDID, "rejected_pdid", conflict.RequestedPDID)
					return
				}
				slog.Error("Failed to persist new permanent identity", "pdid", d.PDID, "error", err)
				return
			}
		}
		e.cache.Upsert(d)
		if canonicalHost != "" {
			_ = e.cache.AcquireHostname(canonicalHost, d.PDID)
		}
		e.recordIdentitySignals(d, signals, candidateTarget, candidateDecision, seenAt)

		slog.Info("New tiered device correlated", "pdid", d.PDID, "tier", tier, "mac", macStr, "ip", ipStr)
		e.broker.Broadcast(models.NewEvent(models.EventDeviceAdded, d.PDID, d))
		if d.Online {
			e.broker.Broadcast(models.NewEvent(models.EventDeviceOnline, d.PDID, d))
		} else if len(d.PendingOnlineObs) > 0 {
			e.scheduleDeferredOnline(d.PDID, 30*time.Second)
		}
		if e.orch != nil {
			e.orch.TriggerEnrichment(d.PDID, false)
		}
		return
	}

	e.recordIdentitySignals(d, signals, nil, identitycore.Decision{}, normalizedObservationTime(obs.Timestamp))

	newTier, newAnchor := inventory.DeriveTierAndAnchor(macStr, canonicalHost, obs.Vendor)
	if inventory.CanPromote(d.IdentityTier, newTier) {
		seenAt := normalizedObservationTime(obs.Timestamp)
		if seenAt.After(d.LastSeen) {
			d.Touch(seenAt)
		}
		recordObservationSource(d, obs, seenAt)
		e.promoteDevice(d, newTier, newAnchor, canonicalHost, "observed")
		return
	}

	if !d.Online && obs.Online && canTriggerOnline(obs.Source) {
		// A sampled AP association or NUD_REACHABLE transition is positive
		// presence evidence. A DHCP lease or stale neighbour mapping is not.
		isAuthoritativeL2 := obs.Source == "openwrt_ap" || obs.Source == "openwrt_neigh"

		exists := false
		for _, s := range d.PendingOnlineObs {
			if s == obs.Source {
				exists = true
				break
			}
		}
		if !exists {
			d.PendingOnlineObs = append(d.PendingOnlineObs, obs.Source)
		}

		if ApplySmartClassifications(d) {
			materialDirty = true
		}
		isInfra := d.HasTag("infrastructure") || d.DeviceType == "infrastructure"

		if isAuthoritativeL2 || isInfra || len(d.PendingOnlineObs) >= 2 || hasL2AndL3Confirmation(d.PendingOnlineObs) {
			d.Online = true
			d.PendingOnlineObs = nil
			e.broker.Broadcast(models.NewEvent(models.EventDeviceOnline, d.PDID, d))
		} else {
			e.scheduleDeferredOnline(d.PDID, 30*time.Second)
		}
	}

	// A single negative neighbor or lease observation is not proof that a
	// device is offline. The staleness sweep performs the transition only
	// after the positive-observation horizon has elapsed.

	if cleanHost != "" && !HostnamesAreEquivalent(d.Hostname, cleanHost) {
		oldHost := d.Hostname
		if d.CanonicalHostname != "" {
			e.cache.ReleaseHostname(d.CanonicalHostname, d.PDID)
		}
		d.Hostname = cleanHost
		d.CanonicalHostname = canonicalHost
		if canonicalHost != "" {
			_ = e.cache.AcquireHostname(canonicalHost, d.PDID)
		}
		e.debouncer.Submit(d.PDID, models.EventHostnameChanged, obs.Source, obs.Group, models.DeviceEventPayload{
			PDID:                 d.PDID,
			Hostname:             cleanHost,
			CanonicalHostname:    canonicalHost,
			OldHost:              oldHost,
			OldCanonicalHostname: CanonicalizeHostname(oldHost),
			Timestamp:            time.Now(),
		})
		materialDirty = true
	}

	if ipStr != "" && canUpdateCurrentIP(obs.Source) && d.CurrentIP != ipStr {
		oldIP := d.CurrentIP
		d.CurrentIP = ipStr
		d.AddIP(ipStr)
		e.debouncer.Submit(d.PDID, models.EventIPChanged, obs.Source, obs.Group, models.DeviceEventPayload{
			PDID:      d.PDID,
			IP:        ipStr,
			OldIP:     oldIP,
			Timestamp: time.Now(),
		})
		materialDirty = true
	}

	seenAt := normalizedObservationTime(obs.Timestamp)
	if recordObservationSource(d, obs, seenAt) {
		materialDirty = true
	}
	for _, svc := range obs.Services {
		if d.AddService(svc) {
			materialDirty = true
		}
	}
	if d.Vendor == "" && strings.TrimSpace(obs.Vendor) != "" {
		d.Vendor = strings.TrimSpace(obs.Vendor)
		materialDirty = true
	}
	if d.Model == "" && strings.TrimSpace(obs.Model) != "" {
		d.Model = strings.TrimSpace(obs.Model)
		materialDirty = true
	}

	// Presence is deliberately volatile. Keep the authoritative live timestamp
	// and online state in the cache used by REST/SSE, but persist only material
	// inventory or identity changes.
	if seenAt.After(d.LastSeen) {
		d.Touch(seenAt)
	}
	e.cache.Upsert(d)
	if materialDirty {
		e.markDirty(d.PDID)
	}
}

func (e *Engine) lockMACClaim(mac string) func() {
	var hash uint32 = 2166136261
	for i := 0; i < len(mac); i++ {
		hash ^= uint32(mac[i])
		hash *= 16777619
	}
	lock := &e.macClaims[hash%uint32(len(e.macClaims))]
	lock.Lock()
	return lock.Unlock
}

func (e *Engine) promoteDevice(d *models.Device, newTier models.IdentityTier, newAnchor, canonicalHost, reasonSuffix string) {
	e.promoteMu.Lock()
	defer e.promoteMu.Unlock()

	slog.Info("Promoting device identity metadata", "pdid", d.PDID, "from", d.IdentityTier, "to", newTier, "reason", reasonSuffix)
	d.IdentityTier = newTier
	d.IdentityAnchor = newAnchor
	d.CanonicalHostname = canonicalHost

	e.cache.Upsert(d)
	e.markDirty(d.PDID)
	e.broker.Broadcast(models.NewEvent(models.EventFingerprintUpdated, d.PDID, d))
}

func (e *Engine) PromoteDeviceIdentity(pdid string) *models.Device {
	d := e.cache.Get(pdid)
	if d == nil {
		return nil
	}

	newTier, newAnchor := inventory.DeriveTierAndAnchor(d.CurrentMAC, d.CanonicalHostname, d.Vendor)

	if inventory.CanPromote(d.IdentityTier, newTier) {
		e.promoteDevice(d, newTier, newAnchor, d.CanonicalHostname, "via_enrichment")
		return e.cache.Get(d.PDID)
	}
	return d
}

func (e *Engine) PersistDevice(pdid string) {
	e.markDirty(pdid)
}

func (e *Engine) scheduleDeferredOnline(pdid string, delay time.Duration) {
	if pdid == "" {
		return
	}
	deadline := time.Now().Add(delay)
	e.deferredMu.Lock()
	if existing, exists := e.deferredOnline[pdid]; !exists || deadline.Before(existing) {
		e.deferredOnline[pdid] = deadline
	}
	e.deferredMu.Unlock()
}

func (e *Engine) runDeferredOnlineSweep(ctx context.Context) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			e.flushDeferredOnline(now)
		}
	}
}

func (e *Engine) flushDeferredOnline(now time.Time) {
	e.deferredMu.Lock()
	due := make([]string, 0)
	for pdid, deadline := range e.deferredOnline {
		if !deadline.After(now) {
			delete(e.deferredOnline, pdid)
			due = append(due, pdid)
		}
	}
	e.deferredMu.Unlock()

	for _, pdid := range due {
		d := e.cache.Get(pdid)
		if d != nil && !d.Online && len(d.PendingOnlineObs) > 0 {
			d.Online = true
			d.PendingOnlineObs = nil
			e.cache.Upsert(d)
			e.broker.Broadcast(models.NewEvent(models.EventDeviceOnline, d.PDID, d))
		}
	}
}

func normalizedObservationTime(ts time.Time) time.Time {
	now := time.Now()
	if ts.IsZero() || ts.After(now.Add(time.Minute)) {
		return now
	}
	return ts
}

func recordObservationSource(d *models.Device, obs discovery.Observation, seenAt time.Time) bool {
	if d == nil || strings.TrimSpace(obs.Source) == "" {
		return false
	}
	if d.SourceInfo == nil {
		d.SourceInfo = make(map[string]models.SourceMeta)
	}

	previous, exists := d.SourceInfo[obs.Source]
	current := models.SourceMeta{
		Source:     obs.Source,
		Confidence: obs.Confidence,
		Timestamp:  seenAt,
		Raw:        obs.Raw,
	}
	d.SourceInfo[obs.Source] = current
	return !exists || previous.Confidence != current.Confidence || !materialRawEqual(previous.Raw, current.Raw)
}

var volatileObservationRawKeys = map[string]struct{}{
	"lease_expires_at": {}, "observation_timestamp": {}, "observed_at": {},
	"poll_timestamp": {}, "timestamp": {},
}

func materialRawEqual(left, right map[string]interface{}) bool {
	return reflect.DeepEqual(materialRaw(left), materialRaw(right))
}

func materialRaw(raw map[string]interface{}) map[string]interface{} {
	if raw == nil {
		return nil
	}
	filtered := make(map[string]interface{}, len(raw))
	for key, value := range raw {
		if _, volatile := volatileObservationRawKeys[strings.ToLower(strings.TrimSpace(key))]; volatile {
			continue
		}
		filtered[key] = value
	}
	return filtered
}

func ApplySmartClassifications(d *models.Device) bool {
	if d == nil {
		return false
	}
	beforeType, beforeName, beforeVendor := d.DeviceType, d.FriendlyName, d.Vendor

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

	if strings.HasPrefix(d.Hostname, "amzn.") || strings.Contains(d.Hostname, "amzn.dmgr") {
		d.Vendor = "Amazon Technologies Inc."
		d.DeviceType = "iot"
		if d.FriendlyName == "" {
			d.FriendlyName = "Amazon Alexa Device"
		}
	}
	return beforeType != d.DeviceType || beforeName != d.FriendlyName || beforeVendor != d.Vendor
}
