// Package correlation implements the correlation, identity, and enrichment engine for DIS.
//
// File:    apps/discovery-service/internal/correlation/engine.go
// Version: 5.5 (Fixed Duplicate Case Syntax Error)
package correlation

import (
    "context"
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
	persistedSeen map[string]time.Time

	deferredMu     sync.Mutex
	deferredOnline map[string]struct{}

    promoteMu sync.Mutex
}

func NewEngine(cache *inventory.Cache, broker *api.Broker) *Engine {
    deb := NewDebouncer(broker)
    return &Engine{
        cache:        cache,
        broker:       broker,
        debouncer:    deb,
        lastSeenObs:  make(map[string]time.Time),
        dirtyDevices: make(map[string]struct{}),
		persistedSeen:  make(map[string]time.Time),
		deferredOnline: make(map[string]struct{}),
    }
}

func (e *Engine) SetOrchestrator(orch EnrichmentOrchestrator) {
    e.orch = orch
}

func (e *Engine) SetStorage(store *storage.Storage) {
    e.store = store
    e.debouncer.SetStore(store)

    if store != nil {
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

func (e *Engine) markSeenDirty(pdid string, seenAt time.Time) {
	if e.store == nil || pdid == "" {
		return
	}
	e.dirtyMu.Lock()
	defer e.dirtyMu.Unlock()
	if last, ok := e.persistedSeen[pdid]; ok && seenAt.Sub(last) < 30*time.Second {
		return
	}
	e.persistedSeen[pdid] = seenAt
	e.dirtyDevices[pdid] = struct{}{}
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
                e.markDirty(pdid)
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
    case "netlink", "dhcp":
        return true
    default:
        return false
    }
}

// V5.4 FIX: Added openwrt_arp as a valid trigger
func canTriggerOnline(source string) bool {
    switch source {
    case "netlink", "dhcp", "openwrt_ap", "openwrt_arp":
        return true
    default:
        return false
    }
}

// V5.5 FIX: Corrected duplicate case syntax error.
// openwrt_arp is now in its own case, setting both L2 and L3 flags.
func hasL2AndL3Confirmation(sources []string) bool {
    hasL2 := false
    hasL3 := false
    for _, s := range sources {
        switch s {
        case "netlink", "openwrt_ap":
            hasL2 = true
        case "dhcp", "pihole":
            hasL3 = true
        case "openwrt_arp":
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

    d := e.cache.GetByMACOrIP(macStr, ipStr)
    dirty := false

    if macStr != "" && d != nil && d.HasMAC(macStr) && d.CurrentMAC != macStr {
        d.CurrentMAC = macStr
        dirty = true
    }

    if macStr != "" && d != nil && !d.HasMAC(macStr) {
        if d.CurrentIP == ipStr {
            claimRes := ValidateIPClaim(obs, d)
            if claimRes == ClaimAttach {
                oldMAC := d.CurrentMAC
                d.AddMAC(macStr)
                d.CurrentMAC = macStr
                e.debouncer.Submit(d.PDID, models.EventMACChanged, obs.Source, obs.Group, models.DeviceEventPayload{
                    PDID:      d.PDID,
                    MAC:       macStr,
                    OldMAC:    oldMAC,
                    Timestamp: time.Now(),
                })
                dirty = true
            } else if claimRes == ClaimCreateNewSilent {
                d = nil
            } else {
                e.broker.Broadcast(models.NewEvent(models.EventSecurityAlert, d.PDID, models.SecurityAlertPayload{
                    AlertType: "mac_spoof_detected",
                    PDID:      d.PDID,
                    Details:   fmt.Sprintf("MAC %s claimed IP %s currently held by %s (MAC %s)", macStr, ipStr, d.PDID, d.CurrentMAC),
                    Timestamp: time.Now(),
                }))
                slog.Warn("Potential MAC spoofing detected", "pdid", d.PDID, "mac", d.CurrentMAC, "ip", ipStr, "conflict_mac", macStr)
                
                e.cache.RemoveIPIndex(ipStr)
                e.markDirty(d.PDID)
                d = nil
            }
        } else if ipStr != "" {
            if existingOnIP := e.cache.GetByIP(ipStr); existingOnIP != nil && existingOnIP.PDID != d.PDID {
                claimRes := ValidateIPClaim(obs, existingOnIP)
                if claimRes == ClaimAttach {
                    oldMAC := existingOnIP.CurrentMAC
                    existingOnIP.AddMAC(macStr)
                    existingOnIP.CurrentMAC = macStr
                    e.debouncer.Submit(existingOnIP.PDID, models.EventMACChanged, obs.Source, obs.Group, models.DeviceEventPayload{
                        PDID:      existingOnIP.PDID,
                        MAC:       macStr,
                        OldMAC:    oldMAC,
                        Timestamp: time.Now(),
                    })
                    d = existingOnIP 
                    dirty = true
                } else if claimRes == ClaimCreateNewSilent {
                    d = nil
                } else {
                    e.broker.Broadcast(models.NewEvent(models.EventSecurityAlert, existingOnIP.PDID, models.SecurityAlertPayload{
                        AlertType: "mac_spoof_detected",
                        PDID:      existingOnIP.PDID,
                        Details:   fmt.Sprintf("MAC %s claimed IP %s held by %s", macStr, ipStr, existingOnIP.PDID),
                        Timestamp: time.Now(),
                    }))
                    slog.Warn("Potential cross-device MAC spoofing detected", "pdid", existingOnIP.PDID, "ip", ipStr, "conflict_mac", macStr)
                    
                    e.cache.RemoveIPIndex(ipStr)
                    e.markDirty(existingOnIP.PDID)
                    d = nil
                }
            }
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
        pdid := inventory.GeneratePDID(tier, anchor)

        d = &models.Device{
            PDID:              pdid,
            IdentityTier:      tier,
            IdentityAnchor:    anchor,
            CanonicalHostname: canonicalHost,
            Hostname:          cleanHost,
            Vendor:            obs.Vendor,
            Model:             obs.Model,
            Online:            false,
            Confidence:        obs.Confidence,
            SourceInfo:        make(map[string]models.SourceMeta),
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
			isAuthoritativeL2 := obs.Source == "openwrt_ap" || obs.Source == "openwrt_arp"
			isInfra := d.HasTag("infrastructure") || d.DeviceType == "infrastructure"
			if isAuthoritativeL2 || isInfra {
				d.Online = true
				d.PendingOnlineObs = nil
			}
		}

        e.cache.Upsert(d)
        if canonicalHost != "" {
            _ = e.cache.AcquireHostname(canonicalHost, d.PDID)
        }

        e.markDirty(d.PDID)

        slog.Info("New tiered device correlated", "pdid", d.PDID, "tier", tier, "mac", macStr, "ip", ipStr)
        e.broker.Broadcast(models.NewEvent(models.EventDeviceAdded, d.PDID, d))
		if d.Online {
			e.broker.Broadcast(models.NewEvent(models.EventDeviceOnline, d.PDID, d))
		} else if len(d.PendingOnlineObs) > 0 {
			e.scheduleDeferredOnline(d.PDID, 30*time.Second)
		}
		if e.orch != nil {
			go e.orch.TriggerEnrichment(d.PDID, false)
		}
        return
    }

    newTier, newAnchor := inventory.DeriveTierAndAnchor(macStr, canonicalHost, obs.Vendor)
    if inventory.CanPromote(d.IdentityTier, newTier) {
        e.promoteDevice(d, newTier, newAnchor, canonicalHost, "observed")
        return
    }

	if !d.Online && obs.Online && canTriggerOnline(obs.Source) {
        // V5.3 FIX: OpenWrt AP and ARP data is authoritative Layer-2/Layer-3 ground truth.
        // If the router reports the device as associated/resolved, it is definitively online.
        // We bypass the 30-second deferred timer to prevent bulk-poll "offline limbo".
        isAuthoritativeL2 := obs.Source == "openwrt_ap" || obs.Source == "openwrt_arp"

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

        ApplySmartClassifications(d)
        isInfra := d.HasTag("infrastructure") || d.DeviceType == "infrastructure"
        
        if isAuthoritativeL2 || isInfra || len(d.PendingOnlineObs) >= 2 || hasL2AndL3Confirmation(d.PendingOnlineObs) {
            d.Online = true
            d.PendingOnlineObs = nil
            e.broker.Broadcast(models.NewEvent(models.EventDeviceOnline, d.PDID, d))
            dirty = true
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
        dirty = true
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
        dirty = true
    }

	seenAt := normalizedObservationTime(obs.Timestamp)
	if recordObservationSource(d, obs, seenAt) {
		dirty = true
	}
	for _, svc := range obs.Services {
		if d.AddService(svc) {
			dirty = true
		}
	}
	if d.Vendor == "" && strings.TrimSpace(obs.Vendor) != "" {
		d.Vendor = strings.TrimSpace(obs.Vendor)
		dirty = true
	}
	if d.Model == "" && strings.TrimSpace(obs.Model) != "" {
		d.Model = strings.TrimSpace(obs.Model)
		dirty = true
	}

    if dirty {
		if seenAt.After(d.LastSeen) {
			d.Touch(seenAt)
		}
        e.cache.Upsert(d)
        e.markDirty(d.PDID)
    } else {
		if seenAt.After(d.LastSeen) {
			e.cache.TouchLastSeen(d.PDID, seenAt)
			e.markSeenDirty(d.PDID, seenAt)
		}
    }
}

func (e *Engine) promoteDevice(d *models.Device, newTier models.IdentityTier, newAnchor, canonicalHost, reasonSuffix string) {
    e.promoteMu.Lock()
    defer e.promoteMu.Unlock()

    oldPDID := d.PDID
    newPDID := inventory.GeneratePDID(newTier, newAnchor)

    slog.Info("Promoting device identity tier", "old_pdid", oldPDID, "new_pdid", newPDID, "from", d.IdentityTier, "to", newTier)

    d.PDID = newPDID
    d.IdentityTier = newTier
    d.IdentityAnchor = newAnchor
    d.CanonicalHostname = canonicalHost

    if e.store != nil {
        if err := e.store.ReplaceDevicePDID(oldPDID, newPDID, d); err != nil {
            slog.Error("Atomic PDID replacement failed", "old_pdid", oldPDID, "new_pdid", newPDID, "error", err)
            d.PDID = oldPDID
            d.IdentityTier = models.TierL7
            return
        }
    }

    e.debouncer.MigratePDID(oldPDID, newPDID)

    e.cache.Delete(oldPDID)
    e.cache.Upsert(d)
    e.markDirty(d.PDID)

    migratedMACs := make([]string, len(d.MACs))
    copy(migratedMACs, d.MACs)

    e.broker.Broadcast(models.NewEvent(models.EventDeviceReidentified, d.PDID, models.DeviceReidentifiedPayload{
        OldPDID:      oldPDID,
        NewPDID:      newPDID,
        Reason:       string(newTier) + "_" + reasonSuffix,
        MigratedMACs: migratedMACs,
        Timestamp:    time.Now(),
    }))
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
	e.deferredMu.Lock()
	if _, exists := e.deferredOnline[pdid]; exists {
		e.deferredMu.Unlock()
		return
	}
	e.deferredOnline[pdid] = struct{}{}
	e.deferredMu.Unlock()

	go func() {
		timer := time.NewTimer(delay)
		defer timer.Stop()
		<-timer.C

		e.deferredMu.Lock()
		delete(e.deferredOnline, pdid)
		e.deferredMu.Unlock()

    d := e.cache.Get(pdid)
    if d != nil && !d.Online && len(d.PendingOnlineObs) > 0 {
        d.Online = true
        d.PendingOnlineObs = nil
        e.cache.Upsert(d)
        e.markDirty(d.PDID)
        e.broker.Broadcast(models.NewEvent(models.EventDeviceOnline, d.PDID, d))
    }
	}()
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
	if exists && previous.Confidence == current.Confidence && reflect.DeepEqual(previous.Raw, current.Raw) {
		return false
	}
	d.SourceInfo[obs.Source] = current
	return true
}

func ApplySmartClassifications(d *models.Device) {
    if d == nil {
        return
    }

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
}
