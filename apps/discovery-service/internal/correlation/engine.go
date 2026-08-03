// Package correlation implements the correlation, identity, and enrichment engine for DIS.
//
// File:    apps/discovery-service/internal/correlation/engine.go
// Version: 3.5
package correlation

import (
    "context"
    "fmt"
    "log/slog"
    "net"
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
}

func NewEngine(cache *inventory.Cache, broker *api.Broker) *Engine {
    deb := NewDebouncer(broker)
    return &Engine{
        cache:       cache,
        broker:      broker,
        debouncer:   deb,
        lastSeenObs: make(map[string]time.Time),
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

        // GAP-D11: Load pending events for crash recovery
        if pending, err := store.LoadPendingEvents(); err == nil {
            // Convert storage.PendingEventRecord to correlation.PendingEventRecord
            // Since they are structurally identical but in different packages,
            // we can just reconstruct the slice.
            correlationPending := make([]PendingEventRecord, len(pending))
            for i, p := range pending {
                correlationPending[i] = PendingEventRecord{
                    PDID:          p.PDID,
                    EventType:     p.EventType,
                    Payload:       p.Payload,
                    FirstSeen:     p.FirstSeen,
                    LastSeen:      p.LastSeen,
                    Confirmations: p.Confirmations,
                    Sources:       p.Sources,
                }
            }
            e.debouncer.LoadPending(correlationPending)
            if len(correlationPending) > 0 {
                slog.Info("Loaded pending events from storage for recovery", "count", len(correlationPending))
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
                if e.store != nil {
                    _ = e.store.SaveDevice(d)
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

func (e *Engine) isDuplicateObservation(macStr, ipStr string, online bool) bool {
    key := fmt.Sprintf("%s|%s|%t", macStr, ipStr, online)
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

// GAP-D09: Provider Confidence Matrix Gates
func canUpdateCurrentIP(source string) bool {
    switch source {
    case "netlink", "dhcp":
        return true
    default:
        return false
    }
}

func canTriggerOnline(source string) bool {
    switch source {
    case "netlink", "dhcp":
        return true
    default:
        return false
    }
}

// GAP-D06: L2 + L3 Confirmation helper for Asymmetric Flap Fix
func hasL2AndL3Confirmation(sources []string) bool {
    hasL2 := false
    hasL3 := false
    for _, s := range sources {
        switch s {
        case "netlink":
            hasL2 = true
        case "dhcp", "pihole":
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

    if macStr == "" && ipStr == "" {
        return
    }

    if e.isDuplicateObservation(macStr, ipStr, obs.Online) {
        return
    }

    cleanHost := discovery.UnescapeHostname(obs.Hostname)
    canonicalHost := CanonicalizeHostname(cleanHost)

    // Step 6: Pi-hole cannot update CurrentIP (Confidence Matrix Gate)
    if obs.Source == "pihole" && ipStr != "" {
        if existing := e.cache.GetByIP(ipStr); existing != nil {
            existing.AddIP(ipStr)
            return
        }
    }

    // 1. Query Existing Device
    d := e.cache.GetByMACOrIP(macStr, ipStr)

    // GAP-D01: MAC Rotation & IP-Claim Validation for existing devices
    if macStr != "" && d != nil && !d.HasMAC(macStr) {
        if d.CurrentIP == ipStr {
            // MAC is new but IP matches - validate claim against d itself
            claimRes := ValidateIPClaim(obs, d)
            if claimRes == ClaimAttach {
                oldMAC := d.CurrentMAC
                d.AddMAC(macStr)
                e.cache.SetCurrentMAC(d.PDID, macStr)
                e.debouncer.Submit(d.PDID, models.EventMACChanged, obs.Source, obs.Group, models.DeviceEventPayload{
                    PDID:      d.PDID,
                    MAC:       macStr,
                    OldMAC:    oldMAC,
                    Timestamp: time.Now(),
                })
            } else {
                e.cache.RemoveIPIndex(ipStr)
                d = nil
            }
        } else if ipStr != "" {
            // Existing IP mismatch path
            if existingOnIP := e.cache.GetByIP(ipStr); existingOnIP != nil && existingOnIP.PDID != d.PDID {
                claimRes := ValidateIPClaim(obs, existingOnIP)
                if claimRes == ClaimAttach {
                    oldMAC := existingOnIP.CurrentMAC
                    existingOnIP.AddMAC(macStr)
                    e.cache.SetCurrentMAC(existingOnIP.PDID, macStr)
                    e.cache.Upsert(existingOnIP)
                    if e.store != nil {
                        _ = e.store.SaveDevice(existingOnIP)
                    }
                    e.debouncer.Submit(existingOnIP.PDID, models.EventMACChanged, obs.Source, obs.Group, models.DeviceEventPayload{
                        PDID:      existingOnIP.PDID,
                        MAC:       macStr,
                        OldMAC:    oldMAC,
                        Timestamp: time.Now(),
                    })
                    d = existingOnIP
                } else {
                    e.cache.RemoveIPIndex(ipStr)
                    d = nil
                }
            }
        }
    }

    // Step 3: Hostname Ownership Lock check
    if canonicalHost != "" && (d == nil || d.CanonicalHostname != canonicalHost) {
        ownerPDID, exists := e.cache.GetHostnameOwner(canonicalHost)
        if exists && (d == nil || ownerPDID != d.PDID) {
            acqRes := e.cache.AcquireHostname(canonicalHost, d.PDID)
            if acqRes == inventory.AcquireReject {
                slog.Debug("Hostname ownership lock rejected claim", "host", canonicalHost, "claimant", obs.Source)
                canonicalHost = ""
                cleanHost = ""
            }
        }
    }

    // 2. New Device Creation with Tiered Identity (Step 7)
    if d == nil {
        // GAP-D02: Use canonicalHost for L7 anchor derivation
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
        d.Touch(time.Now())

        e.cache.Upsert(d)
        if canonicalHost != "" {
            _ = e.cache.AcquireHostname(canonicalHost, d.PDID)
        }

        if e.store != nil {
            _ = e.store.SaveDevice(d)
        }

        slog.Info("New tiered device correlated", "pdid", pdid, "tier", tier, "mac", macStr, "ip", ipStr)
        e.broker.Broadcast(models.NewEvent(models.EventDeviceAdded, d.PDID, d))
        return
    }

    // 3. Identity Promotion State Machine (Step 7)
    // GAP-D02: Use canonicalHost for L7 anchor derivation
    newTier, newAnchor := inventory.DeriveTierAndAnchor(macStr, canonicalHost, obs.Vendor)
    if inventory.CanPromote(d.IdentityTier, newTier) {
        oldPDID := d.PDID
        newPDID := inventory.GeneratePDID(newTier, newAnchor)

        slog.Info("Promoting device identity tier", "old_pdid", oldPDID, "new_pdid", newPDID, "from", d.IdentityTier, "to", newTier)

        e.cache.Delete(oldPDID)
        if e.store != nil {
            _ = e.store.DeleteDevice(oldPDID)
        }

        d.PDID = newPDID
        d.IdentityTier = newTier
        d.IdentityAnchor = newAnchor
        d.CanonicalHostname = canonicalHost

        e.cache.Upsert(d)
        if e.store != nil {
            _ = e.store.SaveDevice(d)
        }

        // GAP-D08: Populate MigratedMACs in payload
        migratedMACs := make([]string, len(d.MACs))
        copy(migratedMACs, d.MACs)

        e.broker.Broadcast(models.NewEvent(models.EventDeviceReidentified, d.PDID, models.DeviceReidentifiedPayload{
            OldPDID:      oldPDID,
            NewPDID:      newPDID,
            Reason:       string(newTier) + "_observed",
            MigratedMACs: migratedMACs,
            Timestamp:    time.Now(),
        }))
        return
    }

    // 4. Asymmetric Online Flap Fix (§8.1) & GAP-D06, GAP-D09
    if !d.Online && obs.Online && canTriggerOnline(obs.Source) {
        d.PendingOnlineObs = append(d.PendingOnlineObs, obs.Source)
        if len(d.PendingOnlineObs) >= 2 || hasL2AndL3Confirmation(d.PendingOnlineObs) {
            d.Online = true
            d.PendingOnlineObs = nil
            e.broker.Broadcast(models.NewEvent(models.EventDeviceOnline, d.PDID, d))
        } else {
            go e.scheduleDeferredOnline(d.PDID, 30*time.Second)
        }
    }

    // 5. Update Record & Submit to Debouncer (§7.2, §7.3) & GAP-D09 (Confidence Matrix)
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
    }

    if ipStr != "" && canUpdateCurrentIP(obs.Source) && d.CurrentIP != ipStr {
        oldIP := d.CurrentIP
        e.cache.SetCurrentIP(d.PDID, ipStr)
        e.debouncer.Submit(d.PDID, models.EventIPChanged, obs.Source, obs.Group, models.DeviceEventPayload{
            PDID:      d.PDID,
            IP:        ipStr,
            OldIP:     oldIP,
            Timestamp: time.Now(),
        })
    }

    d.Touch(time.Now())
    e.cache.Upsert(d)
    if e.store != nil {
        _ = e.store.SaveDevice(d)
    }
}

func (e *Engine) scheduleDeferredOnline(pdid string, delay time.Duration) {
    time.Sleep(delay)
    d := e.cache.Get(pdid)
    if d != nil && !d.Online && len(d.PendingOnlineObs) > 0 {
        d.Online = true
        d.PendingOnlineObs = nil
        e.cache.Upsert(d)
        if e.store != nil {
            _ = e.store.SaveDevice(d)
        }
        e.broker.Broadcast(models.NewEvent(models.EventDeviceOnline, d.PDID, d))
    }
}

// ApplySmartClassifications automatically categorizes routers and Amazon Echo devices.
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
