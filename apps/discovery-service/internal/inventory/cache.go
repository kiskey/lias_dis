// Package inventory provides the in-memory device store for DIS.
//
// File:    apps/discovery-service/internal/inventory/cache.go
// Version: 2.8
package inventory

import (
    "log/slog"
    "strings"
    "sync"
    "time"

    "github.com/user/lias-dis/shared/models"
)

const (
    offlineTTL     = 24 * time.Hour
    staleThreshold = 180 * time.Second
)

type HostnameAcquisitionResult int

const (
    AcquireSuccess HostnameAcquisitionResult = iota
    AcquireReject
    AcquireProvisional
)

type HostnameOwnerListener func(canonicalHost, pdid string, isDelete bool)

type Cache struct {
    mu             sync.RWMutex
    devices        map[string]*models.Device
    macIndex       map[string]*models.Device
    ipIndex        map[string]*models.Device
    hostnameOwners map[string]string
    ownerListener  HostnameOwnerListener
    stopCh         chan struct{}
}

func NewCache() *Cache {
    c := &Cache{
        devices:        make(map[string]*models.Device),
        macIndex:       make(map[string]*models.Device),
        ipIndex:        make(map[string]*models.Device),
        hostnameOwners: make(map[string]string),
        stopCh:         make(chan struct{}),
    }
    go c.purgeLoop()
    return c
}

func (c *Cache) SetHostnameOwnerListener(listener HostnameOwnerListener) {
    c.mu.Lock()
    defer c.mu.Unlock()
    c.ownerListener = listener
}

func (c *Cache) LoadHostnameOwners(owners map[string]string) {
    c.mu.Lock()
    defer c.mu.Unlock()
    for host, pdid := range owners {
        if host != "" && pdid != "" {
            c.hostnameOwners[host] = pdid
        }
    }
}

func (c *Cache) AcquireHostname(canonicalHost, pdid string) HostnameAcquisitionResult {
    if canonicalHost == "" || pdid == "" {
        return AcquireReject
    }

    c.mu.Lock()
    ownerPDID, exists := c.hostnameOwners[canonicalHost]
    if !exists || ownerPDID == pdid {
        c.hostnameOwners[canonicalHost] = pdid
        listener := c.ownerListener
        c.mu.Unlock()
        if listener != nil {
            listener(canonicalHost, pdid, false)
        }
        return AcquireSuccess
    }

    owner := c.devices[ownerPDID]
    if owner == nil || (!owner.Online && time.Since(owner.LastSeen) > 24*time.Hour) {
        c.hostnameOwners[canonicalHost] = pdid
        listener := c.ownerListener
        c.mu.Unlock()
        if listener != nil {
            listener(canonicalHost, pdid, false)
        }
        return AcquireSuccess
    }

    if owner.Online && time.Since(owner.LastSeen) < 5*time.Minute {
        c.mu.Unlock()
        return AcquireReject
    }

    c.hostnameOwners[canonicalHost] = pdid
    listener := c.ownerListener
    c.mu.Unlock()
    if listener != nil {
        listener(canonicalHost, pdid, false)
    }
    return AcquireProvisional
}

func (c *Cache) IsHostnameActivelyOwned(canonicalHost string) bool {
    if canonicalHost == "" {
        return false
    }

    c.mu.RLock()
    defer c.mu.RUnlock()

    ownerPDID, exists := c.hostnameOwners[canonicalHost]
    if !exists {
        return false
    }

    owner := c.devices[ownerPDID]
    if owner == nil {
        return false
    }

    return owner.Online && time.Since(owner.LastSeen) < 5*time.Minute
}

func (c *Cache) ReleaseHostname(canonicalHost, pdid string) {
    if canonicalHost == "" || pdid == "" {
        return
    }

    c.mu.Lock()
    if owner, exists := c.hostnameOwners[canonicalHost]; exists && owner == pdid {
        delete(c.hostnameOwners, canonicalHost)
        listener := c.ownerListener
        c.mu.Unlock()
        if listener != nil {
            listener(canonicalHost, pdid, true)
        }
        return
    }
    c.mu.Unlock()
}

func (c *Cache) GetHostnameOwner(canonicalHost string) (string, bool) {
    if canonicalHost == "" {
        return "", false
    }

    c.mu.RLock()
    defer c.mu.RUnlock()

    pdid, exists := c.hostnameOwners[canonicalHost]
    return pdid, exists
}

func (c *Cache) DemoteStale() []string {
    c.mu.Lock()
    defer c.mu.Unlock()

    var changed []string
    now := time.Now()
    for pdid, d := range c.devices {
        if d.Online && now.Sub(d.LastSeen) > staleThreshold {
            d.Online = false
            changed = append(changed, pdid)
        }
    }
    return changed
}

func (c *Cache) GetByMAC(macStr string) *models.Device {
    c.mu.RLock()
    defer c.mu.RUnlock()

    cleanMAC := NormalizeMAC(macStr)
    if cleanMAC != "" {
        if d, found := c.macIndex[cleanMAC]; found {
            devCopy := *d
            return &devCopy
        }
    }
    return nil
}

func (c *Cache) GetByMACCluster(macStr string) *models.Device {
    cleanMAC := NormalizeMAC(macStr)
    if cleanMAC == "" {
        return nil
    }

    c.mu.RLock()
    defer c.mu.RUnlock()

    for _, d := range c.devices {
        if d.HasMAC(cleanMAC) {
            devCopy := *d
            return &devCopy
        }
    }
    return nil
}

func (c *Cache) GetByIP(ipStr string) *models.Device {
    c.mu.RLock()
    defer c.mu.RUnlock()

    cleanIP := strings.TrimSpace(ipStr)
    if cleanIP != "" {
        if d, found := c.ipIndex[cleanIP]; found {
            devCopy := *d
            return &devCopy
        }
    }
    return nil
}

func (c *Cache) RemoveIPIndex(ipStr string) {
    cleanIP := strings.TrimSpace(ipStr)
    if cleanIP == "" {
        return
    }

    c.mu.Lock()
    defer c.mu.Unlock()

    if d, found := c.ipIndex[cleanIP]; found {
        newIPs := make([]string, 0, len(d.IPs))
        for _, ip := range d.IPs {
            if ip != cleanIP {
                newIPs = append(newIPs, ip)
            }
        }
        d.IPs = newIPs
        if d.CurrentIP == cleanIP {
            d.CurrentIP = ""
            if len(d.IPs) > 0 {
                d.CurrentIP = d.IPs[len(d.IPs)-1]
            }
        }
        delete(c.ipIndex, cleanIP)
        slog.Info("Invalidated stale IP index mapping", "ip", cleanIP, "pdid", d.PDID) // FIXED SYNTAX
    }
}

func (c *Cache) SetCurrentIP(pdid, ipStr string) {
    cleanIP := strings.TrimSpace(ipStr)
    if pdid == "" || cleanIP == "" {
        return
    }

    c.mu.Lock()
    defer c.mu.Unlock()

    d, found := c.devices[pdid]
    if !found {
        return
    }

    if oldDev, exists := c.ipIndex[cleanIP]; exists && oldDev.PDID != pdid {
        oldDev.CurrentIP = ""
    }

    d.AddIP(cleanIP)
    d.CurrentIP = cleanIP
    c.ipIndex[cleanIP] = d
}

func (c *Cache) SetCurrentMAC(pdid, macStr string) {
    cleanMAC := NormalizeMAC(macStr)
    if pdid == "" || cleanMAC == "" {
        return
    }

    c.mu.Lock()
    defer c.mu.Unlock()

    d, found := c.devices[pdid]
    if !found {
        return
    }

    if oldMAC := NormalizeMAC(d.CurrentMAC); oldMAC != "" && oldMAC != cleanMAC {
        if existing, ok := c.macIndex[oldMAC]; ok && existing.PDID == pdid {
            delete(c.macIndex, oldMAC)
        }
    }

    if oldDev, exists := c.macIndex[cleanMAC]; exists && oldDev.PDID != pdid {
        slog.Warn("MAC index collision during SetCurrentMAC", "mac", cleanMAC, "old_pdid", oldDev.PDID, "new_pdid", pdid) // FIXED SYNTAX
    }

    d.AddMAC(cleanMAC)
    c.macIndex[cleanMAC] = d
}

func (c *Cache) GetByMACOrIP(macStr, ipStr string) *models.Device {
    if d := c.GetByMAC(macStr); d != nil {
        return d
    }
    if d := c.GetByMACCluster(macStr); d != nil {
        return d
    }
    return c.GetByIP(ipStr)
}

func (c *Cache) Get(pdid string) *models.Device {
    c.mu.RLock()
    defer c.mu.RUnlock()

    d, ok := c.devices[pdid]
    if !ok {
        return nil
    }
    devCopy := *d
    return &devCopy
}

func (c *Cache) List() []models.Device {
    c.mu.RLock()
    defer c.mu.RUnlock()

    list := make([]models.Device, 0, len(c.devices))
    for _, d := range c.devices {
        list = append(list, *d)
    }
    return list
}

// Gap 1 Fix Reinforcement: Clean up old indices strictly on Upsert
func (c *Cache) Upsert(d *models.Device) {
    if d == nil || d.PDID == "" {
        return
    }

    c.mu.Lock()
    defer c.mu.Unlock()

    if old, exists := c.devices[d.PDID]; exists {
        if oldMAC := NormalizeMAC(old.CurrentMAC); oldMAC != "" && oldMAC != NormalizeMAC(d.CurrentMAC) {
            if idx, ok := c.macIndex[oldMAC]; ok && idx.PDID == d.PDID {
                delete(c.macIndex, oldMAC)
            }
        }
        if oldIP := strings.TrimSpace(old.CurrentIP); oldIP != "" && oldIP != strings.TrimSpace(d.CurrentIP) {
            if idx, ok := c.ipIndex[oldIP]; ok && idx.PDID == d.PDID {
                delete(c.ipIndex, oldIP)
            }
        }
    }

    devCopy := *d
    c.devices[d.PDID] = &devCopy

    if cleanMAC := NormalizeMAC(d.CurrentMAC); cleanMAC != "" {
        c.macIndex[cleanMAC] = &devCopy
    }

    if cleanIP := strings.TrimSpace(d.CurrentIP); cleanIP != "" {
        c.ipIndex[cleanIP] = &devCopy
    }
}

func (c *Cache) Delete(pdid string) {
    c.mu.Lock()
    var releasedHosts []string
    if d, ok := c.devices[pdid]; ok {
        if cleanMAC := NormalizeMAC(d.CurrentMAC); cleanMAC != "" {
            delete(c.macIndex, cleanMAC)
        }
        if cleanIP := strings.TrimSpace(d.CurrentIP); cleanIP != "" {
            delete(c.ipIndex, cleanIP)
        }
        if d.CanonicalHostname != "" {
            if owner, exists := c.hostnameOwners[d.CanonicalHostname]; exists && owner == pdid {
                delete(c.hostnameOwners, d.CanonicalHostname)
                releasedHosts = append(releasedHosts, d.CanonicalHostname)
            }
        }
        delete(c.devices, pdid)
    }
    listener := c.ownerListener
    c.mu.Unlock()

    if listener != nil {
        for _, host := range releasedHosts {
            listener(host, pdid, true)
        }
    }
}

func (c *Cache) Stop() {
    close(c.stopCh)
}

func (c *Cache) purgeLoop() {
    ticker := time.NewTicker(20 * time.Second)
    defer ticker.Stop()

    for {
        select {
        case <-c.stopCh:
            return
        case <-ticker.C:
            c.purgeOffline()
        }
    }
}

func (c *Cache) purgeOffline() {
    c.mu.Lock()
    now := time.Now()
    var releasedHosts []string
    var releasedPDIDs []string

    for pdid, d := range c.devices {
        if !d.Online && now.Sub(d.LastSeen) > offlineTTL {
            slog.Info("Purging offline device from cache", "pdid", pdid, "mac", d.CurrentMAC) // FIXED SYNTAX
            if cleanMAC := NormalizeMAC(d.CurrentMAC); cleanMAC != "" {
                delete(c.macIndex, cleanMAC)
            }
            if cleanIP := strings.TrimSpace(d.CurrentIP); cleanIP != "" {
                delete(c.ipIndex, cleanIP)
            }
            if d.CanonicalHostname != "" {
                if owner, exists := c.hostnameOwners[d.CanonicalHostname]; exists && owner == pdid {
                    delete(c.hostnameOwners, d.CanonicalHostname)
                    releasedHosts = append(releasedHosts, d.CanonicalHostname)
                    releasedPDIDs = append(releasedPDIDs, pdid)
                }
            }
            delete(c.devices, pdid)
        }
    }
    listener := c.ownerListener
    c.mu.Unlock()

    if listener != nil {
        for i, host := range releasedHosts {
            listener(host, releasedPDIDs[i], true)
        }
    }
}
