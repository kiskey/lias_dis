// Package inventory provides the in-memory device store for DIS.
//
// File:    apps/discovery-service/internal/inventory/cache.go
// Version: 2.5
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

// HostnameAcquisitionResult indicates the outcome of attempting to lock a hostname.
type HostnameAcquisitionResult int

const (
    AcquireSuccess HostnameAcquisitionResult = iota
    AcquireReject
    AcquireProvisional
)

type HostnameOwnerListener func(canonicalHost, pdid string, isDelete bool)

// Cache is a thread-safe in-memory store with indexed lookups and hostname ownership locks.
type Cache struct {
    mu             sync.RWMutex
    devices        map[string]*models.Device // Keyed by PDID
    macIndex       map[string]*models.Device // Keyed by CurrentMAC only
    ipIndex        map[string]*models.Device // Keyed by CurrentIP only
    hostnameOwners map[string]string        // Canonical Hostname -> PDID
    ownerListener  HostnameOwnerListener
    stopCh         chan struct{}
}

// NewCache initializes a new device cache and starts the TTL purger.
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

// AcquireHostname attempts to lock canonicalHost for a target pdid.
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

    // Grace window (5m to 24h)
    c.hostnameOwners[canonicalHost] = pdid
    listener := c.ownerListener
    c.mu.Unlock()
    if listener != nil {
        listener(canonicalHost, pdid, false)
    }
    return AcquireProvisional
}

// IsHostnameActivelyOwned returns true if the hostname is owned by an online device.
// Used to prevent nil pointer dereferences when checking availability for new devices.
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

// ReleaseHostname releases ownership of canonicalHost if owned by pdid.
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

// GetHostnameOwner retrieves the PDID owning canonicalHost.
func (c *Cache) GetHostnameOwner(canonicalHost string) (string, bool) {
    if canonicalHost == "" {
        return "", false
    }

    c.mu.RLock()
    defer c.mu.RUnlock()

    pdid, exists := c.hostnameOwners[canonicalHost]
    return pdid, exists
}

// DemoteStale flips Online: true -> false for devices with no observation within staleThreshold (3 minutes).
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

// GetByMAC performs an O(1) indexed lookup on CurrentMAC.
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

// GetByMACCluster performs a scan across all historical MAC clusters.
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

// GetByIP performs an O(1) indexed lookup on CurrentIP.
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

// RemoveIPIndex clears the IP index and updates the owner device atomically.
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
        slog.Info("Invalidated stale IP index mapping", "ip", cleanIP, "pdid", d.PDID)
    }
}

// SetCurrentIP sets the device's CurrentIP and updates index atomically.
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

// SetCurrentMAC sets the device's CurrentMAC and updates index atomically. (GAP-D07)
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
        slog.Warn("MAC index collision during SetCurrentMAC", "mac", cleanMAC, "old_pdid", oldDev.PDID, "new_pdid", pdid)
    }

    d.AddMAC(cleanMAC)
    c.macIndex[cleanMAC] = d
}

// GetByMACOrIP performs an indexed lookup checking MAC first, falling back to IP.
func (c *Cache) GetByMACOrIP(macStr, ipStr string) *models.Device {
    if d := c.GetByMAC(macStr); d != nil {
        return d
    }
    if d := c.GetByMACCluster(macStr); d != nil {
        return d
    }
    return c.GetByIP(ipStr)
}

// Get retrieves a device by PDID.
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

// List returns copies of all cached devices.
func (c *Cache) List() []models.Device {
    c.mu.RLock()
    defer c.mu.RUnlock()

    list := make([]models.Device, 0, len(c.devices))
    for _, d := range c.devices {
        list = append(list, *d)
    }
    return list
}

// Upsert adds or updates a device record, indexing ONLY CurrentMAC and CurrentIP.
func (c *Cache) Upsert(d *models.Device) {
    if d == nil || d.PDID == "" {
        return
    }

    c.mu.Lock()
    defer c.mu.Unlock()

    devCopy := *d
    c.devices[d.PDID] = &devCopy

    if cleanMAC := NormalizeMAC(d.CurrentMAC); cleanMAC != "" {
        c.macIndex[cleanMAC] = &devCopy
    }

    if cleanIP := strings.TrimSpace(d.CurrentIP); cleanIP != "" {
        c.ipIndex[cleanIP] = &devCopy
    }
}

// Delete removes a device and clears its associated index entries.
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

// Stop terminates the background TTL purger.
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
            slog.Info("Purging offline device from cache", "pdid", pdid, "mac", d.CurrentMAC)
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
