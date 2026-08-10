// Package inventory provides the in-memory device store for DIS.
//
// File:    apps/discovery-service/internal/inventory/cache.go
// Version: 2.10 (Added TouchLastSeen for CPU-01)
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
	deviceIDIndex  map[string]*models.Device
    macIndex       map[string]*models.Device
    ipIndex        map[string]*models.Device
    hostnameOwners map[string]string
    dormant        map[string]bool
    ownerListener  HostnameOwnerListener
    stopCh         chan struct{}
}

func NewCache() *Cache {
    c := &Cache{
        devices:        make(map[string]*models.Device),
		deviceIDIndex:  make(map[string]*models.Device),
        macIndex:       make(map[string]*models.Device),
        ipIndex:        make(map[string]*models.Device),
        hostnameOwners: make(map[string]string),
        dormant:        make(map[string]bool),
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
        if !exists {
            c.hostnameOwners[canonicalHost] = pdid
            listener := c.ownerListener
            c.mu.Unlock()
            if listener != nil {
                listener(canonicalHost, pdid, false)
            }
            return AcquireSuccess
        }
        c.mu.Unlock()
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
        if c.dormant[pdid] {
            continue
        }
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
			return d.Clone()
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
			return d.Clone()
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
			return d.Clone()
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
        if d.CurrentIP == cleanIP {
            d.CurrentIP = ""
        }
        delete(c.ipIndex, cleanIP)
        slog.Info("Released current IP ownership while preserving history", "ip", cleanIP, "pdid", d.PDID)
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

    if oldDev, exists := c.macIndex[cleanMAC]; exists && oldDev.PDID != pdid {
        slog.Warn("MAC index collision during SetCurrentMAC", "mac", cleanMAC, "old_pdid", oldDev.PDID, "new_pdid", pdid)
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
	return d.Clone()
}

// GetActive preserves the public inventory behavior: dormant identities remain
// resolvable internally by MAC but are not returned as active inventory rows.
func (c *Cache) GetActive(pdid string) *models.Device {
    c.mu.RLock()
    defer c.mu.RUnlock()
    if c.dormant[pdid] {
        return nil
    }
    d := c.devices[pdid]
    if d == nil {
        return nil
    }
    return d.Clone()
}

func (c *Cache) GetByDeviceID(deviceID string) *models.Device {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if d := c.deviceIDIndex[strings.TrimSpace(deviceID)]; d != nil {
		return d.Clone()
	}
	return nil
}

func (c *Cache) List() []models.Device {
    c.mu.RLock()
    defer c.mu.RUnlock()

    list := make([]models.Device, 0, len(c.devices))
    for pdid, d := range c.devices {
        if c.dormant[pdid] {
            continue
        }
		list = append(list, *d.Clone())
    }
    return list
}

// MATH-02 Fix: Clean up old indices strictly on Upsert based on the OLD cache entry
func (c *Cache) Upsert(d *models.Device) {
    if d == nil || d.PDID == "" {
        return
    }

    c.mu.Lock()
    defer c.mu.Unlock()

    if old, exists := c.devices[d.PDID]; exists {
		if old.DeviceID != "" && old.DeviceID != d.DeviceID {
			delete(c.deviceIDIndex, old.DeviceID)
		}
        nextMACs := make(map[string]bool, len(d.MACs))
        for _, mac := range d.MACs {
            if clean := NormalizeMAC(mac); clean != "" {
                nextMACs[clean] = true
            }
        }
        for _, mac := range old.MACs {
            clean := NormalizeMAC(mac)
            if clean != "" && !nextMACs[clean] {
                if idx, ok := c.macIndex[clean]; ok && idx.PDID == d.PDID {
                    delete(c.macIndex, clean)
                }
            }
        }
        oldIP := strings.TrimSpace(old.CurrentIP)
        newIP := strings.TrimSpace(d.CurrentIP)
        if oldIP != "" && oldIP != newIP {
            if idx, ok := c.ipIndex[oldIP]; ok && idx.PDID == d.PDID {
                delete(c.ipIndex, oldIP)
            }
        }
    }

	devCopy := d.Clone()
	c.devices[d.PDID] = devCopy
	delete(c.dormant, d.PDID)
	if d.DeviceID != "" {
		c.deviceIDIndex[d.DeviceID] = devCopy
	}

    // device_macs is authoritative. Index every owned historical MAC and do
    // not index an inconsistent current_mac that has no ownership row.
    for _, mac := range d.MACs {
        if cleanMAC := NormalizeMAC(mac); cleanMAC != "" {
			c.macIndex[cleanMAC] = devCopy
        }
    }

    if cleanIP := strings.TrimSpace(d.CurrentIP); cleanIP != "" {
		c.ipIndex[cleanIP] = devCopy
    }
}

// CPU-01 Fix: Lightweight timestamp update that doesn't rebuild indices
func (c *Cache) TouchLastSeen(pdid string, ts time.Time) {
    c.mu.Lock()
    defer c.mu.Unlock()
    if d, ok := c.devices[pdid]; ok {
        d.LastSeen = ts
        if d.FirstSeen.IsZero() {
            d.FirstSeen = ts
        }
    }
}

func (c *Cache) Delete(pdid string) {
    c.mu.Lock()
    var releasedHosts []string
    if d, ok := c.devices[pdid]; ok {
        for _, mac := range d.MACs {
			if cleanMAC := NormalizeMAC(mac); cleanMAC != "" {
				if indexed := c.macIndex[cleanMAC]; indexed != nil && indexed.PDID == pdid {
					delete(c.macIndex, cleanMAC)
				}
			}
        }
        if cleanIP := strings.TrimSpace(d.CurrentIP); cleanIP != "" {
            if indexed := c.ipIndex[cleanIP]; indexed != nil && indexed.PDID == pdid {
                delete(c.ipIndex, cleanIP)
            }
        }
        if d.CanonicalHostname != "" {
            if owner, exists := c.hostnameOwners[d.CanonicalHostname]; exists && owner == pdid {
                delete(c.hostnameOwners, d.CanonicalHostname)
                releasedHosts = append(releasedHosts, d.CanonicalHostname)
            }
        }
		delete(c.deviceIDIndex, d.DeviceID)
        delete(c.devices, pdid)
        delete(c.dormant, pdid)
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
		if !c.dormant[pdid] && !d.Online && now.Sub(d.LastSeen) > offlineTTL {
			slog.Info("Marking offline device dormant while retaining identity ownership", "pdid", pdid, "mac", d.CurrentMAC)
			if cleanIP := strings.TrimSpace(d.CurrentIP); cleanIP != "" {
				if indexed := c.ipIndex[cleanIP]; indexed != nil && indexed.PDID == pdid {
					delete(c.ipIndex, cleanIP)
				}
            }
            if d.CanonicalHostname != "" {
                if owner, exists := c.hostnameOwners[d.CanonicalHostname]; exists && owner == pdid {
                    delete(c.hostnameOwners, d.CanonicalHostname)
                    releasedHosts = append(releasedHosts, d.CanonicalHostname)
                    releasedPDIDs = append(releasedPDIDs, pdid)
                }
            }
			c.dormant[pdid] = true
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
