// Package sync provides the mechanisms for LIAS to consume and mirror
// the device inventory from the Discovery Intelligence Service (DIS).
//
// File:    apps/lias/internal/sync/cache.go
// Version: 2.3 (Added PatchDeviceOnline for instant SSE updates)
package sync

import (
    "strings"
    "sync"
    "time"

    "github.com/user/lias-dis/shared/models"
)

type LocalDevice struct {
    models.Device
    Tags            []string       `json:"tags"`
    Policy          *models.Policy `json:"policy,omitempty"`
    NextStateChange *time.Time     `json:"next_state_change,omitempty"`
}

type Cache struct {
    mu         sync.RWMutex // CPU-03 Fix: Use RWMutex
    devices    map[string]*LocalDevice
    stickyTags map[string][]string
    stickyMACs map[string][]string
}

func NewCache() *Cache {
    return &Cache{
        devices:    make(map[string]*LocalDevice),
        stickyTags: make(map[string][]string),
        stickyMACs: make(map[string][]string),
    }
}

func (c *Cache) LoadStickyTags(pdidTags, macTags map[string][]string) {
    c.mu.Lock()
    defer c.mu.Unlock()

    for pdid, tags := range pdidTags {
        c.stickyTags[pdid] = tags
    }
    for mac, tags := range macTags {
        cleanMAC := strings.ToLower(strings.TrimSpace(mac))
        if cleanMAC != "" {
            c.stickyMACs[cleanMAC] = tags
        }
    }

    for _, d := range c.devices {
        c.applyStickyTagLocked(d)
    }
}

func (c *Cache) applyStickyTagLocked(d *LocalDevice) {
    if tags, found := c.stickyTags[d.PDID]; found && len(tags) > 0 {
        d.Tags = tags
        d.Device.Tags = tags
        return
    }

    for _, mac := range d.MACs {
        cleanMAC := strings.ToLower(strings.TrimSpace(mac))
        if macTags, found := c.stickyMACs[cleanMAC]; found && len(macTags) > 0 {
            d.Tags = macTags
            d.Device.Tags = macTags
            c.stickyTags[d.PDID] = macTags
            return
        }
    }

    if len(d.Tags) == 0 {
        if len(d.Device.Tags) > 0 {
            d.Tags = d.Device.Tags
        } else {
            d.Tags = []string{"generic"}
            d.Device.Tags = []string{"generic"}
        }
    }
}

func (c *Cache) MigrateDeviceIdentity(oldPDID, newPDID string, migratedMACs []string) {
    c.mu.Lock()
    defer c.mu.Unlock()

    if tags, found := c.stickyTags[oldPDID]; found {
        c.stickyTags[newPDID] = tags
        delete(c.stickyTags, oldPDID)
    }

    delete(c.devices, oldPDID)
}

// CPU-03 Fix: Get uses RLock and does not mutate the cache.
func (c *Cache) Get(pdid string) *LocalDevice {
    c.mu.RLock()
    defer c.mu.RUnlock()

    d, ok := c.devices[pdid]
    if !ok {
        return nil
    }
    devCopy := *d
    return &devCopy
}

// CPU-03 Fix: List uses RLock and does not mutate the cache.
func (c *Cache) List() []LocalDevice {
    c.mu.RLock()
    defer c.mu.RUnlock()

    list := make([]LocalDevice, 0, len(c.devices))
    for _, d := range c.devices {
        devCopy := *d
        list = append(list, devCopy)
    }
    return list
}

func (c *Cache) ListPDIDs() []string {
    c.mu.RLock()
    defer c.mu.RUnlock()

    list := make([]string, 0, len(c.devices))
    for pdid := range c.devices {
        list = append(list, pdid)
    }
    return list
}

func (c *Cache) UpsertDevice(d models.Device) {
    if d.PDID == "" {
        return
    }

    c.mu.Lock()
    defer c.mu.Unlock()

    if existing, ok := c.devices[d.PDID]; ok {
        pol := existing.Policy
        nextChange := existing.NextStateChange

        existing.Device = d
        existing.Policy = pol
        existing.NextStateChange = nextChange
        c.applyStickyTagLocked(existing)
    } else {
        ld := &LocalDevice{
            Device: d,
        }
        c.applyStickyTagLocked(ld)
        c.devices[d.PDID] = ld
    }
}

func (c *Cache) RemoveDevice(pdid string) {
    c.mu.Lock()
    defer c.mu.Unlock()
    delete(c.devices, pdid)
}

func (c *Cache) SetPolicy(pdid string, p *models.Policy) {
    c.mu.Lock()
    defer c.mu.Unlock()
    if d, ok := c.devices[pdid]; ok {
        d.Policy = p
    }
}

func (c *Cache) SetTags(pdid string, tags []string) {
    c.mu.Lock()
    defer c.mu.Unlock()

    if len(tags) == 0 {
        tags = []string{"generic"}
    }

    c.stickyTags[pdid] = tags

    if d, ok := c.devices[pdid]; ok {
        for _, mac := range d.MACs {
            cleanMAC := strings.ToLower(strings.TrimSpace(mac))
            if cleanMAC != "" {
                c.stickyMACs[cleanMAC] = tags
            }
        }
        d.Tags = tags
        d.Device.Tags = tags
    }
}

func (c *Cache) SetNextStateChange(pdid string, t *time.Time) {
    c.mu.Lock()
    defer c.mu.Unlock()
    if d, ok := c.devices[pdid]; ok {
        d.NextStateChange = t
    }
}

// V2.3 FIX: PatchDeviceOnline updates the online status of a device in the cache
// without overwriting the rest of the device struct. This is used for instant SSE updates.
func (c *Cache) PatchDeviceOnline(pdid string, online bool) {
    c.mu.Lock()
    defer c.mu.Unlock()
    
    if d, ok := c.devices[pdid]; ok {
        if d.Online != online {
            d.Online = online
            d.Device.Online = online
        }
    }
}
