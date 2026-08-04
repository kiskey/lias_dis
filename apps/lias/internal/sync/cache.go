// Package sync provides the mechanisms for LIAS to consume and mirror
// the device inventory from the Discovery Intelligence Service (DIS).
//
// File:    apps/lias/internal/sync/cache.go
// Version: 2.1
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
    mu         sync.Mutex
    devices    map[string]*LocalDevice
    stickyTags map[string][]string // LIAS-TAG-01 Fix: Multi-tag support
    stickyMACs map[string][]string // LIAS-TAG-01 Fix: Multi-tag support
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

    // Fallback to existing or generic
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

func (c *Cache) Get(pdid string) *LocalDevice {
    c.mu.Lock()
    defer c.mu.Unlock()

    d, ok := c.devices[pdid]
    if !ok {
        return nil
    }
    devCopy := *d
    c.applyStickyTagLocked(&devCopy)
    if ptr, exists := c.devices[pdid]; exists {
        ptr.Tags = devCopy.Tags
        ptr.Device.Tags = devCopy.Device.Tags
    }
    return &devCopy
}

func (c *Cache) List() []LocalDevice {
    c.mu.Lock()
    defer c.mu.Unlock()

    list := make([]LocalDevice, 0, len(c.devices))
    for pdid, d := range c.devices {
        devCopy := *d
        c.applyStickyTagLocked(&devCopy)
        if ptr, exists := c.devices[pdid]; exists {
            ptr.Tags = devCopy.Tags
            ptr.Device.Tags = devCopy.Device.Tags
        }
        list = append(list, devCopy)
    }
    return list
}

func (c *Cache) ListPDIDs() []string {
    c.mu.Lock()
    defer c.mu.Unlock()

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

// LIAS-TAG-01 Fix: SetTags accepts a slice of tags
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
