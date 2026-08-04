// Package sync provides the mechanisms for LIAS to consume and mirror
// the device inventory from the Discovery Intelligence Service (DIS).
//
// File:    apps/lias/internal/sync/cache.go
// Version: 2.0
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
    stickyTags map[string]string
    stickyMACs map[string]string
}

func NewCache() *Cache {
    return &Cache{
        devices:    make(map[string]*LocalDevice),
        stickyTags: make(map[string]string),
        stickyMACs: make(map[string]string),
    }
}

func (c *Cache) LoadStickyTags(pdidTags, macTags map[string]string) {
    c.mu.Lock()
    defer c.mu.Unlock()

    for pdid, tagID := range pdidTags {
        c.stickyTags[pdid] = tagID
    }
    for mac, tagID := range macTags {
        cleanMAC := strings.ToLower(strings.TrimSpace(mac))
        if cleanMAC != "" {
            c.stickyMACs[cleanMAC] = tagID
        }
    }

    for _, d := range c.devices {
        c.applyStickyTagLocked(d)
    }
}

func (c *Cache) applyStickyTagLocked(d *LocalDevice) {
    assignedTag := "generic"

    if tag, found := c.stickyTags[d.PDID]; found && tag != "" {
        assignedTag = tag
    } else {
        for _, mac := range d.MACs {
            cleanMAC := strings.ToLower(strings.TrimSpace(mac))
            if macTag, found := c.stickyMACs[cleanMAC]; found && macTag != "" {
                assignedTag = macTag
                c.stickyTags[d.PDID] = assignedTag
                break
            }
        }
    }

    if assignedTag == "generic" {
        if len(d.Tags) > 0 && d.Tags[0] != "" {
            assignedTag = d.Tags[0]
        } else if len(d.Device.Tags) > 0 && d.Device.Tags[0] != "" {
            assignedTag = d.Device.Tags[0]
        }
    }

    d.Tags = []string{assignedTag}
    d.Device.Tags = []string{assignedTag}

    if assignedTag != "generic" {
        for _, mac := range d.MACs {
            cleanMAC := strings.ToLower(strings.TrimSpace(mac))
            if cleanMAC != "" {
                c.stickyMACs[cleanMAC] = assignedTag
            }
        }
    }
}

func (c *Cache) MigrateDeviceIdentity(oldPDID, newPDID string, migratedMACs []string) {
    c.mu.Lock()
    defer c.mu.Unlock()

    if tag, found := c.stickyTags[oldPDID]; found {
        c.stickyTags[newPDID] = tag
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

// ListPDIDs returns a slice of all PDIDs currently in the cache.
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

func (c *Cache) SetTags(pdid string, tags []string) {
    c.mu.Lock()
    defer c.mu.Unlock()

    tagID := "generic"
    if len(tags) > 0 && tags[0] != "" {
        tagID = tags[0]
    }

    c.stickyTags[pdid] = tagID

    if d, ok := c.devices[pdid]; ok {
        for _, mac := range d.MACs {
            cleanMAC := strings.ToLower(strings.TrimSpace(mac))
            if cleanMAC != "" {
                c.stickyMACs[cleanMAC] = tagID
            }
        }
        d.Tags = []string{tagID}
        d.Device.Tags = []string{tagID}
    }
}

func (c *Cache) SetNextStateChange(pdid string, t *time.Time) {
    c.mu.Lock()
    defer c.mu.Unlock()
    if d, ok := c.devices[pdid]; ok {
        d.NextStateChange = t
    }
}
