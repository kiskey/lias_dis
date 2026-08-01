// Package sync provides the mechanisms for LIAS to consume and mirror
// the device inventory from the Discovery Intelligence Service (DIS).
//
// File:    apps/lias/internal/sync/cache.go
// Version: 1.0
package sync

import (
    "sync"
    "time"

    "github.com/user/lias-dis/shared/models"
)

// LocalDevice represents the LIAS-side view of a network device.
// It embeds the canonical models.Device and overlays LIAS-specific state.
type LocalDevice struct {
    models.Device
    Tags            []string     `json:"tags"`
    Policy          *models.Policy `json:"policy,omitempty"`
    NextStateChange *time.Time   `json:"next_state_change,omitempty"`
}

// Cache is a thread-safe in-memory store for LIAS's local view of devices.
// It is keyed by PDID.
type Cache struct {
    mu      sync.RWMutex
    devices map[string]*LocalDevice
}

// NewCache initializes a new local device cache.
func NewCache() *Cache {
    return &Cache{
        devices: make(map[string]*LocalDevice),
    }
}

// Get retrieves a local device by PDID. Returns nil if not found.
func (c *Cache) Get(pdid string) *LocalDevice {
    c.mu.RLock()
    defer c.mu.RUnlock()

    d, ok := c.devices[pdid]
    if !ok {
        return nil
    }
    // Return a copy to prevent race conditions outside the lock
    dev := *d
    return &dev
}

// List returns a slice of all local devices.
func (c *Cache) List() []LocalDevice {
    c.mu.RLock()
    defer c.mu.RUnlock()

    list := make([]LocalDevice, 0, len(c.devices))
    for _, d := range c.devices {
        list = append(list, *d)
    }
    return list
}

// UpsertDevice adds or updates a base device record from DIS.
// It preserves existing LIAS overlays (Tags, Policy) if the device already exists.
func (c *Cache) UpsertDevice(d models.Device) {
    if d.PDID == "" {
        return
    }
    c.mu.Lock()
    defer c.mu.Unlock()

    if existing, ok := c.devices[d.PDID]; ok {
        // Preserve LIAS overlays
        tags := existing.Tags
        policy := existing.Policy
        nextState := existing.NextStateChange
        
        existing.Device = d
        existing.Tags = tags
        existing.Policy = policy
        existing.NextStateChange = nextState
    } else {
        c.devices[d.PDID] = &LocalDevice{
            Device: d,
            Tags:   []string{}, // Initialize with empty tags
        }
    }
}

// RemoveDevice deletes a device from the local cache.
func (c *Cache) RemoveDevice(pdid string) {
    c.mu.Lock()
    defer c.mu.Unlock()
    delete(c.devices, pdid)
}

// SetPolicy assigns a policy to a device in the local cache.
func (c *Cache) SetPolicy(pdid string, p *models.Policy) {
    c.mu.Lock()
    defer c.mu.Unlock()
    if d, ok := c.devices[pdid]; ok {
        d.Policy = p
    }
}

// SetTags assigns tags to a device in the local cache.
func (c *Cache) SetTags(pdid string, tags []string) {
    c.mu.Lock()
    defer c.mu.Unlock()
    if d, ok := c.devices[pdid]; ok {
        d.Tags = tags
    }
}

// SetNextStateChange updates the calculated next state change time for a device.
func (c *Cache) SetNextStateChange(pdid string, t *time.Time) {
    c.mu.Lock()
    defer c.mu.Unlock()
    if d, ok := c.devices[pdid]; ok {
        d.NextStateChange = t
    }
}
