// Package sync provides the mechanisms for LIAS to consume and mirror
// the device inventory from the Discovery Intelligence Service (DIS).
//
// File:    apps/lias/internal/sync/cache.go
// Version: 1.2
package sync

import (
	"sync"
	"time"

	"github.com/user/lias-dis/shared/models"
)

// LocalDevice represents the LIAS view of a network device, combining base DIS attributes
// with local access management overlays.
type LocalDevice struct {
	models.Device
	Tags            []string       `json:"tags"`
	Policy          *models.Policy `json:"policy,omitempty"`
	NextStateChange *time.Time     `json:"next_state_change,omitempty"`
}

// Cache is a thread-safe in-memory store for LIAS local device mirrors.
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

// Get retrieves a local device record by PDID. Returns nil if not found.
func (c *Cache) Get(pdid string) *LocalDevice {
	c.mu.RLock()
	defer c.mu.RUnlock()

	d, ok := c.devices[pdid]
	if !ok {
		return nil
	}

	// Return a deep copy to prevent race conditions during concurrent updates
	devCopy := *d
	return &devCopy
}

// List returns a slice containing all local device records.
func (c *Cache) List() []LocalDevice {
	c.mu.RLock()
	defer c.mu.RUnlock()

	list := make([]LocalDevice, 0, len(c.devices))
	for _, d := range c.devices {
		list = append(list, *d)
	}
	return list
}

// UpsertDevice adds or updates a base device record from DIS while preserving local LIAS overlays.
func (c *Cache) UpsertDevice(d models.Device) {
	if d.PDID == "" {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if existing, ok := c.devices[d.PDID]; ok {
		tags := existing.Tags
		pol := existing.Policy
		nextChange := existing.NextStateChange

		existing.Device = d
		existing.Tags = tags
		existing.Policy = pol
		existing.NextStateChange = nextChange
	} else {
		c.devices[d.PDID] = &LocalDevice{
			Device: d,
			Tags:   []string{"generic"}, // Default tag assignment per §4.7
		}
	}
}

// RemoveDevice deletes a device record from the local cache.
func (c *Cache) RemoveDevice(pdid string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.devices, pdid)
}

// SetPolicy assigns a policy overlay to a device in the local cache.
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
		if len(tags) == 0 {
			d.Tags = []string{"generic"}
		} else {
			d.Tags = tags
		}
	}
}

// SetNextStateChange updates the next state change timestamp for scheduled devices.
func (c *Cache) SetNextStateChange(pdid string, t *time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if d, ok := c.devices[pdid]; ok {
		d.NextStateChange = t
	}
}
