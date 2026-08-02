// Package sync provides the mechanisms for LIAS to consume and mirror
// the device inventory from the Discovery Intelligence Service (DIS).
//
// File:    apps/lias/internal/sync/cache.go
// Version: 1.3
package sync

import (
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
	mu         sync.RWMutex
	devices    map[string]*LocalDevice
	stickyTags map[string]string // Sticky user-assigned tags: PDID -> TagID
}

func NewCache() *Cache {
	return &Cache{
		devices:    make(map[string]*LocalDevice),
		stickyTags: make(map[string]string),
	}
}

// LoadStickyTags populates the in-memory sticky tag mapping from storage on boot.
func (c *Cache) LoadStickyTags(tags map[string]string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for pdid, tagID := range tags {
		c.stickyTags[pdid] = tagID
		if d, ok := c.devices[pdid]; ok {
			d.Tags = []string{tagID}
		}
	}
}

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

func (c *Cache) List() []LocalDevice {
	c.mu.RLock()
	defer c.mu.RUnlock()

	list := make([]LocalDevice, 0, len(c.devices))
	for _, d := range c.devices {
		list = append(list, *d)
	}
	return list
}

// UpsertDevice adds or updates a base device record from DIS while preserving sticky local tags.
func (c *Cache) UpsertDevice(d models.Device) {
	if d.PDID == "" {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// Resolve tag assignment: Sticky user tag > existing tag > DIS tag > "generic"
	assignedTag := "generic"
	if sticky, found := c.stickyTags[d.PDID]; found && sticky != "" {
		assignedTag = sticky
	} else if existing, ok := c.devices[d.PDID]; ok && len(existing.Tags) > 0 {
		assignedTag = existing.Tags[0]
	} else if len(d.Tags) > 0 && d.Tags[0] != "" {
		assignedTag = d.Tags[0]
	}

	if existing, ok := c.devices[d.PDID]; ok {
		pol := existing.Policy
		nextChange := existing.NextStateChange

		existing.Device = d
		existing.Tags = []string{assignedTag}
		existing.Policy = pol
		existing.NextStateChange = nextChange
	} else {
		c.devices[d.PDID] = &LocalDevice{
			Device: d,
			Tags:   []string{assignedTag},
		}
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
		d.Tags = []string{tagID}
	}
}

func (c *Cache) SetNextStateChange(pdid string, t *time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if d, ok := c.devices[pdid]; ok {
		d.NextStateChange = t
	}
}
