// Package sync provides the mechanisms for LIAS to consume and mirror
// the device inventory from the Discovery Intelligence Service (DIS).
//
// File:    apps/lias/internal/sync/cache.go
// Version: 1.4
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
	mu         sync.RWMutex
	devices    map[string]*LocalDevice
	stickyTags map[string]string // PDID -> TagID
	stickyMACs map[string]string // MAC -> TagID
}

func NewCache() *Cache {
	return &Cache{
		devices:    make(map[string]*LocalDevice),
		stickyTags: make(map[string]string),
		stickyMACs: make(map[string]string),
	}
}

// LoadStickyTags populates the in-memory sticky tag mappings from SQLite storage on startup.
func (c *Cache) LoadStickyTags(pdidTags, macTags map[string]string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	for pdid, tagID := range pdidTags {
		c.stickyTags[pdid] = tagID
	}
	for mac, tagID := range macTags {
		c.stickyMACs[strings.ToLower(mac)] = tagID
	}

	for _, d := range c.devices {
		c.applyStickyTagLocked(d)
	}
}

func (c *Cache) applyStickyTagLocked(d *LocalDevice) {
	assignedTag := "generic"

	// Priority: Sticky PDID Tag > Sticky MAC Tag > Existing Tag > DIS Tag > "generic"
	if tag, found := c.stickyTags[d.PDID]; found && tag != "" {
		assignedTag = tag
	} else if macTag, found := c.stickyMACs[strings.ToLower(d.CurrentMAC)]; found && macTag != "" {
		assignedTag = macTag
	} else if len(d.Tags) > 0 && d.Tags[0] != "" {
		assignedTag = d.Tags[0]
	} else if len(d.Device.Tags) > 0 && d.Device.Tags[0] != "" {
		assignedTag = d.Device.Tags[0]
	}

	d.Tags = []string{assignedTag}
	d.Device.Tags = []string{assignedTag} // Synchronize inner embedded struct tags!
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
		devCopy := *d
		c.applyStickyTagLocked(&devCopy)
		list = append(list, devCopy)
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
		if d.CurrentMAC != "" {
			c.stickyMACs[strings.ToLower(d.CurrentMAC)] = tagID
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
