// Package sync provides the mechanisms for LIAS to consume and mirror
// the device inventory from the Discovery Intelligence Service (DIS).
//
// File:    apps/lias/internal/sync/cache.go
// Version: 1.8
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
	mu         sync.Mutex // Mutex protecting all read/write map operations
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
		cleanMAC := strings.ToLower(strings.TrimSpace(mac))
		if cleanMAC != "" {
			c.stickyMACs[cleanMAC] = tagID
		}
	}

	for _, d := range c.devices {
		c.applyStickyTagLocked(d)
	}
}

// applyStickyTagLocked MUST be called while holding c.mu.Lock().
func (c *Cache) applyStickyTagLocked(d *LocalDevice) {
	assignedTag := "generic"

	// 1. Direct PDID match
	if tag, found := c.stickyTags[d.PDID]; found && tag != "" {
		assignedTag = tag
	} else {
		// 2. Multi-MAC fallback: Check ALL accumulated MAC addresses on the device record
		for _, mac := range d.MACs {
			cleanMAC := strings.ToLower(strings.TrimSpace(mac))
			if macTag, found := c.stickyMACs[cleanMAC]; found && macTag != "" {
				assignedTag = macTag
				c.stickyTags[d.PDID] = assignedTag // Auto-repair stickyTags map for current PDID
				break
			}
		}
	}

	// 3. Fallback to DIS or existing tag
	if assignedTag == "generic" {
		if len(d.Tags) > 0 && d.Tags[0] != "" {
			assignedTag = d.Tags[0]
		} else if len(d.Device.Tags) > 0 && d.Device.Tags[0] != "" {
			assignedTag = d.Device.Tags[0]
		}
	}

	d.Tags = []string{assignedTag}
	d.Device.Tags = []string{assignedTag}

	// 4. Backfill stickyMACs for all known MAC addresses (including rotated Private MACs)
	if assignedTag != "generic" {
		for _, mac := range d.MACs {
			cleanMAC := strings.ToLower(strings.TrimSpace(mac))
			if cleanMAC != "" {
				c.stickyMACs[cleanMAC] = assignedTag
			}
		}
	}
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
