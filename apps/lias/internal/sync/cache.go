// Package sync provides the mechanisms for LIAS to consume and mirror
// the device inventory from the Discovery Intelligence Service (DIS).
//
// File:    apps/lias/internal/sync/cache.go
// Version: 2.3 (Added PatchDeviceOnline for instant SSE updates)
package sync

import (
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
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
	mu              sync.RWMutex // CPU-03 Fix: Use RWMutex
	devices         map[string]*LocalDevice
	stickyTags      map[string][]string
	stickyMACs      map[string][]string
	overrides       map[string]string
	userAssignments map[string]string
	revision        atomic.Uint64
}

func NewCache() *Cache {
	cache := &Cache{
		devices:         make(map[string]*LocalDevice),
		stickyTags:      make(map[string][]string),
		stickyMACs:      make(map[string][]string),
		overrides:       make(map[string]string),
		userAssignments: make(map[string]string),
	}
	cache.revision.Store(1)
	return cache
}

func (c *Cache) Revision() uint64 { return c.revision.Load() }
func (c *Cache) BumpRevision()    { c.revision.Add(1) }

func (c *Cache) LoadLocalMetadata(overrides, assignments map[string]string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for pdid, name := range overrides {
		c.overrides[pdid] = name
	}
	for pdid, userID := range assignments {
		c.userAssignments[pdid] = userID
	}
	for _, device := range c.devices {
		c.applyLocalMetadataLocked(device)
	}
	c.revision.Add(1)
}

func (c *Cache) applyLocalMetadataLocked(device *LocalDevice) {
	if name, exists := c.overrides[device.PDID]; exists {
		device.FriendlyName = name
	}
	if userID, exists := c.userAssignments[device.PDID]; exists {
		device.UserID = userID
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
	c.revision.Add(1)
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
	if value, exists := c.overrides[oldPDID]; exists {
		if _, targetExists := c.overrides[newPDID]; !targetExists {
			c.overrides[newPDID] = value
		}
		delete(c.overrides, oldPDID)
	}
	if value, exists := c.userAssignments[oldPDID]; exists {
		if _, targetExists := c.userAssignments[newPDID]; !targetExists {
			c.userAssignments[newPDID] = value
		}
		delete(c.userAssignments, oldPDID)
	}
	c.revision.Add(1)
}

// ReconcileIdentityMigration applies the committed LIAS state to the live
// cache in one critical section. The surviving target record remains the DIS
// record; only LIAS-owned fields are overlaid.
func (c *Cache) ReconcileIdentityMigration(oldPDID, newPDID string, migratedMACs, tags []string, friendlyName, userID string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	cleanTags := dedupeStrings(tags)
	if len(cleanTags) > 0 {
		c.stickyTags[newPDID] = cleanTags
	}
	delete(c.stickyTags, oldPDID)
	delete(c.overrides, oldPDID)
	delete(c.userAssignments, oldPDID)
	if friendlyName != "" {
		c.overrides[newPDID] = friendlyName
	}
	if userID != "" {
		c.userAssignments[newPDID] = userID
	}
	for _, mac := range migratedMACs {
		cleanMAC := strings.ToLower(strings.TrimSpace(mac))
		if cleanMAC != "" && len(cleanTags) > 0 {
			c.stickyMACs[cleanMAC] = cleanTags
		}
	}
	if target := c.devices[newPDID]; target != nil {
		if len(cleanTags) > 0 {
			target.Tags = append([]string(nil), cleanTags...)
			target.Device.Tags = append([]string(nil), cleanTags...)
		}
		if friendlyName != "" {
			target.FriendlyName = friendlyName
		}
		if userID != "" {
			target.UserID = userID
		}
	}
	delete(c.devices, oldPDID)
	c.revision.Add(1)
}

func dedupeStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
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
		before := existing.Device.Clone()
		beforeTags := append([]string(nil), existing.Tags...)
		pol := existing.Policy
		nextChange := existing.NextStateChange

		existing.Device = d
		existing.Policy = pol
		existing.NextStateChange = nextChange
		c.applyStickyTagLocked(existing)
		c.applyLocalMetadataLocked(existing)
		if !reflect.DeepEqual(before, &existing.Device) || !reflect.DeepEqual(beforeTags, existing.Tags) {
			c.revision.Add(1)
		}
	} else {
		ld := &LocalDevice{
			Device: d,
		}
		c.applyStickyTagLocked(ld)
		c.applyLocalMetadataLocked(ld)
		c.devices[d.PDID] = ld
		c.revision.Add(1)
	}
}

func (c *Cache) RemoveDevice(pdid string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, exists := c.devices[pdid]; exists {
		delete(c.devices, pdid)
		c.revision.Add(1)
	}
}

func (c *Cache) SetPolicy(pdid string, p *models.Policy) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if d, ok := c.devices[pdid]; ok {
		d.Policy = p
		c.revision.Add(1)
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
	c.revision.Add(1)
}

func (c *Cache) SetFriendlyName(pdid, name string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.overrides[pdid] = name
	if device := c.devices[pdid]; device != nil {
		device.FriendlyName = name
	}
	c.revision.Add(1)
}

func (c *Cache) SetUserID(pdid, userID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if userID == "" {
		delete(c.userAssignments, pdid)
	} else {
		c.userAssignments[pdid] = userID
	}
	if device := c.devices[pdid]; device != nil {
		device.UserID = userID
	}
	c.revision.Add(1)
}

func (c *Cache) SetNextStateChange(pdid string, t *time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if d, ok := c.devices[pdid]; ok {
		d.NextStateChange = t
		c.revision.Add(1)
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
			c.revision.Add(1)
		}
	}
}
