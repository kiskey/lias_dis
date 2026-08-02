// Package inventory provides the in-memory device store for DIS.
//
// File:    apps/discovery-service/internal/inventory/cache.go
// Version: 1.3
package inventory

import (
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/user/lias-dis/shared/models"
)

const (
	offlineTTL = 24 * time.Hour
)

// Cache is a thread-safe in-memory store with O(1) MAC and IP index lookups.
type Cache struct {
	mu       sync.RWMutex
	devices  map[string]*models.Device // Keyed by PDID
	macIndex map[string]*models.Device // Keyed by normalized MAC
	ipIndex  map[string]*models.Device // Keyed by IP string
	stopCh   chan struct{}
}

// NewCache initializes a new device cache and starts the TTL purger.
func NewCache() *Cache {
	c := &Cache{
		devices:  make(map[string]*models.Device),
		macIndex: make(map[string]*models.Device),
		ipIndex:  make(map[string]*models.Device),
		stopCh:   make(chan struct{}),
	}
	go c.purgeLoop()
	return c
}

// GetByMACOrIP performs an O(1) indexed lookup without copying the full device inventory.
func (c *Cache) GetByMACOrIP(macStr, ipStr string) *models.Device {
	c.mu.RLock()
	defer c.mu.RUnlock()

	cleanMAC := NormalizeMAC(macStr)
	if cleanMAC != "" {
		if d, found := c.macIndex[cleanMAC]; found {
			devCopy := *d
			return &devCopy
		}
	}

	cleanIP := strings.TrimSpace(ipStr)
	if cleanIP != "" {
		if d, found := c.ipIndex[cleanIP]; found {
			devCopy := *d
			return &devCopy
		}
	}

	return nil
}

// Get retrieves a device by PDID. Returns nil if not found.
func (c *Cache) Get(pdid string) *models.Device {
	c.mu.RLock()
	defer c.mu.RUnlock()

	d, ok := c.devices[pdid]
	if !ok {
		return nil
	}
	devCopy := *d
	return &devCopy
}

// List returns a slice containing copies of all cached devices.
func (c *Cache) List() []models.Device {
	c.mu.RLock()
	defer c.mu.RUnlock()

	list := make([]models.Device, 0, len(c.devices))
	for _, d := range c.devices {
		list = append(list, *d)
	}
	return list
}

// Upsert adds or updates a device record and refreshes secondary MAC and IP indices.
func (c *Cache) Upsert(d *models.Device) {
	if d == nil || d.PDID == "" {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// Store copy
	devCopy := *d
	c.devices[d.PDID] = &devCopy

	// Update secondary indices
	for _, mac := range d.MACs {
		cleanMAC := NormalizeMAC(mac)
		if cleanMAC != "" {
			c.macIndex[cleanMAC] = &devCopy
		}
	}

	for _, ip := range d.IPs {
		cleanIP := strings.TrimSpace(ip)
		if cleanIP != "" {
			c.ipIndex[cleanIP] = &devCopy
		}
	}
}

// Delete removes a device and clears its associated index entries.
func (c *Cache) Delete(pdid string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if d, ok := c.devices[pdid]; ok {
		for _, mac := range d.MACs {
			delete(c.macIndex, NormalizeMAC(mac))
		}
		for _, ip := range d.IPs {
			delete(c.ipIndex, strings.TrimSpace(ip))
		}
		delete(c.devices, pdid)
	}
}

// Stop terminates the background TTL purger.
func (c *Cache) Stop() {
	close(c.stopCh)
}

func (c *Cache) purgeLoop() {
	ticker := time.NewTicker(10 * time.Minute)
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
	defer c.mu.Unlock()

	now := time.Now()
	for pdid, d := range c.devices {
		if !d.Online && now.Sub(d.LastSeen) > offlineTTL {
			slog.Info("Purging offline device from cache", "pdid", pdid, "mac", d.CurrentMAC)
			for _, mac := range d.MACs {
				delete(c.macIndex, NormalizeMAC(mac))
			}
			for _, ip := range d.IPs {
				delete(c.ipIndex, strings.TrimSpace(ip))
			}
			delete(c.devices, pdid)
		}
	}
}
