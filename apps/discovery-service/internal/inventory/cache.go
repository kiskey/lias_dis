// Package inventory provides the in-memory device store for DIS.
//
// File:    apps/discovery-service/internal/inventory/cache.go
// Version: 1.7 (Updated staleThreshold to 3 minutes for offline hysteresis)
package inventory

import (
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/user/lias-dis/shared/models"
)

const (
	offlineTTL     = 24 * time.Hour
	staleThreshold = 180 * time.Second // 3 Minutes hysteresis threshold
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

// DemoteStale flips Online: true -> false for devices with no observation
// within staleThreshold (3 minutes), serving as a deterministic threshold
// for marking devices offline without transient flapping.
// Returns the slice of PDIDs that transitioned offline.
func (c *Cache) DemoteStale() []string {
	c.mu.Lock()
	defer c.mu.Unlock()

	var changed []string
	now := time.Now()
	for pdid, d := range c.devices {
		if d.Online && now.Sub(d.LastSeen) > staleThreshold {
			d.Online = false
			changed = append(changed, pdid)
		}
	}
	return changed
}

// GetByMAC performs an O(1) indexed lookup by MAC address.
func (c *Cache) GetByMAC(macStr string) *models.Device {
	c.mu.RLock()
	defer c.mu.RUnlock()

	cleanMAC := NormalizeMAC(macStr)
	if cleanMAC != "" {
		if d, found := c.macIndex[cleanMAC]; found {
			devCopy := *d
			return &devCopy
		}
	}
	return nil
}

// GetByIP performs an O(1) indexed lookup by IP string.
func (c *Cache) GetByIP(ipStr string) *models.Device {
	c.mu.RLock()
	defer c.mu.RUnlock()

	cleanIP := strings.TrimSpace(ipStr)
	if cleanIP != "" {
		if d, found := c.ipIndex[cleanIP]; found {
			devCopy := *d
			return &devCopy
		}
	}
	return nil
}

// GetByHostname searches for an existing cached device record matching a clean, normalized hostname.
func (c *Cache) GetByHostname(hostname string) *models.Device {
	cleanHost := strings.ToLower(strings.TrimSpace(hostname))
	if cleanHost == "" {
		return nil
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	for _, d := range c.devices {
		if strings.ToLower(strings.TrimSpace(d.Hostname)) == cleanHost {
			devCopy := *d
			return &devCopy
		}
	}
	return nil
}

// RemoveIPIndex removes a stale IP index mapping when DHCP reassigns an IP to another MAC.
func (c *Cache) RemoveIPIndex(ipStr string) {
	cleanIP := strings.TrimSpace(ipStr)
	if cleanIP == "" {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if d, found := c.ipIndex[cleanIP]; found {
		newIPs := make([]string, 0, len(d.IPs))
		for _, ip := range d.IPs {
			if ip != cleanIP {
				newIPs = append(newIPs, ip)
			}
		}
		d.IPs = newIPs
		if d.CurrentIP == cleanIP {
			d.CurrentIP = ""
			if len(d.IPs) > 0 {
				d.CurrentIP = d.IPs[len(d.IPs)-1]
			}
		}
		delete(c.ipIndex, cleanIP)
		slog.Info("Invalidated stale IP index mapping due to DHCP IP reassignment", "ip", cleanIP, "pdid", d.PDID)
	}
}

// GetByMACOrIP performs an indexed lookup checking MAC first, falling back to IP.
func (c *Cache) GetByMACOrIP(macStr, ipStr string) *models.Device {
	if d := c.GetByMAC(macStr); d != nil {
		return d
	}
	return c.GetByIP(ipStr)
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

	devCopy := *d
	c.devices[d.PDID] = &devCopy

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
	ticker := time.NewTicker(20 * time.Second)
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
