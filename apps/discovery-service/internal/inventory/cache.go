// Package inventory provides the in-memory device store for DIS.
// It handles TTL purging of offline devices and provides thread-safe access.
//
// File:    apps/discovery-service/internal/inventory/cache.go
// Version: 1.0
package inventory

import (
    "log/slog"
    "sync"
    "time"

    "github.com/user/lias-dis/shared/models"
)

const (
    offlineTTL = 24 * time.Hour
)

// Cache is a thread-safe in-memory store for network devices.
// It is keyed by PDID (Persistent Device Identity).
type Cache struct {
    mu      sync.RWMutex
    devices map[string]*models.Device
    stopCh  chan struct{}
}

// NewCache initializes a new device cache and starts the TTL purger goroutine.
func NewCache() *Cache {
    c := &Cache{
        devices: make(map[string]*models.Device),
        stopCh:  make(chan struct{}),
    }
    go c.purgeLoop()
    return c
}

// Get retrieves a device by its PDID. Returns nil if not found.
func (c *Cache) Get(pdid string) *models.Device {
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

// List returns a slice of all devices currently in the cache.
func (c *Cache) List() []models.Device {
    c.mu.RLock()
    defer c.mu.RUnlock()
    
    list := make([]models.Device, 0, len(c.devices))
    for _, d := range c.devices {
        list = append(list, *d)
    }
    return list
}

// Upsert adds or updates a device in the cache.
// It assumes the caller has already performed correlation and generated the PDID.
func (c *Cache) Upsert(d *models.Device) {
    if d == nil || d.PDID == "" {
        return
    }
    c.mu.Lock()
    defer c.mu.Unlock()
    c.devices[d.PDID] = d
}

// Delete removes a device from the cache immediately.
func (c *Cache) Delete(pdid string) {
    c.mu.Lock()
    defer c.mu.Unlock()
    delete(c.devices, pdid)
}

// MarkOffline sets the Online status to false and updates LastSeen.
// The purge loop will eventually remove it if it remains offline.
func (c *Cache) MarkOffline(pdid string) {
    c.mu.Lock()
    defer c.mu.Unlock()
    
    if d, ok := c.devices[pdid]; ok {
        if d.Online {
            d.Online = false
            d.LastSeen = time.Now()
            slog.Info("Device marked offline", "pdid", pdid, "mac", d.CurrentMAC)
        }
    }
}

// Stop terminates the background TTL purger.
func (c *Cache) Stop() {
    close(c.stopCh)
}

// purgeLoop runs every 10 minutes to remove devices that have been offline
// longer than the offlineTTL threshold (24 hours).
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

// purgeOffline scans the cache and deletes expired offline devices.
func (c *Cache) purgeOffline() {
    c.mu.Lock()
    defer c.mu.Unlock()

    now := time.Now()
    for pdid, d := range c.devices {
        if !d.Online && now.Sub(d.LastSeen) > offlineTTL {
            slog.Info("Purging offline device from cache", "pdid", pdid, "mac", d.CurrentMAC)
            delete(c.devices, pdid)
        }
    }
}
