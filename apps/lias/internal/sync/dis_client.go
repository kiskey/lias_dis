// Package sync provides the mechanisms for LIAS to consume and mirror
// the device inventory from the Discovery Intelligence Service (DIS).
//
// File:    apps/lias/internal/sync/dis_client.go
// Version: 1.1
package sync

import (
    "bufio"
    "context"
    "encoding/json"
    "fmt"
    "log/slog"
    "net/http"
    "strings"
    "time"

    "github.com/user/lias-dis/apps/lias/internal/config"
    "github.com/user/lias-dis/shared/api"
    "github.com/user/lias-dis/shared/models"
)

// DISClient manages the REST and SSE connections to the Discovery Intelligence Service.
type DISClient struct {
    cfg     config.DISConfig
    cache   *Cache
    client  *http.Client
    trigger chan struct{} // Trigger channel for immediate nftables resync
}

// NewDISClient initializes the DIS client.
// The trigger channel is used to notify the nftables sync loop of immediate changes.
func NewDISClient(cfg config.DISConfig, cache *Cache, trigger chan struct{}) *DISClient {
    return &DISClient{
        cfg:     cfg,
        cache:   cache,
        client:  &http.Client{Timeout: 10 * time.Second},
        trigger: trigger,
    }
}

// Run starts both the polling fallback and the SSE consumer goroutines.
func (c *DISClient) Run(ctx context.Context) {
    // 1. Initial blocking sync to ensure cache is populated before LIAS activates
    c.pollDevices()
    // Trigger initial firewall population
    c.tryTrigger()

    // 2. Start background poller (fallback)
    go c.pollerLoop(ctx)

    // 3. Start SSE consumer (primary real-time updates)
    go c.sseLoop(ctx)
}

// tryTrigger sends a non-blocking signal to the nftables sync loop.
func (c *DISClient) tryTrigger() {
    select {
    case c.trigger <- struct{}{}:
    default:
    }
}

// pollerLoop periodically fetches the full device list from DIS.
func (c *DISClient) pollerLoop(ctx context.Context) {
    ticker := time.NewTicker(c.cfg.SyncInterval)
    defer ticker.Stop()

    for {
        select {
        case <-ctx.Done():
            return
        case <-ticker.C:
            c.pollDevices()
            c.tryTrigger() // Resync firewall after poll
        }
    }
}

// pollDevices fetches the complete device inventory and updates the local cache.
func (c *DISClient) pollDevices() {
    req, err := http.NewRequest("GET", c.cfg.URL+"/api/v1/devices", nil)
    if err != nil {
        slog.Error("Failed to create DIS request", "error", err)
        return
    }
    if c.cfg.AuthToken != "" {
        req.Header.Set("Authorization", "Bearer "+c.cfg.AuthToken)
    }

    resp, err := c.client.Do(req)
    if err != nil {
        slog.Error("Failed to poll DIS devices", "error", err)
        return
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        slog.Error("DIS poll returned non-200", "status", resp.StatusCode)
        return
    }

    var listResp api.DeviceListResponse
    if err := json.NewDecoder(resp.Body).Decode(&listResp); err != nil {
        slog.Error("Failed to decode DIS device list", "error", err)
        return
    }

    // Upsert all received devices
    for _, d := range listResp.Devices {
        c.cache.UpsertDevice(d)
    }
    slog.Info("Synced devices from DIS", "count", len(listResp.Devices))
}

// sseLoop connects to the SSE endpoint and handles reconnections with
// exponential backoff (max 30s).
func (c *DISClient) sseLoop(ctx context.Context) {
    backoff := 1 * time.Second
    maxBackoff := 30 * time.Second

    for {
        select {
        case <-ctx.Done():
            return
        default:
        }

        err := c.consumeSSE(ctx)
        if err == nil {
            return
        }

        slog.Warn("SSE disconnected, attempting reconnect", "error", err, "backoff", backoff)
        select {
        case <-ctx.Done():
            return
        case <-time.After(backoff):
            backoff *= 2
            if backoff > maxBackoff {
                backoff = maxBackoff
            }
        }
    }
}

// consumeSSE connects to the SSE stream, parses events, and updates the cache.
func (c *DISClient) consumeSSE(ctx context.Context) error {
    req, err := http.NewRequestWithContext(ctx, "GET", c.cfg.URL+"/api/v1/events", nil)
    if err != nil {
        return err
    }
    if c.cfg.AuthToken != "" {
        req.Header.Set("Authorization", "Bearer "+c.cfg.AuthToken)
    }
    req.Header.Set("Accept", "text/event-stream")

    sseClient := &http.Client{}
    resp, err := sseClient.Do(req)
    if err != nil {
        return err
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        return fmt.Errorf("SSE returned non-200 status: %d", resp.StatusCode)
    }

    slog.Info("Connected to DIS SSE stream")

    scanner := bufio.NewScanner(resp.Body)
    var event models.Event
    var dataBuf strings.Builder

    for scanner.Scan() {
        line := scanner.Text()

        if line == "" {
            if dataBuf.Len() > 0 {
                event.Payload = json.RawMessage(dataBuf.String())
                c.handleEvent(event)
                event = models.Event{}
                dataBuf.Reset()
            }
            continue
        }

        if strings.HasPrefix(line, "event: ") {
            event.Type = models.EventType(strings.TrimPrefix(line, "event: "))
        } else if strings.HasPrefix(line, "data: ") {
            dataBuf.WriteString(strings.TrimPrefix(line, "data: "))
        }
    }

    if err := scanner.Err(); err != nil {
        return err
    }
    return fmt.Errorf("SSE stream closed")
}

// handleEvent processes a single SSE event and applies it to the local cache.
func (c *DISClient) handleEvent(e models.Event) {
    if e.DeviceID == "" {
        return
    }

    switch e.Type {
    case models.EventDeviceRemoved:
        c.cache.RemoveDevice(e.DeviceID)
        slog.Info("Removed device from local cache", "pdid", e.DeviceID)
        c.tryTrigger() // Trigger immediate firewall resync

    case models.EventDeviceAdded, models.EventDeviceOnline, models.EventDeviceOffline,
        models.EventIPChanged, models.EventMACChanged, models.EventHostnameChanged, models.EventFingerprintUpdated:
        
        // Fetch the updated single device to sync base data while preserving overlays
        go func(pdid string) {
            if c.fetchSingleDevice(pdid) {
                c.tryTrigger() // Trigger immediate firewall resync on successful update
            }
        }(e.DeviceID)
    }
}

// fetchSingleDevice fetches a specific device from DIS and updates the cache.
// Returns true if the device was successfully fetched and updated.
func (c *DISClient) fetchSingleDevice(pdid string) bool {
    req, err := http.NewRequest("GET", c.cfg.URL+"/api/v1/devices/"+pdid, nil)
    if err != nil {
        return false
    }
    if c.cfg.AuthToken != "" {
        req.Header.Set("Authorization", "Bearer "+c.cfg.AuthToken)
    }

    resp, err := c.client.Do(req)
    if err != nil {
        slog.Error("Failed to fetch single device from DIS", "pdid", pdid, "error", err)
        return false
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        return false
    }

    var d models.Device
    if err := json.NewDecoder(resp.Body).Decode(&d); err != nil {
        return false
    }

    c.cache.UpsertDevice(d)
    return true
}
