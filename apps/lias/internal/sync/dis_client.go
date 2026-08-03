// Package sync provides the mechanisms for LIAS to consume and mirror
// the device inventory from the Discovery Intelligence Service (DIS).
//
// File:    apps/lias/internal/sync/dis_client.go
// Version: 1.9
package sync

import (
    "bufio"
    "context"
    "encoding/json"
    "fmt"
    "log/slog"
    "net/http"
    "net/url"
    "strings"
    "time"

    "github.com/user/lias-dis/apps/lias/internal/config"
    "github.com/user/lias-dis/shared/api"
    "github.com/user/lias-dis/shared/models"
)

type EventBroadcaster interface {
    Broadcast(event models.Event)
}

type DISClient struct {
    cfg     config.DISConfig
    cache   *Cache
    store   StorageMigrator // NEW: Interface for DB migration
    client  *http.Client
    trigger chan struct{}
    broker  EventBroadcaster
}

// StorageMigrator allows DISClient to migrate tag assignments without importing sqlite directly
type StorageMigrator interface {
    MigrateDeviceTag(oldPDID, newPDID string) error
}

func NewDISClient(cfg config.DISConfig, cache *Cache, trigger chan struct{}, broker EventBroadcaster, store StorageMigrator) *DISClient {
    return &DISClient{
        cfg:     cfg,
        cache:   cache,
        store:   store,
        client:  &http.Client{Timeout: 10 * time.Second},
        trigger: trigger,
        broker:  broker,
    }
}

func (c *DISClient) Run(ctx context.Context) {
    c.pollDevices()
    c.tryTrigger()

    go c.pollerLoop(ctx)
    go c.sseLoop(ctx)
}

func (c *DISClient) tryTrigger() {
    select {
    case c.trigger <- struct{}{}:
    default:
    }
}

func (c *DISClient) pollerLoop(ctx context.Context) {
    interval := c.cfg.SyncInterval
    if interval <= 0 {
        interval = 30 * time.Second
    }

    ticker := time.NewTicker(interval)
    defer ticker.Stop()

    for {
        select {
        case <-ctx.Done():
            return
        case <-ticker.C:
            c.pollDevices()
            c.tryTrigger()
        }
    }
}

func (c *DISClient) getEndpointURL(path string) string {
    rawURL := strings.TrimSpace(c.cfg.URL)
    if !strings.HasPrefix(rawURL, "http://") && !strings.HasPrefix(rawURL, "https://") {
        rawURL = "http://" + rawURL
    }

    u, err := url.Parse(rawURL)
    if err != nil {
        return strings.TrimRight(c.cfg.URL, "/") + path
    }

    if u.Port() == "" {
        u.Host = u.Host + ":8080"
    }

    u.Path = strings.TrimRight(u.Path, "/") + path
    return u.String()
}

func (c *DISClient) pollDevices() {
    targetURL := c.getEndpointURL("/api/v1/devices")
    req, err := http.NewRequest("GET", targetURL, nil)
    if err != nil {
        slog.Error("Failed to create DIS request", "url", targetURL, "error", err)
        return
    }
    if c.cfg.AuthToken != "" {
        req.Header.Set("Authorization", "Bearer "+c.cfg.AuthToken)
    }

    resp, err := c.client.Do(req)
    if err != nil {
        slog.Error("Failed to poll DIS devices", "url", targetURL, "error", err)
        return
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        slog.Error("DIS poll returned non-200 status", "status", resp.StatusCode)
        return
    }

    var listResp api.DeviceListResponse
    if err := json.NewDecoder(resp.Body).Decode(&listResp); err != nil {
        slog.Error("Failed to decode DIS device list", "error", err)
        return
    }

    for _, d := range listResp.Devices {
        prev := c.cache.Get(d.PDID)
        isNewDevice := prev == nil

        c.cache.UpsertDevice(d)

        if isNewDevice {
            slog.Info("Completely new device discovered in LIAS", "pdid", d.PDID, "name", d.DisplayName())
            if c.broker != nil {
                // Broadcast explicit EventDeviceAdded to trigger UI toast notification for brand-new device
                c.broker.Broadcast(models.NewEvent(models.EventDeviceAdded, d.PDID, d))
            }
        } else if c.broker != nil && prev.Online != d.Online {
            evtType := models.EventDeviceOnline
            if !d.Online {
                evtType = models.EventDeviceOffline
            }
            c.broker.Broadcast(models.NewEvent(evtType, d.PDID, models.DeviceEventPayload{
                PDID:      d.PDID,
                MAC:       d.CurrentMAC,
                IP:        d.CurrentIP,
                Timestamp: time.Now(),
            }))
        }
    }
    slog.Info("Synced device inventory from DIS", "count", len(listResp.Devices))
}

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

        slog.Warn("DIS SSE stream disconnected, reconnecting", "error", err, "backoff", backoff)
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

func (c *DISClient) consumeSSE(ctx context.Context) error {
    targetURL := c.getEndpointURL("/api/v1/events")
    req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
    if err != nil {
        return err
    }
    if c.cfg.AuthToken != "" {
        req.Header.Set("Authorization", "Bearer "+c.cfg.AuthToken)
    }
    req.Header.Set("Accept", "text/event-stream")

    sseClient := &http.Client{Timeout: 0}
    resp, err := sseClient.Do(req)
    if err != nil {
        return err
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        return fmt.Errorf("SSE stream endpoint returned status: %d", resp.StatusCode)
    }

    slog.Info("Successfully connected to DIS SSE event stream", "url", targetURL)

    scanner := bufio.NewScanner(resp.Body)
    var event models.Event
    var dataBuf strings.Builder

    for scanner.Scan() {
        line := scanner.Text()

        if line == "" {
            if dataBuf.Len() > 0 {
                event.Payload = json.RawMessage(dataBuf.String())

                if event.DeviceID == "" {
                    var payloadMeta struct {
                        PDID     string `json:"pdid"`
                        DeviceID string `json:"device_id"`
                    }
                    if err := json.Unmarshal(event.Payload, &payloadMeta); err == nil {
                        if payloadMeta.PDID != "" {
                            event.DeviceID = payloadMeta.PDID
                        } else if payloadMeta.DeviceID != "" {
                            event.DeviceID = payloadMeta.DeviceID
                        }
                    }
                }

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
    return fmt.Errorf("SSE stream connection closed by server")
}

func (c *DISClient) handleEvent(e models.Event) {
    if e.DeviceID == "" {
        return
    }

    slog.Debug("Received real-time event from DIS", "type", e.Type, "device_id", e.DeviceID)

    switch e.Type {
    case models.EventDeviceRemoved:
        c.cache.RemoveDevice(e.DeviceID)
        slog.Info("Device removed from local cache via SSE", "pdid", e.DeviceID)
        c.tryTrigger()
        if c.broker != nil {
            c.broker.Broadcast(e)
        }

    case models.EventDeviceReidentified: // GAP-L02
        var payload models.DeviceReidentifiedPayload
        if len(e.Payload) > 0 {
            json.Unmarshal(e.Payload, &payload)
        }

        if payload.OldPDID != "" && payload.NewPDID != "" {
            // Migrate sticky tags from old PDID to new PDID in cache
            c.cache.MigrateDeviceIdentity(payload.OldPDID, payload.NewPDID, payload.MigratedMACs)

            // Migrate tag persistence in storage
            if c.store != nil {
                _ = c.store.MigrateDeviceTag(payload.OldPDID, payload.NewPDID)
            }

            // Fetch the new device record to upsert into cache
            if c.fetchSingleDevice(payload.NewPDID) {
                c.tryTrigger()
            }

            slog.Info("Device reidentified, migrated identity",
                "old_pdid", payload.OldPDID,
                "new_pdid", payload.NewPDID,
                "reason", payload.Reason)

            if c.broker != nil {
                c.broker.Broadcast(e)
            }
        }

    case models.EventDeviceAdded, models.EventDeviceOnline, models.EventDeviceOffline,
        models.EventIPChanged, models.EventMACChanged, models.EventHostnameChanged, models.EventFingerprintUpdated:

        go func(pdid string, evt models.Event) {
            prev := c.cache.Get(pdid)
            isNewDevice := prev == nil || evt.Type == models.EventDeviceAdded

            // Attempt to unmarshal full Device payload directly from event to avoid extra REST call
            var inlineDev models.Device
            if len(evt.Payload) > 0 && json.Unmarshal(evt.Payload, &inlineDev) == nil && inlineDev.PDID == pdid {
                c.cache.UpsertDevice(inlineDev)
                c.tryTrigger()
            } else if c.fetchSingleDevice(pdid) {
                c.tryTrigger()
            }

            if c.broker != nil {
                if isNewDevice {
                    // Ensure event type is explicitly EventDeviceAdded so Web UI displays new device toast
                    evt.Type = models.EventDeviceAdded
                }
                c.broker.Broadcast(evt)
            }
        }(e.DeviceID, e)

    default: // GAP-I02
        slog.Debug("Unhandled DIS event type", "type", e.Type, "device_id", e.DeviceID)
    }
}

func (c *DISClient) fetchSingleDevice(pdid string) bool {
    targetURL := c.getEndpointURL("/api/v1/devices/" + pdid)
    req, err := http.NewRequest("GET", targetURL, nil)
    if err != nil {
        return false
    }
    if c.cfg.AuthToken != "" {
        req.Header.Set("Authorization", "Bearer "+c.cfg.AuthToken)
    }

    resp, err := c.client.Do(req)
    if err != nil {
        slog.Error("Failed to fetch updated device record from DIS", "pdid", pdid, "error", err)
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
