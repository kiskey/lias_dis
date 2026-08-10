// Package sync provides the mechanisms for LIAS to consume and mirror
// the device inventory from the Discovery Intelligence Service (DIS).
//
// File:    apps/lias/internal/sync/dis_client.go
// Version: 2.5 (Fixed SSE Online Status Race Condition)
package sync

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/user/lias-dis/apps/lias/internal/config"
	"github.com/user/lias-dis/shared/api"
	"github.com/user/lias-dis/shared/models"
)

const maxSSEEventBytes = 1 << 20

type EventBroadcaster interface {
	Broadcast(event models.Event)
	// CPU-05 Fix: Added method to signal backoff reset
	SignalSSEConnected()
}

type IdentityMigrator interface {
	MigrateIdentity(oldPDID, newPDID string, migratedMACs []string) (MigrationResult, error)
}

type MigrationResult struct {
	Conflicts int
	Replayed  bool
}

type DISClient struct {
	cfg             config.DISConfig
	cache           *Cache
	migrator        IdentityMigrator
	client          *http.Client
	trigger         chan struct{}
	broker          EventBroadcaster
	lastSeenInDIS   map[string]time.Time
	redirectChecked map[string]bool
	lastEventID     int64
	stateMu         sync.RWMutex
	disCapabilities *api.CapabilitiesResponse
	upstream        api.UpstreamState
}

func NewDISClient(cfg config.DISConfig, cache *Cache, trigger chan struct{}, broker EventBroadcaster, migrator IdentityMigrator) *DISClient {
	return &DISClient{
		cfg:             cfg,
		cache:           cache,
		migrator:        migrator,
		client:          &http.Client{Timeout: 10 * time.Second},
		trigger:         trigger,
		broker:          broker,
		lastSeenInDIS:   make(map[string]time.Time),
		redirectChecked: make(map[string]bool),
	}
}

func (c *DISClient) Run(ctx context.Context) {
	c.refreshCapabilities(ctx)
	c.pollDevices()
	c.tryTrigger()

	go c.pollerLoop(ctx)
	go c.sseLoop(ctx)
	go c.capabilityLoop(ctx)
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

	escapedPath := strings.TrimRight(u.EscapedPath(), "/") + path
	if decodedPath, decodeErr := url.PathUnescape(escapedPath); decodeErr == nil {
		u.Path = decodedPath
		u.RawPath = escapedPath
	} else {
		u.Path = strings.TrimRight(u.Path, "/") + path
	}
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
		c.recordUpstreamError(err)
		slog.Error("Failed to poll DIS devices", "url", targetURL, "error", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		c.recordUpstreamError(fmt.Errorf("device inventory status %d", resp.StatusCode))
		slog.Error("DIS poll returned non-200 status", "status", resp.StatusCode)
		return
	}

	var listResp api.DeviceListResponse
	if err := json.NewDecoder(resp.Body).Decode(&listResp); err != nil {
		c.recordUpstreamError(err)
		slog.Error("Failed to decode DIS device list", "error", err)
		return
	}

	activePDIDs := make(map[string]bool)
	c.stateMu.Lock()
	for _, d := range listResp.Devices {
		activePDIDs[d.PDID] = true
		c.lastSeenInDIS[d.PDID] = time.Now()
		delete(c.redirectChecked, d.PDID)
	}
	c.stateMu.Unlock()

	cachedPDIDs := c.cache.ListPDIDs()
	for _, pdid := range cachedPDIDs {
		if !activePDIDs[pdid] {
			c.stateMu.RLock()
			lastSeen, seen := c.lastSeenInDIS[pdid]
			checked := c.redirectChecked[pdid]
			c.stateMu.RUnlock()
			if !checked {
				c.stateMu.Lock()
				c.redirectChecked[pdid] = true
				c.stateMu.Unlock()
				if resolved, ok := c.fetchDeviceRecord(pdid); ok && resolved.PDID != "" && resolved.PDID != pdid {
					if c.reconcileMissedRedirect(pdid, resolved) {
						continue
					}
					c.stateMu.Lock()
					delete(c.redirectChecked, pdid)
					c.stateMu.Unlock()
				}
			}
			if seen {
				if time.Since(lastSeen) < 5*time.Minute {
					slog.Debug("Device in grace period, keeping in cache", "pdid", pdid)
					continue
				}
			}
			c.cache.RemoveDevice(pdid)
			c.stateMu.Lock()
			delete(c.lastSeenInDIS, pdid)
			delete(c.redirectChecked, pdid)
			c.stateMu.Unlock()
			slog.Info("Removed stale device from LIAS cache (grace period expired)", "pdid", pdid)
		}
	}

	for _, d := range listResp.Devices {
		prev := c.cache.Get(d.PDID)
		isNewDevice := prev == nil

		c.cache.UpsertDevice(d)

		if isNewDevice {
			slog.Info("Completely new device discovered in LIAS", "pdid", d.PDID, "name", d.DisplayName())
			if c.broker != nil {
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
	c.stateMu.Lock()
	c.upstream.Reachable = true
	c.upstream.LastSuccessfulSync = time.Now()
	c.upstream.LastError = ""
	c.stateMu.Unlock()
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
	c.stateMu.RLock()
	lastEventID := c.lastEventID
	c.stateMu.RUnlock()
	if lastEventID == 0 {
		// Request events emitted during DIS startup (including one-time identity
		// repair) even when LIAS itself has just restarted.
		lastEventID = 1
	}
	req.Header.Set("Last-Event-ID", fmt.Sprintf("%d", lastEventID))

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
	c.refreshCapabilities(ctx)

	// CPU-05 Fix: Signal successful connection to reset backoff
	if c.broker != nil {
		c.broker.SignalSSEConnected()
	}

	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 4<<10), maxSSEEventBytes)
	var event models.Event
	var dataBuf strings.Builder

	for scanner.Scan() {
		line := scanner.Text()

		if line == "" {
			if dataBuf.Len() > 0 {
				event.Payload = json.RawMessage(dataBuf.String())
				event.SetTargetPDID(resolveEventPDID(event.Type, event.Payload))

				c.handleEvent(event)

				event = models.Event{}
				dataBuf.Reset()
			}
			continue
		}

		if strings.HasPrefix(line, "event: ") {
			event.Type = models.EventType(strings.TrimPrefix(line, "event: "))
		} else if strings.HasPrefix(line, "id: ") {
			if parsed, parseErr := strconv.ParseInt(strings.TrimSpace(strings.TrimPrefix(line, "id: ")), 10, 64); parseErr == nil {
				c.stateMu.Lock()
				if parsed > c.lastEventID {
					c.lastEventID = parsed
				}
				c.stateMu.Unlock()
			}
		} else if strings.HasPrefix(line, "data: ") {
			data := strings.TrimPrefix(line, "data: ")
			separatorBytes := 0
			if dataBuf.Len() > 0 {
				separatorBytes = 1
			}
			if dataBuf.Len()+separatorBytes+len(data) > maxSSEEventBytes {
				return fmt.Errorf("SSE event exceeds %d-byte limit", maxSSEEventBytes)
			}
			if separatorBytes != 0 {
				dataBuf.WriteByte('\n')
			}
			dataBuf.WriteString(data)
		}
	}

	if err := scanner.Err(); err != nil {
		return err
	}
	return fmt.Errorf("SSE stream connection closed by server")
}

func resolveEventPDID(eventType models.EventType, payload json.RawMessage) string {
	if len(payload) == 0 {
		return ""
	}
	var metadata struct {
		PDID     string `json:"pdid"`
		DeviceID string `json:"device_id"`
		NewPDID  string `json:"new_pdid"`
	}
	if err := json.Unmarshal(payload, &metadata); err != nil {
		return ""
	}
	if metadata.PDID != "" {
		return metadata.PDID
	}
	if eventType == models.EventDeviceReidentified && metadata.NewPDID != "" {
		return metadata.NewPDID
	}
	return metadata.DeviceID
}

func (c *DISClient) handleEvent(e models.Event) {
	c.stateMu.Lock()
	c.upstream.Reachable = true
	c.upstream.LastSSEEvent = time.Now()
	c.upstream.LastError = ""
	c.stateMu.Unlock()
	pdid := e.TargetPDID()
	if pdid != "" {
		e.SetTargetPDID(pdid)
	}

	slog.Debug("Received real-time event from DIS", "type", e.Type, "pdid", pdid)

	switch e.Type {
	case models.EventDeviceRemoved:
		if pdid == "" {
			slog.Warn("Ignoring device removal event without PDID")
			return
		}
		c.cache.RemoveDevice(pdid)
		c.stateMu.Lock()
		delete(c.lastSeenInDIS, pdid)
		delete(c.redirectChecked, pdid)
		c.stateMu.Unlock()
		slog.Info("Device removed from local cache via SSE", "pdid", pdid)
		c.tryTrigger()
		if c.broker != nil {
			c.broker.Broadcast(e)
		}

	case models.EventDeviceReidentified:
		var payload models.DeviceReidentifiedPayload
		if len(e.Payload) > 0 {
			json.Unmarshal(e.Payload, &payload)
		}

		if payload.OldPDID != "" && payload.NewPDID != "" {
			e.SetTargetPDID(payload.NewPDID)
			if c.migrator != nil {
				migration, err := c.migrator.MigrateIdentity(payload.OldPDID, payload.NewPDID, payload.MigratedMACs)
				if err != nil {
					slog.Error("Failed to migrate LIAS identity state; event will be retried safely", "old_pdid", payload.OldPDID, "new_pdid", payload.NewPDID, "error", err)
					return
				}
				slog.Info("Reconciled LIAS identity state", "old_pdid", payload.OldPDID, "new_pdid", payload.NewPDID,
					"conflicts", migration.Conflicts, "replayed", migration.Replayed)
			} else {
				c.cache.MigrateDeviceIdentity(payload.OldPDID, payload.NewPDID, payload.MigratedMACs)
			}

			if c.fetchSingleDevice(payload.NewPDID) {
				c.tryTrigger()
			}

			slog.Info("Device reidentified, migrated identity and policies",
				"old_pdid", payload.OldPDID,
				"new_pdid", payload.NewPDID,
				"reason", payload.Reason)

			if c.broker != nil {
				c.broker.Broadcast(e)
			}
		}

	// P1-FIX: Handle events that carry the FULL Device struct inline.
	case models.EventDeviceAdded, models.EventFingerprintUpdated:
		if pdid == "" {
			slog.Warn("Ignoring device record event without PDID", "type", e.Type)
			return
		}
		go func(pdid string, evt models.Event) {
			prev := c.cache.Get(pdid)
			isNewDevice := prev == nil || evt.Type == models.EventDeviceAdded

			var inlineDev models.Device
			// FIX: Validate that the unmarshalled struct is actually a full Device
			// (must have a MAC) before upserting. This prevents partial payloads
			// from corrupting the LIAS cache.
			if len(evt.Payload) > 0 && json.Unmarshal(evt.Payload, &inlineDev) == nil && inlineDev.PDID == pdid && inlineDev.CurrentMAC != "" {
				c.cache.UpsertDevice(inlineDev)
				c.tryTrigger()
			} else if c.fetchSingleDevice(pdid) {
				c.tryTrigger()
			}

			if c.broker != nil {
				if isNewDevice {
					evt.Type = models.EventDeviceAdded
				}
				c.broker.Broadcast(evt)
			}
		}(pdid, e)

	// V2.5 FIX: Handle Online/Offline events IMMEDIATELY without waiting for REST fetch
	case models.EventDeviceOnline, models.EventDeviceOffline:
		if pdid == "" {
			slog.Warn("Ignoring presence event without PDID", "type", e.Type)
			return
		}
		go func(pdid string, evt models.Event) {
			// 1. Immediately patch local cache for instant UI feedback and firewall sync
			onlineStatus := evt.Type == models.EventDeviceOnline
			c.cache.PatchDeviceOnline(pdid, onlineStatus)
			c.tryTrigger()

			// 2. Broadcast to frontend immediately
			if c.broker != nil {
				c.broker.Broadcast(evt)
			}

			// 3. Background fetch to sync any remaining changed fields (IP, MAC, etc.)
			c.fetchSingleDevice(pdid)
		}(pdid, e)

	// Handle partial payload events that require full struct fetch
	case models.EventIPChanged, models.EventMACChanged, models.EventHostnameChanged:
		if pdid == "" {
			slog.Warn("Ignoring partial device event without PDID", "type", e.Type)
			return
		}
		go func(pdid string, evt models.Event) {
			if c.fetchSingleDevice(pdid) {
				c.tryTrigger()
			}
			if c.broker != nil {
				c.broker.Broadcast(evt)
			}
		}(pdid, e)

	default:
		// Unknown and global events are safe to relay to clients. They never
		// trigger policy evaluation, cache mutation, storage, or network I/O.
		if c.broker != nil {
			c.broker.Broadcast(e)
		}
		slog.Debug("Relayed non-enforcement DIS event", "type", e.Type, "pdid", pdid)
	}
}

func (c *DISClient) fetchSingleDevice(pdid string) bool {
	d, ok := c.fetchDeviceRecord(pdid)
	if !ok {
		return false
	}
	c.cache.UpsertDevice(d)
	return true
}

func (c *DISClient) fetchDeviceRecord(pdid string) (models.Device, bool) {
	targetURL := c.getEndpointURL("/api/v1/devices/" + pdid)
	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return models.Device{}, false
	}
	if c.cfg.AuthToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.cfg.AuthToken)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		slog.Error("Failed to fetch updated device record from DIS", "pdid", pdid, "error", err)
		return models.Device{}, false
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return models.Device{}, false
	}

	var d models.Device
	if err := json.NewDecoder(resp.Body).Decode(&d); err != nil {
		return models.Device{}, false
	}
	return d, true
}

func (c *DISClient) reconcileMissedRedirect(oldPDID string, resolved models.Device) bool {
	old := c.cache.Get(oldPDID)
	if old == nil {
		return false
	}
	migratedMACs := append([]string(nil), old.Device.MACs...)
	if len(migratedMACs) == 0 && old.Device.CurrentMAC != "" {
		migratedMACs = []string{old.Device.CurrentMAC}
	}
	if c.migrator != nil {
		if _, err := c.migrator.MigrateIdentity(oldPDID, resolved.PDID, migratedMACs); err != nil {
			slog.Error("Failed to reconcile missed DIS identity redirect", "old_pdid", oldPDID,
				"new_pdid", resolved.PDID, "error", err)
			return false
		}
	} else {
		c.cache.MigrateDeviceIdentity(oldPDID, resolved.PDID, migratedMACs)
	}
	c.cache.UpsertDevice(resolved)
	c.cache.RemoveDevice(oldPDID)
	c.stateMu.Lock()
	delete(c.lastSeenInDIS, oldPDID)
	delete(c.redirectChecked, oldPDID)
	c.stateMu.Unlock()
	c.tryTrigger()
	if c.broker != nil {
		c.broker.Broadcast(models.NewEvent(models.EventDeviceReidentified, resolved.PDID, models.DeviceReidentifiedPayload{
			PDID: resolved.PDID, OldPDID: oldPDID, NewPDID: resolved.PDID,
			Reason: "missed_dis_redirect", MigratedMACs: migratedMACs, Timestamp: time.Now(),
		}))
	}
	return true
}
