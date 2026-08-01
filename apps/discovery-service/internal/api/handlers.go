// Package api implements the HTTP server, middleware, and SSE broker for DIS.
//
// File:    apps/discovery-service/internal/api/handlers.go
// Version: 1.1
package api

import (
    "context"
    "crypto/rand"
    "encoding/hex"
    "encoding/json"
    "log/slog"
    "net/http"
    "time"

    "github.com/user/lias-dis/apps/discovery-service/internal/discovery"
    "github.com/user/lias-dis/apps/discovery-service/internal/inventory"
    "github.com/user/lias-dis/shared/api"
    "github.com/user/lias-dis/shared/models"
)

// Handlers contains the HTTP handlers for the DIS REST API.
type Handlers struct {
    cache     *inventory.Cache
    broker    *Broker
    enrichers []discovery.Enricher
}

// NewHandlers creates a new Handlers instance.
func NewHandlers(cache *inventory.Cache, broker *Broker, enrichers []discovery.Enricher) *Handlers {
    return &Handlers{
        cache:     cache,
        broker:    broker,
        enrichers: enrichers,
    }
}

// RegisterRoutes wires the handlers to the HTTP mux using Go 1.22+ routing.
func (h *Handlers) RegisterRoutes(mux *http.ServeMux) {
    mux.HandleFunc("GET /api/v1/devices", h.ListDevices)
    mux.HandleFunc("GET /api/v1/devices/{pdid}", h.GetDevice)
    mux.HandleFunc("POST /api/v1/devices/{pdid}/refresh", h.RefreshDevice)
    mux.HandleFunc("GET /api/v1/events", h.StreamEvents)
}

// ListDevices returns all known devices.
func (h *Handlers) ListDevices(w http.ResponseWriter, r *http.Request) {
    devs := h.cache.List()
    w.Header().Set("Content-Type", "application/json")
    _ = json.NewEncoder(w).Encode(api.DeviceListResponse{
        Devices: devs,
        Total:   len(devs),
    })
}

// GetDevice returns a single device by PDID.
func (h *Handlers) GetDevice(w http.ResponseWriter, r *http.Request) {
    pdid := r.PathValue("pdid")
    d := h.cache.Get(pdid)
    if d == nil {
        http.Error(w, `{"error":"device not found"}`, http.StatusNotFound)
        return
    }
    w.Header().Set("Content-Type", "application/json")
    _ = json.NewEncoder(w).Encode(d)
}

// RefreshDevice triggers an on-demand enrichment for a device.
// It executes all configured enrichers asynchronously and updates the cache.
func (h *Handlers) RefreshDevice(w http.ResponseWriter, r *http.Request) {
    pdid := r.PathValue("pdid")
    d := h.cache.Get(pdid)
    if d == nil {
        http.Error(w, `{"error":"device not found"}`, http.StatusNotFound)
        return
    }

    // Execute enrichers asynchronously to not block the HTTP request
    go func(dev *models.Device) {
        for _, e := range h.enrichers {
            enr, err := e.Enrich(context.Background(), dev)
            if err != nil {
                slog.Debug("Enricher failed", "enricher", e.Name(), "error", err)
                continue
            }
            if enr != nil {
                changed := false
                // Apply enrichment fields if they are provided and confidence hierarchy allows
                if enr.Hostname != "" && dev.Hostname != enr.Hostname {
                    dev.Hostname = enr.Hostname
                    changed = true
                }
                if enr.FriendlyName != "" && dev.FriendlyName != enr.FriendlyName {
                    dev.FriendlyName = enr.FriendlyName
                    changed = true
                }
                if enr.Manufacturer != "" && dev.Manufacturer != enr.Manufacturer {
                    dev.Manufacturer = enr.Manufacturer
                    changed = true
                }
                if enr.Vendor != "" && dev.Vendor != enr.Vendor {
                    dev.Vendor = enr.Vendor
                    changed = true
                }
                if enr.Model != "" && dev.Model != enr.Model {
                    dev.Model = enr.Model
                    changed = true
                }
                if enr.DeviceType != "" && dev.DeviceType != enr.DeviceType {
                    dev.DeviceType = enr.DeviceType
                    changed = true
                }
                for _, svc := range enr.Services {
                    dev.AddService(svc)
                    changed = true
                }
                
                if changed {
                    dev.Touch(time.Now())
                    h.cache.Upsert(dev)
                    h.broker.Broadcast(models.NewEvent(models.EventFingerprintUpdated, dev.PDID, dev))
                }
            }
        }
    }(d)

    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(http.StatusAccepted)
    _ = json.NewEncoder(w).Encode(api.AcceptedResponse{
        Message: "Refresh triggered",
        TaskID:  generateID(),
    })
}

// StreamEvents handles the SSE connection for real-time event streaming.
func (h *Handlers) StreamEvents(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "text/event-stream")
    w.Header().Set("Cache-Control", "no-cache")
    w.Header().Set("Connection", "keep-alive")

    flusher, ok := w.(http.Flusher)
    if !ok {
        http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
        return
    }

    clientID := generateID()
    client := h.broker.Subscribe(clientID)
    defer h.broker.Unsubscribe(clientID)

    notify := r.Context().Done()
    for {
        select {
        case <-notify:
            return
        case event, ok := <-client.Events:
            if !ok {
                return
            }
            _, _ = w.Write([]byte(event.SSEFrame()))
            flusher.Flush()
        }
    }
}

// generateID creates a random hex string for client/task identification.
func generateID() string {
    b := make([]byte, 8)
    _, _ = rand.Read(b)
    return hex.EncodeToString(b)
}
