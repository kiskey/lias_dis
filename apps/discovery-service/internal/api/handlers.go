// Package api implements the HTTP server, middleware, and SSE broker for DIS.
//
// File:    apps/discovery-service/internal/api/handlers.go
// Version: 1.4
package api

import (
    "crypto/rand"
    "encoding/hex"
    "encoding/json"
    "log/slog"
    "net/http"
    "strconv"
    "strings"

    "github.com/user/lias-dis/apps/discovery-service/internal/inventory"
    "github.com/user/lias-dis/shared/api"
    "github.com/user/lias-dis/shared/models"
)

// EnrichmentTrigger defines the interface for triggering on-demand enrichment.
type EnrichmentTrigger interface {
    TriggerEnrichment(pdid string, force bool)
}

// Handlers contains the HTTP handlers for the DIS REST API.
type Handlers struct {
    cache  *inventory.Cache
    broker *Broker
    orch   EnrichmentTrigger
}

// NewHandlers creates a new Handlers instance.
func NewHandlers(cache *inventory.Cache, broker *Broker, orch EnrichmentTrigger) *Handlers {
    return &Handlers{
        cache:  cache,
        broker: broker,
        orch:   orch,
    }
}

// RegisterRoutes wires the handlers to the HTTP mux using Go 1.22+ routing patterns.
// It accepts an authToken to apply Bearer authentication middleware across all routes.
func (h *Handlers) RegisterRoutes(mux *http.ServeMux, authToken string) {
    handler := http.NewServeMux()

    handler.HandleFunc("GET /api/v1/devices", h.ListDevices)
    handler.HandleFunc("GET /api/v1/devices/{pdid}", h.GetDevice)
    handler.HandleFunc("POST /api/v1/devices/{pdid}/refresh", h.RefreshDevice)
    handler.HandleFunc("GET /api/v1/events", h.StreamEvents)

    // Wrap the internal handler with the Auth middleware
    mux.Handle("/", AuthMiddleware(authToken, handler))
}

// ListDevices returns all known devices, supporting query parameters `?online=true` and `?type=phone`.
func (h *Handlers) ListDevices(w http.ResponseWriter, r *http.Request) {
    allDevs := h.cache.List()

    filterOnline := r.URL.Query().Get("online")
    filterType := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("type")))

    filtered := make([]models.Device, 0, len(allDevs))

    for _, d := range allDevs {
        if filterOnline != "" {
            wantOnline := filterOnline == "true" || filterOnline == "1"
            if d.Online != wantOnline {
                continue
            }
        }

        if filterType != "" && strings.ToLower(d.DeviceType) != filterType {
            continue
        }

        filtered = append(filtered, d)
    }

    w.Header().Set("Content-Type", "application/json")
    _ = json.NewEncoder(w).Encode(api.DeviceListResponse{
        Devices: filtered,
        Total:   len(filtered),
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

// RefreshDevice triggers an asynchronous, forced enrichment run for a device.
func (h *Handlers) RefreshDevice(w http.ResponseWriter, r *http.Request) {
    pdid := r.PathValue("pdid")
    d := h.cache.Get(pdid)
    if d == nil {
        http.Error(w, `{"error":"device not found"}`, http.StatusNotFound)
        return
    }

    if h.orch != nil {
        go h.orch.TriggerEnrichment(pdid, true)
    }

    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(http.StatusAccepted)
    _ = json.NewEncoder(w).Encode(api.AcceptedResponse{
        Message: "Refresh triggered",
        TaskID:  generateID(),
    })
}

// StreamEvents handles SSE connections, parsing Last-Event-ID headers for replay support.
func (h *Handlers) StreamEvents(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "text/event-stream")
    w.Header().Set("Cache-Control", "no-cache")
    w.Header().Set("Connection", "keep-alive")
    // CORS is intentionally omitted here for strict security; if cross-origin dashboard is needed, 
    // it should be handled by a reverse proxy. Keeping it strict prevents CSRF SSE hijacking.

    flusher, ok := w.(http.Flusher)
    if !ok {
        http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
        return
    }

    var lastEventID int64
    if lastIDStr := r.Header.Get("Last-Event-ID"); lastIDStr != "" {
        lastEventID, _ = strconv.ParseInt(lastIDStr, 10, 64)
    }

    clientID := generateID()
    client := h.broker.Subscribe(clientID, lastEventID)
    defer h.broker.Unsubscribe(clientID)

    ctx := r.Context()
    for {
        select {
        case <-ctx.Done():
            return
        case event, ok := <-client.Events:
            if !ok {
                return
            }

            frame := event.SSEFrame()
            if _, err := w.Write([]byte(frame)); err != nil {
                slog.Debug("SSE client socket write error, closing stream", "client_id", clientID, "error", err)
                return
            }
            flusher.Flush()
        }
    }
}

// generateID creates a random hex string for task or connection identification.
func generateID() string {
    b := make([]byte, 8)
    _, _ = rand.Read(b)
    return hex.EncodeToString(b)
}
