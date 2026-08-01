// Package api implements the HTTP server, middleware, and SSE broker for DIS.
//
// File:    apps/discovery-service/internal/api/handlers.go
// Version: 1.2
package api

import (
    "crypto/rand"
    "encoding/hex"
    "encoding/json"
    "net/http"

    "github.com/user/lias-dis/apps/discovery-service/internal/inventory"
    "github.com/user/lias-dis/shared/api"
)

// EnrichmentTrigger defines the interface for triggering on-demand enrichment.
// This decouples the API layer from the discovery package, preventing cyclic imports.
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

// RefreshDevice triggers an on-demand enrichment for a device via the orchestrator.
// The orchestrator handles running primaries and falling back to Nmap if needed.
func (h *Handlers) RefreshDevice(w http.ResponseWriter, r *http.Request) {
    pdid := r.PathValue("pdid")
    d := h.cache.Get(pdid)
    if d == nil {
        http.Error(w, `{"error":"device not found"}`, http.StatusNotFound)
        return
    }

    // Force enrichment pipeline asynchronously
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
