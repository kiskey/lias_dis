// Package api implements the HTTP server, middleware, and SSE broker for DIS.
//
// File:    apps/discovery-service/internal/api/handlers.go
// Version: 1.4
package api

import (
    "crypto/rand"
    "encoding/hex"
    "encoding/json"
	"io"
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

type IdentityManager interface {
	ResolvePDID(string) string
	GetIdentityProfile(string) (*models.IdentityProfile, error)
	BindIdentityAlias(string, models.IdentityBindingRequest) (models.IdentityAlias, error)
	RevokeIdentityAlias(string, int64) error
	ConfirmIdentityCandidate(int64) (*models.Device, error)
	RejectIdentityCandidate(int64) error
	SplitIdentity(string, models.IdentitySplitRequest) (*models.Device, error)
}

// Handlers contains the HTTP handlers for the DIS REST API.
type Handlers struct {
    cache  *inventory.Cache
    broker *Broker
    orch   EnrichmentTrigger
	identity IdentityManager
}

func (h *Handlers) SetIdentityManager(manager IdentityManager) { h.identity = manager }

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
	handler.HandleFunc("GET /api/v1/devices/{pdid}/identity", h.GetIdentity)
	handler.HandleFunc("POST /api/v1/devices/{pdid}/identity/bindings", h.BindIdentity)
	handler.HandleFunc("DELETE /api/v1/devices/{pdid}/identity/bindings/{aliasID}", h.RevokeIdentity)
	handler.HandleFunc("POST /api/v1/identity/candidates/{candidateID}/confirm", h.ConfirmIdentityCandidate)
	handler.HandleFunc("POST /api/v1/identity/candidates/{candidateID}/reject", h.RejectIdentityCandidate)
	handler.HandleFunc("POST /api/v1/devices/{pdid}/identity/split", h.SplitIdentity)

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
	if h.identity != nil {
		pdid = h.identity.ResolvePDID(pdid)
	}
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
	if h.identity != nil {
		pdid = h.identity.ResolvePDID(pdid)
	}
    d := h.cache.Get(pdid)
    if d == nil {
        http.Error(w, `{"error":"device not found"}`, http.StatusNotFound)
        return
    }

    if h.orch != nil {
		h.orch.TriggerEnrichment(pdid, true)
    }

    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(http.StatusAccepted)
    _ = json.NewEncoder(w).Encode(api.AcceptedResponse{
        Message: "Refresh triggered",
        TaskID:  generateID(),
    })
}

func (h *Handlers) GetIdentity(w http.ResponseWriter, r *http.Request) {
	if h.identity == nil {
		http.Error(w, `{"error":"identity persistence unavailable"}`, http.StatusServiceUnavailable)
		return
	}
	profile, err := h.identity.GetIdentityProfile(r.PathValue("pdid"))
	writeIdentityResult(w, profile, err, http.StatusOK)
}

func (h *Handlers) BindIdentity(w http.ResponseWriter, r *http.Request) {
	if h.identity == nil {
		http.Error(w, `{"error":"identity persistence unavailable"}`, http.StatusServiceUnavailable)
		return
	}
	var req models.IdentityBindingRequest
	if err := decodeIdentityJSON(r, &req); err != nil {
		http.Error(w, `{"error":"invalid request"}`, http.StatusBadRequest)
		return
	}
	alias, err := h.identity.BindIdentityAlias(r.PathValue("pdid"), req)
	writeIdentityResult(w, alias, err, http.StatusCreated)
}

func (h *Handlers) RevokeIdentity(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("aliasID"), 10, 64)
	if err == nil && h.identity != nil {
		err = h.identity.RevokeIdentityAlias(r.PathValue("pdid"), id)
	}
	if err != nil || h.identity == nil {
		http.Error(w, `{"error":"identity alias not found"}`, http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handlers) ConfirmIdentityCandidate(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("candidateID"), 10, 64)
	if err != nil || h.identity == nil {
		http.Error(w, `{"error":"candidate not found"}`, http.StatusNotFound)
		return
	}
	device, err := h.identity.ConfirmIdentityCandidate(id)
	writeIdentityResult(w, device, err, http.StatusOK)
}

func (h *Handlers) RejectIdentityCandidate(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("candidateID"), 10, 64)
	if err == nil && h.identity != nil {
		err = h.identity.RejectIdentityCandidate(id)
	}
	if err != nil || h.identity == nil {
		http.Error(w, `{"error":"candidate not found"}`, http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handlers) SplitIdentity(w http.ResponseWriter, r *http.Request) {
	if h.identity == nil {
		http.Error(w, `{"error":"identity persistence unavailable"}`, http.StatusServiceUnavailable)
		return
	}
	var req models.IdentitySplitRequest
	if err := decodeIdentityJSON(r, &req); err != nil {
		http.Error(w, `{"error":"invalid request"}`, http.StatusBadRequest)
		return
	}
	device, err := h.identity.SplitIdentity(r.PathValue("pdid"), req)
	writeIdentityResult(w, device, err, http.StatusCreated)
}

func decodeIdentityJSON(r *http.Request, value interface{}) error {
	decoder := json.NewDecoder(io.LimitReader(r.Body, 64<<10))
	decoder.DisallowUnknownFields()
	return decoder.Decode(value)
}

func writeIdentityResult(w http.ResponseWriter, value interface{}, err error, status int) {
	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		http.Error(w, `{"error":"`+strings.ReplaceAll(err.Error(), `"`, `'`)+`"}`, http.StatusBadRequest)
		return
	}
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
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
