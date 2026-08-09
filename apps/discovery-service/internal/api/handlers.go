// Package api implements the HTTP server, middleware, and SSE broker for DIS.
//
// File:    apps/discovery-service/internal/api/handlers.go
// Version: 1.4
package api

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
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
	ListIdentityCandidates(string, int, string) (models.IdentityCandidateListResponse, error)
	GetIdentityCandidate(int64) (*models.IdentityCandidateDetail, error)
	ConfirmIdentityCandidate(int64, models.IdentityCandidateDecisionRequest) (*models.Device, error)
	RejectIdentityCandidate(int64, models.IdentityCandidateDecisionRequest) (*models.IdentityCandidateDetail, error)
	ReopenIdentityCandidate(int64, models.IdentityCandidateDecisionRequest) (*models.IdentityCandidateDetail, error)
	SplitIdentity(string, models.IdentitySplitRequest) (*models.Device, error)
}

// Handlers contains the HTTP handlers for the DIS REST API.
type Handlers struct {
	cache    *inventory.Cache
	broker   *Broker
	orch     EnrichmentTrigger
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

	handler.HandleFunc("GET /api/v1/capabilities", h.Capabilities)
	handler.HandleFunc("GET /api/v1/devices", h.ListDevices)
	handler.HandleFunc("GET /api/v1/devices/{pdid}", h.GetDevice)
	handler.HandleFunc("POST /api/v1/devices/{pdid}/refresh", h.RefreshDevice)
	handler.HandleFunc("GET /api/v1/events", h.StreamEvents)
	handler.HandleFunc("GET /api/v1/devices/{pdid}/identity", h.GetIdentity)
	handler.HandleFunc("POST /api/v1/devices/{pdid}/identity/bindings", h.BindIdentity)
	handler.HandleFunc("DELETE /api/v1/devices/{pdid}/identity/bindings/{aliasID}", h.RevokeIdentity)
	handler.HandleFunc("GET /api/v1/identity/candidates", h.ListIdentityCandidates)
	handler.HandleFunc("GET /api/v1/identity/candidates/{candidateID}", h.GetIdentityCandidate)
	handler.HandleFunc("POST /api/v1/identity/candidates/{candidateID}/confirm", h.ConfirmIdentityCandidate)
	handler.HandleFunc("POST /api/v1/identity/candidates/{candidateID}/reject", h.RejectIdentityCandidate)
	handler.HandleFunc("POST /api/v1/identity/candidates/{candidateID}/reopen", h.ReopenIdentityCandidate)
	handler.HandleFunc("POST /api/v1/devices/{pdid}/identity/split", h.SplitIdentity)

	// Wrap the internal handler with the Auth middleware
	mux.Handle("/", AuthMiddleware(authToken, handler))
}

// Capabilities returns the stable v1 contract and optional DIS feature set.
// The response is computed from constants and performs no storage or network I/O.
func (h *Handlers) Capabilities(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "private, max-age=300")
	_ = json.NewEncoder(w).Encode(api.DISCapabilities())
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
	if err := decodeIdentityJSON(w, r, &req, false); err != nil {
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
	var req models.IdentityCandidateDecisionRequest
	if err := decodeIdentityJSON(w, r, &req, true); err != nil || len(req.DecisionNote) > 1024 {
		writeAPIError(w, http.StatusBadRequest, "invalid_request", "invalid candidate decision request", false)
		return
	}
	device, err := h.identity.ConfirmIdentityCandidate(id, req)
	writeCandidateResult(w, device, err, http.StatusOK)
}

func (h *Handlers) RejectIdentityCandidate(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("candidateID"), 10, 64)
	if err != nil || h.identity == nil {
		writeAPIError(w, http.StatusNotFound, "candidate_not_found", "candidate not found", false)
		return
	}
	var req models.IdentityCandidateDecisionRequest
	if err := decodeIdentityJSON(w, r, &req, true); err != nil || len(req.DecisionNote) > 1024 {
		writeAPIError(w, http.StatusBadRequest, "invalid_request", "invalid candidate decision request", false)
		return
	}
	_, err = h.identity.RejectIdentityCandidate(id, req)
	if err != nil {
		writeCandidateResult(w, nil, err, http.StatusOK)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handlers) ListIdentityCandidates(w http.ResponseWriter, r *http.Request) {
	if h.identity == nil {
		writeAPIError(w, http.StatusServiceUnavailable, "identity_unavailable", "identity persistence unavailable", true)
		return
	}
	for key := range r.URL.Query() {
		if key != "status" && key != "limit" && key != "cursor" {
			writeAPIError(w, http.StatusBadRequest, "invalid_query", "unsupported candidate query parameter", false)
			return
		}
	}
	status := strings.TrimSpace(r.URL.Query().Get("status"))
	if status != "" && status != "pending" && status != "rejected" && status != "confirmed" {
		writeAPIError(w, http.StatusBadRequest, "invalid_status", "status must be pending, rejected, or confirmed", false)
		return
	}
	limit := 50
	if raw := r.URL.Query().Get("limit"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > 100 {
			writeAPIError(w, http.StatusBadRequest, "invalid_limit", "limit must be between 1 and 100", false)
			return
		}
		limit = parsed
	}
	response, err := h.identity.ListIdentityCandidates(status, limit, r.URL.Query().Get("cursor"))
	writeCandidateResult(w, response, err, http.StatusOK)
}

func (h *Handlers) GetIdentityCandidate(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("candidateID"), 10, 64)
	if err != nil || id < 1 || h.identity == nil {
		writeAPIError(w, http.StatusNotFound, "candidate_not_found", "candidate not found", false)
		return
	}
	candidate, err := h.identity.GetIdentityCandidate(id)
	writeCandidateResult(w, candidate, err, http.StatusOK)
}

func (h *Handlers) ReopenIdentityCandidate(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("candidateID"), 10, 64)
	if err != nil || id < 1 || h.identity == nil {
		writeAPIError(w, http.StatusNotFound, "candidate_not_found", "candidate not found", false)
		return
	}
	var req models.IdentityCandidateDecisionRequest
	if err := decodeIdentityJSON(w, r, &req, true); err != nil || len(req.DecisionNote) > 1024 {
		writeAPIError(w, http.StatusBadRequest, "invalid_request", "invalid candidate decision request", false)
		return
	}
	candidate, err := h.identity.ReopenIdentityCandidate(id, req)
	writeCandidateResult(w, candidate, err, http.StatusOK)
}

func (h *Handlers) SplitIdentity(w http.ResponseWriter, r *http.Request) {
	if h.identity == nil {
		http.Error(w, `{"error":"identity persistence unavailable"}`, http.StatusServiceUnavailable)
		return
	}
	var req models.IdentitySplitRequest
	if err := decodeIdentityJSON(w, r, &req, false); err != nil {
		http.Error(w, `{"error":"invalid request"}`, http.StatusBadRequest)
		return
	}
	device, err := h.identity.SplitIdentity(r.PathValue("pdid"), req)
	writeIdentityResult(w, device, err, http.StatusCreated)
}

func decodeIdentityJSON(w http.ResponseWriter, r *http.Request, value interface{}, optional bool) error {
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		if optional && errors.Is(err, io.EOF) {
			return nil
		}
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("request must contain one JSON object")
	}
	return nil
}

func writeCandidateResult(w http.ResponseWriter, value interface{}, err error, status int) {
	if errors.Is(err, models.ErrCandidateNotFound) {
		writeAPIError(w, http.StatusNotFound, "candidate_not_found", "candidate not found", false)
		return
	}
	if errors.Is(err, models.ErrCandidateStaleOrConflicting) {
		writeAPIError(w, http.StatusConflict, "candidate_stale_or_conflicting", "candidate changed, was decided, disappeared, or is simultaneously present", false)
		return
	}
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid_request", err.Error(), false)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeAPIError(w http.ResponseWriter, status int, code, details string, retryable bool) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(api.ErrorResponse{Error: code, Code: code, Details: details, Retryable: retryable})
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
