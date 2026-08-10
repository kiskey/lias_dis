// Package api implements the HTTP server, REST handlers, and SSE broker for LIAS.
//
// File:    apps/lias/internal/api/handlers.go
// Version: 3.4 (Enforced Enabled state for global policy to fix hierarchy reset bug)
package api

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/user/lias-dis/apps/lias/internal/nftables"
	"github.com/user/lias-dis/apps/lias/internal/policy"
	"github.com/user/lias-dis/apps/lias/internal/schedule"
	"github.com/user/lias-dis/apps/lias/internal/scheduleconflict"
	"github.com/user/lias-dis/apps/lias/internal/storage"
	liasSync "github.com/user/lias-dis/apps/lias/internal/sync"
	"github.com/user/lias-dis/apps/lias/internal/tags"
	"github.com/user/lias-dis/shared/api"
	"github.com/user/lias-dis/shared/models"
)

type Handlers struct {
	cache         *liasSync.Cache
	tagMgr        *tags.Manager
	polEng        *policy.Engine
	schedEng      *schedule.Engine
	nftCtrl       *nftables.Controller
	store         *storage.Storage
	trigger       chan struct{}
	broker        *Broker
	identity      IdentityGateway
	sessions      *browserSessionManager
	secureCookies bool
	usersMu       sync.RWMutex
	users         map[string]models.User
}

type IdentityGateway interface {
	CapabilitiesSnapshot() api.LIASCapabilitiesResponse
	SystemStatus() api.SystemStatusResponse
	ListIdentityCandidates(context.Context, url.Values) liasSync.GatewayResponse
	GetIdentityCandidate(context.Context, int64) liasSync.GatewayResponse
	GetIdentityProfile(context.Context, string) liasSync.GatewayResponse
	BindIdentity(context.Context, string, []byte) liasSync.GatewayResponse
	RevokeIdentity(context.Context, string, int64) liasSync.GatewayResponse
	DecideIdentityCandidate(context.Context, int64, string, []byte) liasSync.GatewayResponse
	SplitIdentity(context.Context, string, []byte) liasSync.GatewayResponse
}

func (h *Handlers) SetIdentityGateway(gateway IdentityGateway) { h.identity = gateway }

func NewHandlers(
	cache *liasSync.Cache,
	tagMgr *tags.Manager,
	polEng *policy.Engine,
	schedEng *schedule.Engine,
	nftCtrl *nftables.Controller,
	store *storage.Storage,
	trigger chan struct{},
	broker *Broker,
) *Handlers {
	handler := &Handlers{
		cache:    cache,
		tagMgr:   tagMgr,
		polEng:   polEng,
		schedEng: schedEng,
		nftCtrl:  nftCtrl,
		store:    store,
		trigger:  trigger,
		broker:   broker,
		sessions: newBrowserSessionManager(),
		users:    make(map[string]models.User),
	}
	if store != nil {
		if users, err := store.ListUsers(); err == nil {
			for _, user := range users {
				handler.users[user.ID] = user
			}
		}
	}
	return handler
}

// SetSecureCookies controls the Secure attribute on browser session cookies.
// It should be enabled whenever LIAS is served over HTTPS.
func (h *Handlers) SetSecureCookies(enabled bool) { h.secureCookies = enabled }

func (h *Handlers) RegisterRoutes(mux *http.ServeMux, authToken string) {
	h.sessions.configure(authToken, h.secureCookies)
	mux.Handle("POST /api/v1/session", jsonErrorContentTypeMiddleware(http.HandlerFunc(h.CreateBrowserSession)))
	mux.Handle("DELETE /api/v1/session", jsonErrorContentTypeMiddleware(http.HandlerFunc(h.DeleteBrowserSession)))
	handler := http.NewServeMux()

	handler.HandleFunc("GET /api/v1/devices", h.ListDevices)
	handler.HandleFunc("GET /api/v1/snapshot", h.Snapshot)
	handler.HandleFunc("GET /api/v1/devices/{pdid}", h.GetDevice)
	handler.HandleFunc("POST /api/v1/devices/{pdid}/tags", h.AssignDeviceTag)
	handler.HandleFunc("POST /api/v1/devices/{pdid}/pause", h.PauseDeviceInternet)
	handler.HandleFunc("DELETE /api/v1/devices/{pdid}/pause", h.UnpauseDeviceInternet)
	handler.HandleFunc("POST /api/v1/devices/{pdid}/extend", h.ExtendDeviceAccess)
	handler.HandleFunc("DELETE /api/v1/devices/{pdid}/extend", h.CancelDeviceExtension)
	handler.HandleFunc("GET /api/v1/devices/{pdid}/effective-status", h.GetDeviceEffectiveStatus)
	handler.HandleFunc("POST /api/v1/devices/{pdid}/rename", h.RenameDevice)
	handler.HandleFunc("POST /api/v1/devices/{pdid}/user", h.AssignDeviceUser)
	handler.HandleFunc("GET /api/v1/devices/{pdid}/logs", h.GetDeviceLogs)
	handler.HandleFunc("GET /api/v1/capabilities", h.Capabilities)
	handler.HandleFunc("GET /api/v1/system/status", h.SystemStatus)
	handler.HandleFunc("GET /api/v1/identity/candidates", h.ListIdentityCandidates)
	handler.HandleFunc("GET /api/v1/identity/candidates/{candidateID}", h.GetIdentityCandidate)
	handler.HandleFunc("POST /api/v1/identity/candidates/{candidateID}/confirm", h.ConfirmIdentityCandidate)
	handler.HandleFunc("POST /api/v1/identity/candidates/{candidateID}/reject", h.RejectIdentityCandidate)
	handler.HandleFunc("POST /api/v1/identity/candidates/{candidateID}/reopen", h.ReopenIdentityCandidate)
	handler.HandleFunc("GET /api/v1/devices/{pdid}/identity", h.GetIdentityProfile)
	handler.HandleFunc("POST /api/v1/devices/{pdid}/identity/bindings", h.BindIdentity)
	handler.HandleFunc("DELETE /api/v1/devices/{pdid}/identity/bindings/{aliasID}", h.RevokeIdentity)
	handler.HandleFunc("POST /api/v1/devices/{pdid}/identity/split", h.SplitIdentity)

	handler.HandleFunc("GET /api/v1/tags", h.ListTags)
	handler.HandleFunc("POST /api/v1/tags", h.CreateTag)
	handler.HandleFunc("PUT /api/v1/tags/{id}", h.UpdateTag)
	handler.HandleFunc("DELETE /api/v1/tags/{id}", h.DeleteTag)
	handler.HandleFunc("POST /api/v1/tags/{id}/extend", h.ExtendTagAccess)
	handler.HandleFunc("DELETE /api/v1/tags/{id}/extend", h.CancelTagExtension)
	handler.HandleFunc("GET /api/v1/tags/{id}/effective-status", h.GetTagEffectiveStatus)

	handler.HandleFunc("GET /api/v1/policies", h.ListPolicies)
	handler.HandleFunc("POST /api/v1/policies", h.CreatePolicy)
	handler.HandleFunc("POST /api/v1/policies/validate", h.ValidatePolicy)
	handler.HandleFunc("PUT /api/v1/policies/{id}", h.UpdatePolicy)
	handler.HandleFunc("DELETE /api/v1/policies/{id}", h.DeletePolicy)
	handler.HandleFunc("GET /api/v1/policies/export", h.ExportPolicies)
	handler.HandleFunc("POST /api/v1/policies/import", h.ImportPolicies)

	handler.HandleFunc("GET /api/v1/schedules", h.ListSchedules)
	handler.HandleFunc("POST /api/v1/schedules", h.CreateSchedule)
	handler.HandleFunc("PUT /api/v1/schedules/{id}", h.UpdateSchedule)
	handler.HandleFunc("DELETE /api/v1/schedules/{id}", h.DeleteSchedule)

	handler.HandleFunc("GET /api/v1/users", h.ListUsers)
	handler.HandleFunc("POST /api/v1/users", h.CreateUser)
	handler.HandleFunc("GET /api/v1/users/{id}", h.GetUser)
	handler.HandleFunc("PUT /api/v1/users/{id}", h.UpdateUser)
	handler.HandleFunc("DELETE /api/v1/users/{id}", h.DeleteUser)
	handler.HandleFunc("DELETE /api/v1/devices/{pdid}/user", h.UnassignDeviceUser)
	handler.HandleFunc("POST /api/v1/vacation", h.ToggleVacationMode)

	handler.HandleFunc("GET /api/v1/stats", h.GetNetworkStats)
	handler.HandleFunc("POST /api/v1/nftables/flush", h.FlushNftables)
	handler.HandleFunc("GET /api/v1/events", h.StreamEvents)

	mux.Handle("/api/", jsonErrorContentTypeMiddleware(AuthMiddlewareWithSessions(authToken, h.sessions, http.MaxBytesHandler(handler, 1<<20))))
}

func (h *Handlers) StreamEvents(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "null")

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, `{"error":"streaming unsupported"}`, http.StatusInternalServerError)
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
				slog.Debug("LIAS SSE client socket write error, closing stream", "client_id", clientID, "error", err)
				return
			}
			flusher.Flush()
		}
	}
}

func (h *Handlers) tryTrigger() {
	h.cache.BumpRevision()
	select {
	case h.trigger <- struct{}{}:
	default:
	}
}

type snapshotResponse struct {
	Revision        uint64                                 `json:"revision"`
	Devices         []models.Device                        `json:"devices"`
	Tags            []tags.Tag                             `json:"tags"`
	Policies        []models.Policy                        `json:"policies"`
	Schedules       []models.Schedule                      `json:"schedules"`
	Users           []models.User                          `json:"users"`
	DeviceEffective map[string]api.EffectiveStatusResponse `json:"device_effective_statuses"`
	TagEffective    map[string]api.EffectiveStatusResponse `json:"tag_effective_statuses"`
}

func (h *Handlers) Snapshot(w http.ResponseWriter, r *http.Request) {
	for attempt := 0; attempt < 3; attempt++ {
		revision := h.cache.Revision()
		etag := fmt.Sprintf(`"rev-%d"`, revision)
		if r.Header.Get("If-None-Match") == etag {
			w.Header().Set("ETag", etag)
			w.WriteHeader(http.StatusNotModified)
			return
		}
		localDevices := h.cache.List()
		devices := make([]models.Device, 0, len(localDevices))
		deviceEffective := make(map[string]api.EffectiveStatusResponse, len(localDevices))
		for i := range localDevices {
			device := localDevices[i].Device
			device.Tags = append([]string(nil), localDevices[i].Tags...)
			devices = append(devices, device)
			deviceEffective[device.PDID] = h.computeDeviceEffectiveStatus(&localDevices[i])
		}
		tagList := h.tagMgr.List()
		tagEffective := make(map[string]api.EffectiveStatusResponse, len(tagList))
		for _, tag := range tagList {
			tagEffective[tag.ID] = h.computeTagEffectiveStatus(tag.ID)
		}
		snapshot := snapshotResponse{Revision: revision, Devices: devices, Tags: tagList,
			Policies: h.polEng.ListPolicies(), Schedules: h.schedEng.ListSchedules(), Users: h.usersSnapshot(),
			DeviceEffective: deviceEffective, TagEffective: tagEffective}
		if h.cache.Revision() != revision {
			continue
		}
		w.Header().Set("ETag", etag)
		w.Header().Set("Cache-Control", "private, no-cache")
		writeJSON(w, http.StatusOK, snapshot)
		return
	}
	writeJSON(w, http.StatusServiceUnavailable, api.ErrorResponse{Error: "snapshot_busy", Code: "snapshot_busy", Retryable: true})
}

func (h *Handlers) usersSnapshot() []models.User {
	h.usersMu.RLock()
	users := make([]models.User, 0, len(h.users))
	for _, user := range h.users {
		users = append(users, user)
	}
	h.usersMu.RUnlock()
	sort.Slice(users, func(i, j int) bool { return users[i].ID < users[j].ID })
	return users
}

func (h *Handlers) Capabilities(w http.ResponseWriter, _ *http.Request) {
	if h.identity == nil {
		writeJSON(w, http.StatusOK, api.LIASCapabilitiesResponse{
			CapabilitiesResponse: api.CapabilitiesResponse{APIVersion: api.APIVersionV1, SchemaVersion: api.APISchemaVersion,
				MinClientAPIVersion: api.APIVersionV1, PublicDeviceKey: "pdid", ResponseCompatibility: "additive",
				Features: []string{api.FeatureDeviceInventory, api.FeatureSnapshotV1, api.FeatureSSEEvents, api.FeatureSSEReplay}},
			Upstream: api.UpstreamState{},
		})
		return
	}
	writeJSON(w, http.StatusOK, h.identity.CapabilitiesSnapshot())
}

func (h *Handlers) SystemStatus(w http.ResponseWriter, _ *http.Request) {
	if h.identity == nil {
		writeJSON(w, http.StatusServiceUnavailable, api.SystemStatusResponse{Status: "degraded", APIVersion: api.APIVersionV1,
			SchemaVersion: api.APISchemaVersion})
		return
	}
	writeJSON(w, http.StatusOK, h.identity.SystemStatus())
}

func (h *Handlers) ListIdentityCandidates(w http.ResponseWriter, r *http.Request) {
	if h.identity == nil {
		writeGatewayUnavailable(w)
		return
	}
	for key := range r.URL.Query() {
		if key != "status" && key != "limit" && key != "cursor" {
			writeJSON(w, http.StatusBadRequest, api.ErrorResponse{Error: "invalid_query", Code: "invalid_query"})
			return
		}
	}
	query := make(url.Values)
	status := strings.TrimSpace(r.URL.Query().Get("status"))
	if status != "" {
		if status != "pending" && status != "confirmed" && status != "rejected" {
			writeJSON(w, http.StatusBadRequest, api.ErrorResponse{Error: "invalid_status", Code: "invalid_status"})
			return
		}
		query.Set("status", status)
	}
	if rawLimit := r.URL.Query().Get("limit"); rawLimit != "" {
		limit, err := strconv.Atoi(rawLimit)
		if err != nil || limit < 1 || limit > 100 {
			writeJSON(w, http.StatusBadRequest, api.ErrorResponse{Error: "invalid_limit", Code: "invalid_limit"})
			return
		}
		query.Set("limit", strconv.Itoa(limit))
	}
	if cursor := r.URL.Query().Get("cursor"); cursor != "" {
		if len(cursor) > 1024 {
			writeJSON(w, http.StatusBadRequest, api.ErrorResponse{Error: "invalid_cursor", Code: "invalid_cursor"})
			return
		}
		query.Set("cursor", cursor)
	}
	writeGatewayResponse(w, h.identity.ListIdentityCandidates(r.Context(), query))
}

func (h *Handlers) GetIdentityCandidate(w http.ResponseWriter, r *http.Request) {
	id, ok := identityPathID(w, r, "candidateID")
	if !ok || h.identity == nil {
		if h.identity == nil {
			writeGatewayUnavailable(w)
		}
		return
	}
	writeGatewayResponse(w, h.identity.GetIdentityCandidate(r.Context(), id))
}

func (h *Handlers) ConfirmIdentityCandidate(w http.ResponseWriter, r *http.Request) {
	h.decideIdentityCandidate(w, r, "confirm")
}

func (h *Handlers) RejectIdentityCandidate(w http.ResponseWriter, r *http.Request) {
	h.decideIdentityCandidate(w, r, "reject")
}

func (h *Handlers) ReopenIdentityCandidate(w http.ResponseWriter, r *http.Request) {
	h.decideIdentityCandidate(w, r, "reopen")
}

func (h *Handlers) decideIdentityCandidate(w http.ResponseWriter, r *http.Request, action string) {
	id, ok := identityPathID(w, r, "candidateID")
	if !ok {
		return
	}
	if h.identity == nil {
		writeGatewayUnavailable(w)
		return
	}
	var request models.IdentityCandidateDecisionRequest
	body, err := decodeAndMarshalGatewayJSON(w, r, &request, true)
	if err != nil || len(request.DecisionNote) > 1024 {
		writeJSON(w, http.StatusBadRequest, api.ErrorResponse{Error: "invalid_request", Code: "invalid_request"})
		return
	}
	writeGatewayResponse(w, h.identity.DecideIdentityCandidate(r.Context(), id, action, body))
}

func (h *Handlers) GetIdentityProfile(w http.ResponseWriter, r *http.Request) {
	if h.identity == nil {
		writeGatewayUnavailable(w)
		return
	}
	writeGatewayResponse(w, h.identity.GetIdentityProfile(r.Context(), r.PathValue("pdid")))
}

func (h *Handlers) BindIdentity(w http.ResponseWriter, r *http.Request) {
	if h.identity == nil {
		writeGatewayUnavailable(w)
		return
	}
	var request models.IdentityBindingRequest
	body, err := decodeAndMarshalGatewayJSON(w, r, &request, false)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, api.ErrorResponse{Error: "invalid_request", Code: "invalid_request"})
		return
	}
	writeGatewayResponse(w, h.identity.BindIdentity(r.Context(), r.PathValue("pdid"), body))
}

func (h *Handlers) RevokeIdentity(w http.ResponseWriter, r *http.Request) {
	if h.identity == nil {
		writeGatewayUnavailable(w)
		return
	}
	id, ok := identityPathID(w, r, "aliasID")
	if !ok {
		return
	}
	writeGatewayResponse(w, h.identity.RevokeIdentity(r.Context(), r.PathValue("pdid"), id))
}

func (h *Handlers) SplitIdentity(w http.ResponseWriter, r *http.Request) {
	if h.identity == nil {
		writeGatewayUnavailable(w)
		return
	}
	var request models.IdentitySplitRequest
	body, err := decodeAndMarshalGatewayJSON(w, r, &request, false)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, api.ErrorResponse{Error: "invalid_request", Code: "invalid_request"})
		return
	}
	writeGatewayResponse(w, h.identity.SplitIdentity(r.Context(), r.PathValue("pdid"), body))
}

func identityPathID(w http.ResponseWriter, r *http.Request, name string) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue(name), 10, 64)
	if err != nil || id < 1 {
		writeJSON(w, http.StatusNotFound, api.ErrorResponse{Error: "identity_record_not_found", Code: "identity_record_not_found"})
		return 0, false
	}
	return id, true
}

func decodeAndMarshalGatewayJSON(w http.ResponseWriter, r *http.Request, target any, optional bool) ([]byte, error) {
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		if optional && err == io.EOF {
			return nil, nil
		}
		return nil, err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return nil, fmt.Errorf("request must contain one JSON object")
	}
	return json.Marshal(target)
}

func writeGatewayResponse(w http.ResponseWriter, response liasSync.GatewayResponse) {
	if response.ContentType != "" {
		w.Header().Set("Content-Type", response.ContentType)
	}
	if response.Status == 0 {
		response.Status = http.StatusBadGateway
	}
	w.WriteHeader(response.Status)
	if len(response.Body) > 0 {
		_, _ = w.Write(response.Body)
	}
}

func writeGatewayUnavailable(w http.ResponseWriter) {
	writeJSON(w, http.StatusNotImplemented, api.ErrorResponse{Error: "feature_not_supported", Code: "feature_not_supported"})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func (h *Handlers) ListDevices(w http.ResponseWriter, r *http.Request) {
	localDevs := h.cache.List()
	devs := make([]models.Device, 0, len(localDevs))
	for _, ld := range localDevs {
		dev := ld.Device
		dev.Tags = ld.Tags
		devs = append(devs, dev)
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(api.DeviceListResponse{
		Devices: devs,
		Total:   len(devs),
	})
}

func (h *Handlers) GetDevice(w http.ResponseWriter, r *http.Request) {
	pdid := r.PathValue("pdid")
	d := h.cache.Get(pdid)
	if d == nil {
		http.Error(w, `{"error":"device not found"}`, http.StatusNotFound)
		return
	}
	dev := d.Device
	dev.Tags = d.Tags

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(dev)
}

func (h *Handlers) GetDeviceLogs(w http.ResponseWriter, r *http.Request) {
	pdid := r.PathValue("pdid")
	if h.store == nil {
		http.Error(w, `{"error":"storage unavailable"}`, http.StatusServiceUnavailable)
		return
	}

	logs, err := h.store.GetDeviceFlowLogs(pdid, 100)
	if err != nil {
		http.Error(w, `{"error":"failed to fetch logs"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(logs)
}

// AssignDeviceTag accepts an array of tags
func (h *Handlers) AssignDeviceTag(w http.ResponseWriter, r *http.Request) {
	pdid := r.PathValue("pdid")

	var rawBody map[string]json.RawMessage
	if _, err := decodeAndMarshalGatewayJSON(w, r, &rawBody, false); err != nil {
		http.Error(w, `{"error":"invalid request"}`, http.StatusBadRequest)
		return
	}
	for key := range rawBody {
		if key != "tag_ids" && key != "tag_id" {
			writeJSON(w, http.StatusBadRequest, api.ErrorResponse{Error: "invalid_request", Code: "invalid_request", Details: "unknown field: " + key})
			return
		}
	}

	var req struct {
		TagIDs []string
	}

	if v, ok := rawBody["tag_ids"]; ok {
		if err := json.Unmarshal(v, &req.TagIDs); err != nil {
			http.Error(w, `{"error":"invalid tag_ids format"}`, http.StatusBadRequest)
			return
		}
	} else if v, ok := rawBody["tag_id"]; ok {
		var legacyTagID string
		if err := json.Unmarshal(v, &legacyTagID); err != nil {
			http.Error(w, `{"error":"invalid tag_id format"}`, http.StatusBadRequest)
			return
		}
		req.TagIDs = []string{legacyTagID}
	}

	if len(req.TagIDs) == 0 {
		req.TagIDs = []string{"generic"}
	}

	h.cache.SetTags(pdid, req.TagIDs)
	d := h.cache.Get(pdid)
	mac := ""
	if d != nil {
		mac = d.CurrentMAC
	}

	if h.store != nil {
		if err := h.store.SaveDeviceTags(pdid, req.TagIDs, mac); err != nil {
			http.Error(w, `{"error":"failed to persist device tags"}`, http.StatusInternalServerError)
			return
		}
	}
	h.tryTrigger()
	w.WriteHeader(http.StatusNoContent)
}

// PauseDeviceInternet creates a temporary high-priority block schedule for 1 hour.
// V3.2: Migrated to use persistent ExpiresAt field instead of fragile goroutine.
func (h *Handlers) PauseDeviceInternet(w http.ResponseWriter, r *http.Request) {
	pdid := r.PathValue("pdid")
	d := h.cache.Get(pdid)
	if d == nil {
		http.Error(w, `{"error":"device not found"}`, http.StatusNotFound)
		return
	}
	for _, t := range d.Tags {
		if t == "infrastructure" {
			http.Error(w, `{"error":"infrastructure devices are always allowed; pause not applicable"}`, http.StatusConflict)
			return
		}
	}

	expiresAt := time.Now().Add(1 * time.Hour)
	polID := "pol_pause_" + pdid
	tempSchedID := "sched_pause_" + generateID()
	now := time.Now()
	tempSched := models.Schedule{
		ID: tempSchedID, Name: "Temporary Pause", Mode: models.ScheduleModeDowntime, Timezone: "UTC",
		Rules: []models.ScheduleRule{
			{Days: []string{"sun", "mon", "tue", "wed", "thu", "fri", "sat"}, StartTime: now.UTC().Format("15:04"), EndTime: now.UTC().Add(1 * time.Hour).Format("15:04"), Action: models.ActionBlock},
		},
	}
	h.schedEng.UpsertSchedule(tempSched)
	if h.store != nil {
		_ = h.store.SaveSchedule(tempSched)
	}

	tempPol := models.Policy{
		ID: polID, Name: "Paused Internet", Type: models.PolicyTypeDevice, TargetID: pdid,
		Action: models.ActionSchedule, ScheduleIDs: []string{tempSchedID}, Priority: 1000, Enabled: true,
		ExpiresAt: &expiresAt, ReasonTag: "pause",
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
	h.polEng.UpsertPolicy(tempPol)
	if h.store != nil {
		_ = h.store.SavePolicy(tempPol)
	}

	h.tryTrigger()
	h.broker.BroadcastEffectiveStatusChanged("device", pdid)

	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "paused for 1 hour"})
}

func (h *Handlers) UnpauseDeviceInternet(w http.ResponseWriter, r *http.Request) {
	pdid := r.PathValue("pdid")
	polID := "pol_pause_" + pdid

	pol, exists := h.polEng.GetPolicy(polID)
	if !exists {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	schedIDs := pol.GetScheduleIDs()
	h.polEng.DeletePolicy(polID)
	if h.store != nil {
		_ = h.store.DeletePolicy(polID)
	}

	for _, sid := range schedIDs {
		h.schedEng.DeleteSchedule(sid)
		if h.store != nil {
			_ = h.store.DeleteSchedule(sid)
		}
	}

	h.tryTrigger()
	h.broker.BroadcastEffectiveStatusChanged("device", pdid)
	w.WriteHeader(http.StatusNoContent)
}

// ExtendDeviceAccess creates a temporary high-priority ALLOW policy for a device.
func (h *Handlers) ExtendDeviceAccess(w http.ResponseWriter, r *http.Request) {
	pdid := r.PathValue("pdid")
	d := h.cache.Get(pdid)
	if d == nil {
		http.Error(w, `{"error":"device not found"}`, http.StatusNotFound)
		return
	}
	for _, t := range d.Tags {
		if t == "infrastructure" {
			http.Error(w, `{"error":"infrastructure devices are always allowed; extension not applicable"}`, http.StatusConflict)
			return
		}
	}

	var req api.ExtendAccessRequest
	if _, err := decodeAndMarshalGatewayJSON(w, r, &req, false); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}
	if req.Minutes < 1 || req.Minutes > 120 {
		http.Error(w, `{"error":"minutes must be between 1 and 120"}`, http.StatusBadRequest)
		return
	}

	if gp, ok := h.polEng.GetPolicy("global_default"); ok && gp.Enabled && gp.Action == models.ActionBlock {
		http.Error(w, `{"error":"global access switch is set to Block; per-device extension is not available"}`, http.StatusConflict)
		return
	}

	expiresAt := time.Now().Add(time.Duration(req.Minutes) * time.Minute)
	polID := "pol_extend_device_" + pdid
	pol := models.Policy{
		ID: polID, Name: "Extended Access", Type: models.PolicyTypeDevice, TargetID: pdid,
		Action: models.ActionAllow, Priority: 2000, Enabled: true,
		ExpiresAt: &expiresAt, ReasonTag: "extend_access",
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
	h.polEng.UpsertPolicy(pol)
	if h.store != nil {
		if err := h.store.SavePolicy(pol); err != nil {
			http.Error(w, `{"error":"failed to persist extension"}`, http.StatusInternalServerError)
			return
		}
	}
	h.tryTrigger()
	h.broker.BroadcastEffectiveStatusChanged("device", pdid)

	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(api.ExtendAccessResponse{
		Status: "extended", ExpiresAt: expiresAt.UTC().Format(time.RFC3339), Minutes: req.Minutes,
	})
}

func (h *Handlers) CancelDeviceExtension(w http.ResponseWriter, r *http.Request) {
	pdid := r.PathValue("pdid")
	polID := "pol_extend_device_" + pdid
	if _, exists := h.polEng.GetPolicy(polID); !exists {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	h.polEng.DeletePolicy(polID)
	if h.store != nil {
		_ = h.store.DeletePolicy(polID)
	}
	h.tryTrigger()
	h.broker.BroadcastEffectiveStatusChanged("device", pdid)
	w.WriteHeader(http.StatusNoContent)
}

// ExtendTagAccess creates a temporary high-priority ALLOW policy for an entire tag group.
func (h *Handlers) ExtendTagAccess(w http.ResponseWriter, r *http.Request) {
	tagID := r.PathValue("id")
	var exists bool
	for _, t := range h.tagMgr.List() {
		if t.ID == tagID {
			exists = true
			break
		}
	}
	if !exists {
		http.Error(w, `{"error":"tag not found"}`, http.StatusNotFound)
		return
	}
	if tagID == "infrastructure" {
		http.Error(w, `{"error":"infrastructure tag is always allowed; extension not applicable"}`, http.StatusConflict)
		return
	}

	var req api.ExtendAccessRequest
	if _, err := decodeAndMarshalGatewayJSON(w, r, &req, false); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}
	if req.Minutes < 1 || req.Minutes > 120 {
		http.Error(w, `{"error":"minutes must be between 1 and 120"}`, http.StatusBadRequest)
		return
	}

	if gp, ok := h.polEng.GetPolicy("global_default"); ok && gp.Enabled && gp.Action == models.ActionBlock {
		http.Error(w, `{"error":"global access switch is set to Block; per-tag extension is not available"}`, http.StatusConflict)
		return
	}

	expiresAt := time.Now().Add(time.Duration(req.Minutes) * time.Minute)
	polID := "pol_extend_tag_" + tagID
	pol := models.Policy{
		ID: polID, Name: "Extended Access (Tag)", Type: models.PolicyTypeTag, TargetID: tagID,
		Action: models.ActionAllow, Priority: 2000, Enabled: true,
		ExpiresAt: &expiresAt, ReasonTag: "extend_access",
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
	h.polEng.UpsertPolicy(pol)
	if h.store != nil {
		if err := h.store.SavePolicy(pol); err != nil {
			http.Error(w, `{"error":"failed to persist extension"}`, http.StatusInternalServerError)
			return
		}
	}
	h.tryTrigger()
	h.broker.BroadcastEffectiveStatusChanged("tag", tagID)

	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(api.ExtendAccessResponse{
		Status: "extended", ExpiresAt: expiresAt.UTC().Format(time.RFC3339), Minutes: req.Minutes,
	})
}

func (h *Handlers) CancelTagExtension(w http.ResponseWriter, r *http.Request) {
	tagID := r.PathValue("id")
	polID := "pol_extend_tag_" + tagID
	if _, exists := h.polEng.GetPolicy(polID); !exists {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	h.polEng.DeletePolicy(polID)
	if h.store != nil {
		_ = h.store.DeletePolicy(polID)
	}
	h.tryTrigger()
	h.broker.BroadcastEffectiveStatusChanged("tag", tagID)
	w.WriteHeader(http.StatusNoContent)
}

// GetDeviceEffectiveStatus computes the real-time enforcement status for a device.
func (h *Handlers) GetDeviceEffectiveStatus(w http.ResponseWriter, r *http.Request) {
	pdid := r.PathValue("pdid")
	d := h.cache.Get(pdid)
	if d == nil {
		http.Error(w, `{"error":"device not found"}`, http.StatusNotFound)
		return
	}
	res := h.computeDeviceEffectiveStatus(d)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(res)
}

func (h *Handlers) computeDeviceEffectiveStatus(d *liasSync.LocalDevice) api.EffectiveStatusResponse {
	res := api.EffectiveStatusResponse{}
	if d == nil {
		return res
	}

	if d.HasTag("infrastructure") {
		res.Action = models.ActionAllow
		res.Source = api.EffectiveSourceInfrastructure
		return res
	}

	if gp, ok := h.polEng.GetPolicy("global_default"); ok && gp.Enabled {
		if gp.Action == models.ActionBlock {
			res.Action = models.ActionBlock
			res.Source = api.EffectiveSourceGlobal
			return res
		}
		if gp.Action == models.ActionAllow {
			res.Action = models.ActionAllow
			res.Source = api.EffectiveSourceGlobal
			res.PauseAvailable = true
			return res
		}
	}

	pols := h.polEng.ListPolicies()
	var activeExt *models.Policy
	var activePause *models.Policy

	for _, p := range pols {
		if !p.Enabled || p.TargetID != d.PDID {
			continue
		}
		if p.Type == models.PolicyTypeDevice {
			if p.ID == "pol_extend_device_"+d.PDID {
				pCopy := p
				activeExt = &pCopy
			}
			if p.ID == "pol_pause_"+d.PDID {
				pCopy := p
				activePause = &pCopy
			}
		}
	}

	if activeExt != nil {
		res.Action = models.ActionAllow
		res.Source = api.EffectiveSourceDevicePolicy
		if activeExt.ExpiresAt != nil {
			minsLeft := int(time.Until(*activeExt.ExpiresAt).Minutes())
			if minsLeft < 0 {
				minsLeft = 0
			}
			res.ActiveExtension = &api.ExtensionInfo{
				ExpiresAt:   activeExt.ExpiresAt.UTC().Format(time.RFC3339),
				MinutesLeft: minsLeft,
				ReasonTag:   activeExt.ReasonTag,
			}
		}
		return res
	}

	if activePause != nil {
		res.Action = models.ActionBlock
		res.Source = api.EffectiveSourceDevicePolicy
		res.ExtendAvailable = true
		if activePause.ExpiresAt != nil {
			minsLeft := int(time.Until(*activePause.ExpiresAt).Minutes())
			if minsLeft < 0 {
				minsLeft = 0
			}
			res.ActiveExtension = &api.ExtensionInfo{
				ExpiresAt:   activePause.ExpiresAt.UTC().Format(time.RFC3339),
				MinutesLeft: minsLeft,
				ReasonTag:   activePause.ReasonTag,
			}
		}
		return res
	}

	pol := h.polEng.GetEffectivePolicy(d)
	if pol.Action == models.ActionSchedule {
		res.Action = h.schedEng.EvaluateBundle(pol.GetScheduleIDs())
		res.Source = api.EffectiveSourceSchedule
	} else {
		res.Action = pol.Action
		if pol.Type == models.PolicyTypeDevice {
			res.Source = api.EffectiveSourceDevicePolicy
		} else if pol.Type == models.PolicyTypeTag {
			res.Source = api.EffectiveSourceTagPolicy
		} else {
			res.Source = api.EffectiveSourceFallback
		}
	}

	if res.Action == models.ActionBlock {
		res.ExtendAvailable = true
	} else {
		res.PauseAvailable = true
	}
	return res
}

// GetTagEffectiveStatus computes the real-time enforcement status for a tag group.
func (h *Handlers) GetTagEffectiveStatus(w http.ResponseWriter, r *http.Request) {
	tagID := r.PathValue("id")
	var exists bool
	for _, t := range h.tagMgr.List() {
		if t.ID == tagID {
			exists = true
			break
		}
	}
	if !exists {
		http.Error(w, `{"error":"tag not found"}`, http.StatusNotFound)
		return
	}

	res := h.computeTagEffectiveStatus(tagID)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(res)
}

func (h *Handlers) computeTagEffectiveStatus(tagID string) api.EffectiveStatusResponse {
	res := api.EffectiveStatusResponse{}
	if tagID == "infrastructure" {
		res.Action = models.ActionAllow
		res.Source = api.EffectiveSourceInfrastructure
		return res
	}
	if gp, ok := h.polEng.GetPolicy("global_default"); ok && gp.Enabled {
		if gp.Action == models.ActionBlock {
			res.Action = models.ActionBlock
			res.Source = api.EffectiveSourceGlobal
			return res
		}
		if gp.Action == models.ActionAllow {
			res.Action = models.ActionAllow
			res.Source = api.EffectiveSourceGlobal
			return res
		}
	}
	best, ok := h.polEng.GetEffectiveTagPolicy(tagID)
	if ok {
		if best.Action == models.ActionSchedule {
			if len(best.GetScheduleIDs()) == 0 {
				res.Action = models.ActionBlock
			} else {
				res.Action = h.schedEng.EvaluateBundle(best.GetScheduleIDs())
			}
			res.Source = api.EffectiveSourceSchedule
		} else {
			res.Action = best.Action
			res.Source = api.EffectiveSourceTagPolicy
		}
		if best.ReasonTag == "extend_access" && best.ExpiresAt != nil {
			mins := int(time.Until(*best.ExpiresAt).Minutes())
			if mins < 0 {
				mins = 0
			}
			res.ActiveExtension = &api.ExtensionInfo{ExpiresAt: best.ExpiresAt.UTC().Format(time.RFC3339), MinutesLeft: mins, ReasonTag: best.ReasonTag}
		}
	} else if gp, ok := h.polEng.GetPolicy("global_default"); ok && gp.Enabled && gp.Action == models.ActionSchedule {
		res.Action = h.schedEng.EvaluateBundle(gp.GetScheduleIDs())
		res.Source = api.EffectiveSourceSchedule
	} else {
		res.Action = models.ActionAllow
		res.Source = api.EffectiveSourceFallback
	}
	if res.Action == models.ActionBlock {
		res.ExtendAvailable = true
	}
	return res
}

func (h *Handlers) ToggleVacationMode(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Enabled bool `json:"enabled"`
	}
	if _, err := decodeAndMarshalGatewayJSON(w, r, &req, false); err != nil {
		http.Error(w, `{"error":"invalid request"}`, http.StatusBadRequest)
		return
	}

	globalPol, exists := h.polEng.GetPolicy("global_default")
	if !exists {
		globalPol = models.Policy{ID: "global_default", Name: "Global Access Switch", Type: models.PolicyTypeGlobal, Priority: 0, Enabled: true}
	}

	if req.Enabled {
		globalPol.Action = models.ActionBlock
	} else {
		globalPol.Action = models.ActionSchedule
	}

	h.polEng.UpsertPolicy(globalPol)
	if h.store != nil {
		_ = h.store.SavePolicy(globalPol)
	}
	h.tryTrigger()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]bool{"vacation_mode": req.Enabled})
}

func (h *Handlers) RenameDevice(w http.ResponseWriter, r *http.Request) {
	pdid := r.PathValue("pdid")
	var req struct {
		Name string `json:"name"`
	}
	if _, err := decodeAndMarshalGatewayJSON(w, r, &req, false); err != nil {
		http.Error(w, `{"error":"invalid request"}`, http.StatusBadRequest)
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if h.cache.Get(pdid) == nil {
		writeJSON(w, http.StatusNotFound, api.ErrorResponse{Error: "device_not_found", Code: "device_not_found"})
		return
	}
	if req.Name == "" || len(req.Name) > 128 {
		writeJSON(w, http.StatusBadRequest, api.ErrorResponse{Error: "invalid_name", Code: "invalid_name"})
		return
	}

	if h.store != nil {
		if err := h.store.SaveDeviceOverride(pdid, req.Name); err != nil {
			http.Error(w, `{"error":"failed to save rename"}`, http.StatusInternalServerError)
			return
		}
	}

	d := h.cache.Get(pdid)
	if d != nil {
		h.cache.SetFriendlyName(pdid, req.Name)
	}

	h.tryTrigger()
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handlers) CreateUser(w http.ResponseWriter, r *http.Request) {
	var u models.User
	if _, err := decodeAndMarshalGatewayJSON(w, r, &u, false); err != nil {
		writeJSON(w, http.StatusBadRequest, api.ErrorResponse{Error: "invalid_request", Code: "invalid_request"})
		return
	}
	u.Name = strings.TrimSpace(u.Name)
	u.ID = strings.TrimSpace(u.ID)
	if u.Name == "" || len(u.Name) > 128 || len(u.ID) > 128 {
		writeJSON(w, http.StatusBadRequest, api.ErrorResponse{Error: "invalid_user", Code: "invalid_user", Details: "name is required and limited to 128 characters"})
		return
	}
	if u.ID == "" {
		u.ID = "user_" + generateID()
	}

	if h.store != nil {
		if err := h.store.SaveUser(u); err != nil {
			http.Error(w, `{"error":"failed to save user"}`, http.StatusInternalServerError)
			return
		}
	}
	h.usersMu.Lock()
	h.users[u.ID] = u
	h.usersMu.Unlock()
	h.cache.BumpRevision()
	writeJSON(w, http.StatusCreated, u)
}

func (h *Handlers) ListUsers(w http.ResponseWriter, _ *http.Request) {
	h.usersMu.RLock()
	users := make([]models.User, 0, len(h.users))
	for _, user := range h.users {
		users = append(users, user)
	}
	h.usersMu.RUnlock()
	sort.Slice(users, func(i, j int) bool {
		if users[i].Name == users[j].Name {
			return users[i].ID < users[j].ID
		}
		return users[i].Name < users[j].Name
	})
	writeJSON(w, http.StatusOK, users)
}

func (h *Handlers) GetUser(w http.ResponseWriter, r *http.Request) {
	h.usersMu.RLock()
	user, exists := h.users[r.PathValue("id")]
	h.usersMu.RUnlock()
	if !exists {
		writeJSON(w, http.StatusNotFound, api.ErrorResponse{Error: "user_not_found", Code: "user_not_found"})
		return
	}
	writeJSON(w, http.StatusOK, user)
}

func (h *Handlers) UpdateUser(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var request models.User
	if _, err := decodeAndMarshalGatewayJSON(w, r, &request, false); err != nil {
		writeJSON(w, http.StatusBadRequest, api.ErrorResponse{Error: "invalid_request", Code: "invalid_request"})
		return
	}
	request.ID = id
	request.Name = strings.TrimSpace(request.Name)
	if request.Name == "" || len(request.Name) > 128 {
		writeJSON(w, http.StatusBadRequest, api.ErrorResponse{Error: "invalid_user", Code: "invalid_user"})
		return
	}
	h.usersMu.RLock()
	_, exists := h.users[id]
	h.usersMu.RUnlock()
	if !exists {
		writeJSON(w, http.StatusNotFound, api.ErrorResponse{Error: "user_not_found", Code: "user_not_found"})
		return
	}
	if h.store != nil {
		if err := h.store.SaveUser(request); err != nil {
			writeJSON(w, http.StatusInternalServerError, api.ErrorResponse{Error: "storage_error", Code: "storage_error"})
			return
		}
	}
	h.usersMu.Lock()
	h.users[id] = request
	h.usersMu.Unlock()
	h.cache.BumpRevision()
	writeJSON(w, http.StatusOK, request)
}

func (h *Handlers) DeleteUser(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	h.usersMu.RLock()
	_, exists := h.users[id]
	h.usersMu.RUnlock()
	if !exists {
		writeJSON(w, http.StatusNotFound, api.ErrorResponse{Error: "user_not_found", Code: "user_not_found"})
		return
	}
	assigned := false
	for _, device := range h.cache.List() {
		if device.UserID == id {
			assigned = true
			break
		}
	}
	if assigned {
		writeJSON(w, http.StatusConflict, api.ErrorResponse{Error: "user_is_assigned", Code: "user_is_assigned"})
		return
	}
	if h.store != nil {
		if err := h.store.DeleteUserIfUnassigned(id); err != nil {
			if errors.Is(err, storage.ErrUserAssigned) {
				writeJSON(w, http.StatusConflict, api.ErrorResponse{Error: "user_is_assigned", Code: "user_is_assigned"})
				return
			}
			writeJSON(w, http.StatusInternalServerError, api.ErrorResponse{Error: "storage_error", Code: "storage_error"})
			return
		}
	}
	h.usersMu.Lock()
	delete(h.users, id)
	h.usersMu.Unlock()
	h.cache.BumpRevision()
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handlers) AssignDeviceUser(w http.ResponseWriter, r *http.Request) {
	pdid := r.PathValue("pdid")
	var req struct {
		UserID string `json:"user_id"`
	}
	if _, err := decodeAndMarshalGatewayJSON(w, r, &req, false); err != nil {
		writeJSON(w, http.StatusBadRequest, api.ErrorResponse{Error: "invalid_request", Code: "invalid_request"})
		return
	}
	if h.cache.Get(pdid) == nil {
		writeJSON(w, http.StatusNotFound, api.ErrorResponse{Error: "device_not_found", Code: "device_not_found"})
		return
	}
	if req.UserID == "" {
		h.unassignDeviceUser(w, pdid)
		return
	}
	h.usersMu.RLock()
	_, userExists := h.users[req.UserID]
	h.usersMu.RUnlock()
	if !userExists {
		writeJSON(w, http.StatusNotFound, api.ErrorResponse{Error: "user_not_found", Code: "user_not_found"})
		return
	}

	if h.store != nil {
		if err := h.store.AssignDeviceToUser(pdid, req.UserID); err != nil {
			if errors.Is(err, storage.ErrUserNotFound) {
				writeJSON(w, http.StatusNotFound, api.ErrorResponse{Error: "user_not_found", Code: "user_not_found"})
				return
			}
			http.Error(w, `{"error":"failed to map user"}`, http.StatusInternalServerError)
			return
		}
	}
	h.cache.SetUserID(pdid, req.UserID)
	h.tryTrigger()
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handlers) UnassignDeviceUser(w http.ResponseWriter, r *http.Request) {
	pdid := r.PathValue("pdid")
	if h.cache.Get(pdid) == nil {
		writeJSON(w, http.StatusNotFound, api.ErrorResponse{Error: "device_not_found", Code: "device_not_found"})
		return
	}
	h.unassignDeviceUser(w, pdid)
}

func (h *Handlers) unassignDeviceUser(w http.ResponseWriter, pdid string) {
	if h.store != nil {
		if err := h.store.UnassignDeviceUser(pdid); err != nil {
			writeJSON(w, http.StatusInternalServerError, api.ErrorResponse{Error: "storage_error", Code: "storage_error"})
			return
		}
	}
	h.cache.SetUserID(pdid, "")
	h.tryTrigger()
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handlers) ListTags(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(h.tagMgr.List())
}

func (h *Handlers) CreateTag(w http.ResponseWriter, r *http.Request) {
	var t tags.Tag
	if _, err := decodeAndMarshalGatewayJSON(w, r, &t, false); err != nil {
		http.Error(w, `{"error":"invalid request"}`, http.StatusBadRequest)
		return
	}
	created, err := h.tagMgr.Create(t.Name, t.Color)
	if err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusBadRequest)
		return
	}

	if h.store != nil {
		if err := h.store.SaveTag(created); err != nil {
			http.Error(w, `{"error":"failed to persist tag to storage"}`, http.StatusInternalServerError)
			return
		}
	}
	h.tryTrigger()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(created)
}

func (h *Handlers) UpdateTag(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var t tags.Tag
	if _, err := decodeAndMarshalGatewayJSON(w, r, &t, false); err != nil {
		http.Error(w, `{"error":"invalid request"}`, http.StatusBadRequest)
		return
	}

	updated, err := h.tagMgr.Update(id, t.Name, t.Color)
	if err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusBadRequest)
		return
	}

	if h.store != nil {
		if err := h.store.SaveTag(updated); err != nil {
			http.Error(w, `{"error":"failed to update tag in storage"}`, http.StatusInternalServerError)
			return
		}
	}
	h.tryTrigger()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(updated)
}

func (h *Handlers) DeleteTag(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := h.tagMgr.Delete(id); err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusBadRequest)
		return
	}

	if h.store != nil {
		if err := h.store.DeleteTag(id); err != nil {
			http.Error(w, `{"error":"failed to delete tag from storage"}`, http.StatusInternalServerError)
			return
		}
	}
	h.tryTrigger()
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handlers) ListPolicies(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(h.polEng.ListPolicies())
}

func (h *Handlers) ExportPolicies(w http.ResponseWriter, r *http.Request) {
	if h.store == nil {
		http.Error(w, `{"error":"storage unavailable"}`, http.StatusServiceUnavailable)
		return
	}
	data, err := h.store.ExportPolicies()
	if err != nil {
		http.Error(w, `{"error":"failed to export policies"}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", "attachment; filename=lias_policies_export.json")
	w.Write(data)
}

func (h *Handlers) ImportPolicies(w http.ResponseWriter, r *http.Request) {
	if h.store == nil {
		http.Error(w, `{"error":"storage unavailable"}`, http.StatusServiceUnavailable)
		return
	}

	var policies []models.Policy
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&policies); err != nil {
		writeJSON(w, http.StatusBadRequest, api.ErrorResponse{Error: "invalid_policy_import", Code: "invalid_policy_import"})
		return
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		writeJSON(w, http.StatusBadRequest, api.ErrorResponse{Error: "invalid_policy_import", Code: "invalid_policy_import"})
		return
	}
	for _, policy := range policies {
		if policy.ID == "" || len(policy.ID) > 128 || len(policy.Name) > 256 ||
			(policy.Type != models.PolicyTypeGlobal && policy.Type != models.PolicyTypeTag && policy.Type != models.PolicyTypeDevice) ||
			(policy.Action != models.ActionAllow && policy.Action != models.ActionBlock && policy.Action != models.ActionSchedule) {
			writeJSON(w, http.StatusBadRequest, api.ErrorResponse{Error: "invalid_policy_import", Code: "invalid_policy_import", Details: "entire import must contain valid policies"})
			return
		}
	}
	data, err := json.Marshal(policies)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, api.ErrorResponse{Error: "invalid_policy_import", Code: "invalid_policy_import"})
		return
	}
	if err := h.store.ImportPolicies(data); err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusBadRequest)
		return
	}

	for _, p := range policies {
		h.polEng.UpsertPolicy(p)
	}

	h.tryTrigger()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "import successful"})
}

func (h *Handlers) validateAndMergePolicySchedules(p *models.Policy) ([]scheduleconflict.Conflict, error) {
	if p.Action != models.ActionSchedule {
		return nil, nil
	}
	schedIDs := p.GetScheduleIDs()
	if len(schedIDs) == 0 {
		if p.ID == "global_default" {
			return nil, nil
		}
		return nil, httpError{status: http.StatusBadRequest, msg: "schedule policy requires at least one schedule"}
	}
	var scheds []models.Schedule
	for _, sid := range schedIDs {
		sch, ok := h.schedEng.GetSchedule(sid)
		if !ok {
			return nil, httpError{status: http.StatusBadRequest, msg: "referenced schedule '" + sid + "' does not exist"}
		}
		scheds = append(scheds, sch)
	}
	_, conflicts, err := scheduleconflict.MergeSchedules(scheds)
	if err != nil && len(conflicts) == 0 {
		return nil, httpError{status: http.StatusBadRequest, msg: err.Error()}
	}
	return conflicts, err
}

type httpError struct {
	status int
	msg    string
}

func (e httpError) Error() string { return e.msg }

func toAPIConflicts(sc []scheduleconflict.Conflict) []api.Conflict {
	if len(sc) == 0 {
		return []api.Conflict{}
	}
	out := make([]api.Conflict, len(sc))
	for i, c := range sc {
		out[i] = api.Conflict{
			ScheduleAID: c.ScheduleAID, ScheduleAName: c.ScheduleAName, ScheduleBID: c.ScheduleBID, ScheduleBName: c.ScheduleBName,
			Day: c.Day, OverlapStart: c.OverlapStart, OverlapEnd: c.OverlapEnd, ActionA: c.ActionA, ActionB: c.ActionB,
		}
	}
	return out
}

func (h *Handlers) ValidatePolicy(w http.ResponseWriter, r *http.Request) {
	var req api.PolicyValidateRequest
	if _, err := decodeAndMarshalGatewayJSON(w, r, &req, false); err != nil {
		http.Error(w, `{"error":"invalid request"}`, http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if len(req.ScheduleIDs) == 0 {
		_ = json.NewEncoder(w).Encode(api.ConflictResponse{Conflicts: []api.Conflict{}})
		return
	}
	var scheds []models.Schedule
	for _, sid := range req.ScheduleIDs {
		sch, ok := h.schedEng.GetSchedule(sid)
		if !ok {
			http.Error(w, `{"error":"referenced schedule '`+sid+`' does not exist"}`, http.StatusBadRequest)
			return
		}
		scheds = append(scheds, sch)
	}
	_, conflicts, err := scheduleconflict.MergeSchedules(scheds)
	if err != nil && len(conflicts) == 0 {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusBadRequest)
		return
	}
	_ = json.NewEncoder(w).Encode(api.ConflictResponse{Conflicts: toAPIConflicts(conflicts)})
}

func (h *Handlers) CreatePolicy(w http.ResponseWriter, r *http.Request) {
	var p models.Policy
	if _, err := decodeAndMarshalGatewayJSON(w, r, &p, false); err != nil {
		http.Error(w, `{"error":"invalid request"}`, http.StatusBadRequest)
		return
	}
	if p.ID == "" {
		p.ID = "pol_" + generateID()
	}
	if p.Type == models.PolicyTypeTag && p.TargetID == "infrastructure" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "policy_immutable_target", "message": "The 'infrastructure' tag is super-immutable."})
		return
	}

	conflicts, err := h.validateAndMergePolicySchedules(&p)
	if err != nil && len(conflicts) == 0 {
		if hErr, ok := err.(httpError); ok {
			http.Error(w, `{"error":"`+hErr.msg+`"}`, hErr.status)
			return
		}
		http.Error(w, `{"error":"invalid schedule bundle"}`, http.StatusBadRequest)
		return
	}
	if len(conflicts) > 0 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		_ = json.NewEncoder(w).Encode(api.ConflictResponse{Error: "schedule_conflict", Message: "Attached schedules contain contradictory windows", Conflicts: toAPIConflicts(conflicts)})
		return
	}

	h.polEng.UpsertPolicy(p)
	if h.store != nil {
		if err := h.store.SavePolicy(p); err != nil {
			http.Error(w, `{"error":"failed to persist policy to storage"}`, http.StatusInternalServerError)
			return
		}
	}
	h.tryTrigger()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(p)
}

func (h *Handlers) UpdatePolicy(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var p models.Policy
	if _, err := decodeAndMarshalGatewayJSON(w, r, &p, false); err != nil {
		http.Error(w, `{"error":"invalid request"}`, http.StatusBadRequest)
		return
	}
	p.ID = id

	// V3.4 Fix: Strictly enforce enabled state for global policy to fix hierarchy reset bug
	if p.ID == "global_default" {
		p.Enabled = true
	}

	if p.Type == models.PolicyTypeTag && p.TargetID == "infrastructure" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "policy_immutable_target", "message": "The 'infrastructure' tag is super-immutable."})
		return
	}

	conflicts, err := h.validateAndMergePolicySchedules(&p)
	if err != nil && len(conflicts) == 0 {
		if hErr, ok := err.(httpError); ok {
			http.Error(w, `{"error":"`+hErr.msg+`"}`, hErr.status)
			return
		}
		http.Error(w, `{"error":"invalid schedule bundle"}`, http.StatusBadRequest)
		return
	}
	if len(conflicts) > 0 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		_ = json.NewEncoder(w).Encode(api.ConflictResponse{Error: "schedule_conflict", Message: "Attached schedules contain contradictory windows", Conflicts: toAPIConflicts(conflicts)})
		return
	}

	h.polEng.UpsertPolicy(p)
	if h.store != nil {
		if err := h.store.SavePolicy(p); err != nil {
			http.Error(w, `{"error":"failed to update policy in storage"}`, http.StatusInternalServerError)
			return
		}
	}
	h.tryTrigger()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(p)
}

func (h *Handlers) DeletePolicy(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	h.polEng.DeletePolicy(id)
	if h.store != nil {
		if err := h.store.DeletePolicy(id); err != nil {
			http.Error(w, `{"error":"failed to delete policy from storage"}`, http.StatusInternalServerError)
			return
		}
	}
	h.tryTrigger()
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handlers) ListSchedules(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(h.schedEng.ListSchedules())
}

func isSupportedTimezone(tz string) bool {
	if tz == "" {
		return false
	}
	_, err := time.LoadLocation(tz)
	return err == nil
}

func validScheduleDay(day string) bool {
	switch strings.ToLower(strings.TrimSpace(day)) {
	case "sun", "sunday", "mon", "monday", "tue", "tuesday", "wed", "wednesday", "thu", "thursday", "fri", "friday", "sat", "saturday":
		return true
	default:
		return false
	}
}

func validateScheduleRules(s *models.Schedule) error {
	if s.Mode != models.ScheduleModeDowntime && s.Mode != models.ScheduleModeWhitelist {
		return fmt.Errorf("invalid schedule mode %q", s.Mode)
	}
	for i, rule := range s.Rules {
		if rule.Action != models.ActionAllow && rule.Action != models.ActionBlock {
			return fmt.Errorf("rule %d: action must be allow or block", i+1)
		}
		hasStartDate, hasEndDate := rule.StartDate != "", rule.EndDate != ""
		if hasStartDate != hasEndDate {
			return fmt.Errorf("rule %d: start_date and end_date must be provided together", i+1)
		}
		if !hasStartDate {
			if len(rule.Days) == 0 {
				return fmt.Errorf("rule %d: days must be non-empty if calendar dates are not specified", i+1)
			}
			for _, day := range rule.Days {
				if !validScheduleDay(day) {
					return fmt.Errorf("rule %d: invalid day %q", i+1, day)
				}
			}
		}
		if rule.StartTime == rule.EndTime {
			return fmt.Errorf("rule %d: start_time and end_time cannot be identical", i+1)
		}
		if _, err := time.Parse("15:04", rule.StartTime); err != nil {
			return fmt.Errorf("rule %d: invalid start_time format %q", i+1, rule.StartTime)
		}
		if _, err := time.Parse("15:04", rule.EndTime); err != nil {
			return fmt.Errorf("rule %d: invalid end_time format %q", i+1, rule.EndTime)
		}
		if hasStartDate {
			startDate, err := time.Parse("2006-01-02", rule.StartDate)
			if err != nil {
				return fmt.Errorf("rule %d: invalid start_date format %q", i+1, rule.StartDate)
			}
			endDate, err := time.Parse("2006-01-02", rule.EndDate)
			if err != nil {
				return fmt.Errorf("rule %d: invalid end_date format %q", i+1, rule.EndDate)
			}
			if endDate.Before(startDate) {
				return fmt.Errorf("rule %d: end_date cannot be before start_date", i+1)
			}
		}
	}
	return nil
}

func (h *Handlers) CreateSchedule(w http.ResponseWriter, r *http.Request) {
	var s models.Schedule
	if _, err := decodeAndMarshalGatewayJSON(w, r, &s, false); err != nil {
		http.Error(w, `{"error":"invalid request"}`, http.StatusBadRequest)
		return
	}
	if s.ID == "" {
		s.ID = "sched_" + generateID()
	}
	if s.Mode == "" {
		hasAllow := false
		for _, r := range s.Rules {
			if r.Action == models.ActionAllow {
				hasAllow = true
				break
			}
		}
		if hasAllow {
			s.Mode = models.ScheduleModeWhitelist
		} else {
			s.Mode = models.ScheduleModeDowntime
		}
	}
	if err := validateScheduleRules(&s); err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusBadRequest)
		return
	}
	if !isSupportedTimezone(s.Timezone) {
		http.Error(w, `{"error":"unsupported or invalid timezone"}`, http.StatusBadRequest)
		return
	}
	_, conflicts, err := scheduleconflict.MergeSchedules([]models.Schedule{s})
	if err != nil || len(conflicts) > 0 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		_ = json.NewEncoder(w).Encode(api.ConflictResponse{Error: "schedule_conflict", Message: "Schedule rules contain internal contradictory windows", Conflicts: toAPIConflicts(conflicts)})
		return
	}
	h.schedEng.UpsertSchedule(s)
	if h.store != nil {
		if err := h.store.SaveSchedule(s); err != nil {
			http.Error(w, `{"error":"failed to persist schedule to storage"}`, http.StatusInternalServerError)
			return
		}
	}
	h.tryTrigger()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(s)
}

func (h *Handlers) UpdateSchedule(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var s models.Schedule
	if _, err := decodeAndMarshalGatewayJSON(w, r, &s, false); err != nil {
		http.Error(w, `{"error":"invalid request"}`, http.StatusBadRequest)
		return
	}
	s.ID = id
	if s.Mode == "" {
		hasAllow := false
		for _, r := range s.Rules {
			if r.Action == models.ActionAllow {
				hasAllow = true
				break
			}
		}
		if hasAllow {
			s.Mode = models.ScheduleModeWhitelist
		} else {
			s.Mode = models.ScheduleModeDowntime
		}
	}
	if err := validateScheduleRules(&s); err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusBadRequest)
		return
	}
	if !isSupportedTimezone(s.Timezone) {
		http.Error(w, `{"error":"unsupported or invalid timezone"}`, http.StatusBadRequest)
		return
	}
	_, conflicts, err := scheduleconflict.MergeSchedules([]models.Schedule{s})
	if err != nil || len(conflicts) > 0 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		_ = json.NewEncoder(w).Encode(api.ConflictResponse{Error: "schedule_conflict", Message: "Schedule rules contain internal contradictory windows", Conflicts: toAPIConflicts(conflicts)})
		return
	}
	h.schedEng.UpsertSchedule(s)
	if h.store != nil {
		if err := h.store.SaveSchedule(s); err != nil {
			http.Error(w, `{"error":"failed to update schedule in storage"}`, http.StatusInternalServerError)
			return
		}
	}
	h.tryTrigger()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(s)
}

func (h *Handlers) DeleteSchedule(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	h.schedEng.DeleteSchedule(id)
	if h.store != nil {
		if err := h.store.DeleteSchedule(id); err != nil {
			http.Error(w, `{"error":"failed to delete schedule from storage"}`, http.StatusInternalServerError)
			return
		}
	}
	h.tryTrigger()
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handlers) GetNetworkStats(w http.ResponseWriter, r *http.Request) {
	if h.store == nil {
		http.Error(w, `{"error":"storage unavailable"}`, http.StatusServiceUnavailable)
		return
	}
	stats, err := h.store.GetNetworkStats()
	if err != nil {
		http.Error(w, `{"error":"failed to fetch stats"}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(stats)
}

func (h *Handlers) FlushNftables(w http.ResponseWriter, r *http.Request) {
	if err := h.nftCtrl.FlushTable(); err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func generateID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func AuthMiddleware(token string, next http.Handler) http.Handler {
	return AuthMiddlewareWithSessions(token, nil, next)
}

func AuthMiddlewareWithSessions(token string, sessions *browserSessionManager, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if token == "" {
			next.ServeHTTP(w, r)
			return
		}
		authHeader := r.Header.Get("Authorization")
		parts := strings.SplitN(authHeader, " ", 2)
		providedDigest := sha256.Sum256(nil)
		if len(parts) == 2 {
			providedDigest = sha256.Sum256([]byte(parts[1]))
		}
		expectedDigest := sha256.Sum256([]byte(token))
		if len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") && subtle.ConstantTimeCompare(providedDigest[:], expectedDigest[:]) == 1 {
			next.ServeHTTP(w, r)
			return
		}
		if sessions != nil && sessions.authenticate(r) {
			if isMutatingMethod(r.Method) && !sessions.validateCSRF(r) {
				http.Error(w, `{"error":"invalid or missing CSRF token"}`, http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
			return
		}
		if authHeader == "" {
			http.Error(w, `{"error":"missing authorization"}`, http.StatusUnauthorized)
			return
		}
		http.Error(w, `{"error":"invalid or malformed authorization token"}`, http.StatusUnauthorized)
	})
}

type jsonErrorResponseWriter struct{ http.ResponseWriter }

func (w jsonErrorResponseWriter) WriteHeader(status int) {
	if status >= 400 {
		w.Header().Set("Content-Type", "application/json")
	}
	w.ResponseWriter.WriteHeader(status)
}

func (w jsonErrorResponseWriter) Flush() {
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

func jsonErrorContentTypeMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(jsonErrorResponseWriter{ResponseWriter: w}, r)
	})
}
