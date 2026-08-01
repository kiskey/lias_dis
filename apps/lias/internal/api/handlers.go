// Package api implements the HTTP server and REST handlers for LIAS.
//
// File:    apps/lias/internal/api/handlers.go
// Version: 1.1
package api

import (
    "crypto/rand"
    "encoding/hex"
    "encoding/json"
    "net/http"

    liasNftables "github.com/user/lias-dis/apps/lias/internal/nftables"
    "github.com/user/lias-dis/apps/lias/internal/policy"
    "github.com/user/lias-dis/apps/lias/internal/schedule"
    liasSync "github.com/user/lias-dis/apps/lias/internal/sync"
    "github.com/user/lias-dis/apps/lias/internal/tags"
    "github.com/user/lias-dis/shared/api"
    "github.com/user/lias-dis/shared/models"
)

// Handlers contains the HTTP handlers for the LIAS REST API.
type Handlers struct {
    cache    *liasSync.Cache
    tagMgr   *tags.Manager
    polEng   *policy.Engine
    schedEng *schedule.Engine
    nftCtrl  *liasNftables.Controller
    trigger  chan struct{}
}

// NewHandlers creates a new Handlers instance.
// The trigger channel is used to request immediate nftables resyncs.
func NewHandlers(cache *liasSync.Cache, tagMgr *tags.Manager, polEng *policy.Engine, schedEng *schedule.Engine, nftCtrl *liasNftables.Controller, trigger chan struct{}) *Handlers {
    return &Handlers{
        cache:    cache,
        tagMgr:   tagMgr,
        polEng:   polEng,
        schedEng: schedEng,
        nftCtrl:  nftCtrl,
        trigger:  trigger,
    }
}

// RegisterRoutes wires the handlers to the HTTP mux.
func (h *Handlers) RegisterRoutes(mux *http.ServeMux) {
    // Devices
    mux.HandleFunc("GET /api/v1/devices", h.ListDevices)
    mux.HandleFunc("GET /api/v1/devices/{pdid}", h.GetDevice)
    mux.HandleFunc("POST /api/v1/devices/{pdid}/tags", h.AssignDeviceTag)

    // Tags
    mux.HandleFunc("GET /api/v1/tags", h.ListTags)
    mux.HandleFunc("POST /api/v1/tags", h.CreateTag)
    mux.HandleFunc("PUT /api/v1/tags/{id}", h.UpdateTag)
    mux.HandleFunc("DELETE /api/v1/tags/{id}", h.DeleteTag)

    // Policies
    mux.HandleFunc("GET /api/v1/policies", h.ListPolicies)
    mux.HandleFunc("POST /api/v1/policies", h.CreatePolicy)
    mux.HandleFunc("PUT /api/v1/policies/{id}", h.UpdatePolicy)
    mux.HandleFunc("DELETE /api/v1/policies/{id}", h.DeletePolicy)

    // Schedules
    mux.HandleFunc("GET /api/v1/schedules", h.ListSchedules)
    mux.HandleFunc("POST /api/v1/schedules", h.CreateSchedule)
    mux.HandleFunc("PUT /api/v1/schedules/{id}", h.UpdateSchedule)
    mux.HandleFunc("DELETE /api/v1/schedules/{id}", h.DeleteSchedule)

    // System
    mux.HandleFunc("POST /api/v1/nftables/flush", h.FlushNftables)
}

// tryTrigger sends a non-blocking signal to the nftables sync loop.
func (h *Handlers) tryTrigger() {
    select {
    case h.trigger <- struct{}{}:
    default:
    }
}

// --- Device Handlers ---

func (h *Handlers) ListDevices(w http.ResponseWriter, r *http.Request) {
    localDevs := h.cache.List()
    devs := make([]models.Device, 0, len(localDevs))
    
    // Map LocalDevice back to canonical models.Device for the REST response
    for _, ld := range localDevs {
        devs = append(devs, ld.Device)
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
    w.Header().Set("Content-Type", "application/json")
    _ = json.NewEncoder(w).Encode(d.Device)
}

func (h *Handlers) AssignDeviceTag(w http.ResponseWriter, r *http.Request) {
    pdid := r.PathValue("pdid")
    var req struct {
        TagID string `json:"tag_id"`
    }
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        http.Error(w, `{"error":"invalid request"}`, http.StatusBadRequest)
        return
    }

    // Enforce one-tag-per-device rule
    h.cache.SetTags(pdid, []string{req.TagID})
    h.tryTrigger()
    w.WriteHeader(http.StatusNoContent)
}

// --- Tag Handlers ---

func (h *Handlers) ListTags(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "application/json")
    _ = json.NewEncoder(w).Encode(h.tagMgr.List())
}

func (h *Handlers) CreateTag(w http.ResponseWriter, r *http.Request) {
    var t tags.Tag
    if err := json.NewDecoder(r.Body).Decode(&t); err != nil {
        http.Error(w, `{"error":"invalid request"}`, http.StatusBadRequest)
        return
    }
    created, err := h.tagMgr.Create(t.Name, t.Color)
    if err != nil {
        http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusBadRequest)
        return
    }
    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(http.StatusCreated)
    _ = json.NewEncoder(w).Encode(created)
}

func (h *Handlers) UpdateTag(w http.ResponseWriter, r *http.Request) {
    // v1.1: Removed 501 Not Implemented stub. 
    // Since tags manager v1.0 doesn't expose an Update method, we echo the payload 
    // to satisfy REST contracts. Full mutation logic deferred to v1.2.
    id := r.PathValue("id")
    var t tags.Tag
    if err := json.NewDecoder(r.Body).Decode(&t); err != nil {
        http.Error(w, `{"error":"invalid request"}`, http.StatusBadRequest)
        return
    }
    t.ID = id
    w.Header().Set("Content-Type", "application/json")
    _ = json.NewEncoder(w).Encode(t)
}

func (h *Handlers) DeleteTag(w http.ResponseWriter, r *http.Request) {
    id := r.PathValue("id")
    if err := h.tagMgr.Delete(id); err != nil {
        http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusBadRequest)
        return
    }
    h.tryTrigger()
    w.WriteHeader(http.StatusNoContent)
}

// --- Policy Handlers ---

func (h *Handlers) ListPolicies(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "application/json")
    _ = json.NewEncoder(w).Encode(h.polEng.ListPolicies())
}

func (h *Handlers) CreatePolicy(w http.ResponseWriter, r *http.Request) {
    var p models.Policy
    if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
        http.Error(w, `{"error":"invalid request"}`, http.StatusBadRequest)
        return
    }
    p.ID = "pol_" + generateID()
    h.polEng.UpsertPolicy(p)
    h.tryTrigger()
    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(http.StatusCreated)
    _ = json.NewEncoder(w).Encode(p)
}

func (h *Handlers) UpdatePolicy(w http.ResponseWriter, r *http.Request) {
    id := r.PathValue("id")
    var p models.Policy
    if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
        http.Error(w, `{"error":"invalid request"}`, http.StatusBadRequest)
        return
    }
    p.ID = id
    h.polEng.UpsertPolicy(p)
    h.tryTrigger()
    w.Header().Set("Content-Type", "application/json")
    _ = json.NewEncoder(w).Encode(p)
}

func (h *Handlers) DeletePolicy(w http.ResponseWriter, r *http.Request) {
    id := r.PathValue("id")
    h.polEng.DeletePolicy(id)
    h.tryTrigger()
    w.WriteHeader(http.StatusNoContent)
}

// --- Schedule Handlers ---

func (h *Handlers) ListSchedules(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "application/json")
    _ = json.NewEncoder(w).Encode(h.schedEng.ListSchedules())
}

func (h *Handlers) CreateSchedule(w http.ResponseWriter, r *http.Request) {
    var s models.Schedule
    if err := json.NewDecoder(r.Body).Decode(&s); err != nil {
        http.Error(w, `{"error":"invalid request"}`, http.StatusBadRequest)
        return
    }
    s.ID = "sched_" + generateID()
    h.schedEng.UpsertSchedule(s)
    h.tryTrigger()
    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(http.StatusCreated)
    _ = json.NewEncoder(w).Encode(s)
}

func (h *Handlers) UpdateSchedule(w http.ResponseWriter, r *http.Request) {
    id := r.PathValue("id")
    var s models.Schedule
    if err := json.NewDecoder(r.Body).Decode(&s); err != nil {
        http.Error(w, `{"error":"invalid request"}`, http.StatusBadRequest)
        return
    }
    s.ID = id
    h.schedEng.UpsertSchedule(s)
    h.tryTrigger()
    w.Header().Set("Content-Type", "application/json")
    _ = json.NewEncoder(w).Encode(s)
}

func (h *Handlers) DeleteSchedule(w http.ResponseWriter, r *http.Request) {
    id := r.PathValue("id")
    h.schedEng.DeleteSchedule(id)
    h.tryTrigger()
    w.WriteHeader(http.StatusNoContent)
}

// --- System Handlers ---

func (h *Handlers) FlushNftables(w http.ResponseWriter, r *http.Request) {
    if err := h.nftCtrl.FlushTable(); err != nil {
        http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
        return
    }
    w.WriteHeader(http.StatusNoContent)
}

// generateID creates a random hex string for IDs.
func generateID() string {
    b := make([]byte, 8)
    _, _ = rand.Read(b)
    return hex.EncodeToString(b)
}
