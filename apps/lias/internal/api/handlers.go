// Package api implements the HTTP server, REST handlers, and SSE broker for LIAS.
//
// File:    apps/lias/internal/api/handlers.go
// Version: 2.3
package api

import (
    "crypto/rand"
    "encoding/hex"
    "encoding/json"
    "fmt"
    "log/slog"
    "net/http"
    "strconv"
    "strings"
    "time"

    liasNftables "github.com/user/lias-dis/apps/lias/internal/nftables"
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
    cache    *liasSync.Cache
    tagMgr   *tags.Manager
    polEng   *policy.Engine
    schedEng *schedule.Engine
    nftCtrl  *liasNftables.Controller
    store    *storage.Storage
    trigger  chan struct{}
    broker   *Broker
}

func NewHandlers(
    cache *liasSync.Cache,
    tagMgr *tags.Manager,
    polEng *policy.Engine,
    schedEng *schedule.Engine,
    nftCtrl *liasNftables.Controller,
    store *storage.Storage,
    trigger chan struct{},
    broker *Broker,
) *Handlers {
    return &Handlers{
        cache:    cache,
        tagMgr:   tagMgr,
        polEng:   polEng,
        schedEng: schedEng,
        nftCtrl:  nftCtrl,
        store:    store,
        trigger:  trigger,
        broker:   broker,
    }
}

func (h *Handlers) RegisterRoutes(mux *http.ServeMux, authToken string) {
    handler := http.NewServeMux()

    handler.HandleFunc("GET /api/v1/devices", h.ListDevices)
    handler.HandleFunc("GET /api/v1/devices/{pdid}", h.GetDevice)
    handler.HandleFunc("POST /api/v1/devices/{pdid}/tags", h.AssignDeviceTag)
    handler.HandleFunc("POST /api/v1/devices/{pdid}/pause", h.PauseDeviceInternet) // UI-FN-06
    handler.HandleFunc("POST /api/v1/devices/{pdid}/rename", h.RenameDevice)       // UI-FN-12
    handler.HandleFunc("POST /api/v1/devices/{pdid}/user", h.AssignDeviceUser)     // SYS-FEAT-03

    handler.HandleFunc("GET /api/v1/tags", h.ListTags)
    handler.HandleFunc("POST /api/v1/tags", h.CreateTag)
    handler.HandleFunc("PUT /api/v1/tags/{id}", h.UpdateTag)
    handler.HandleFunc("DELETE /api/v1/tags/{id}", h.DeleteTag)

    handler.HandleFunc("GET /api/v1/policies", h.ListPolicies)
    handler.HandleFunc("POST /api/v1/policies", h.CreatePolicy)
    handler.HandleFunc("POST /api/v1/policies/validate", h.ValidatePolicy)
    handler.HandleFunc("PUT /api/v1/policies/{id}", h.UpdatePolicy)
    handler.HandleFunc("DELETE /api/v1/policies/{id}", h.DeletePolicy)

    handler.HandleFunc("GET /api/v1/schedules", h.ListSchedules)
    handler.HandleFunc("POST /api/v1/schedules", h.CreateSchedule)
    handler.HandleFunc("PUT /api/v1/schedules/{id}", h.UpdateSchedule)
    handler.HandleFunc("DELETE /api/v1/schedules/{id}", h.DeleteSchedule)
    
    handler.HandleFunc("POST /api/v1/users", h.CreateUser) // SYS-FEAT-03

    handler.HandleFunc("POST /api/v1/nftables/flush", h.FlushNftables)
    handler.HandleFunc("GET /api/v1/events", h.StreamEvents)

    mux.Handle("/", AuthMiddleware(authToken, handler))
}

// PauseDeviceInternet creates a temporary 1-hour block policy for a specific device.
func (h *Handlers) PauseDeviceInternet(w http.ResponseWriter, r *http.Request) {
    pdid := r.PathValue("pdid")
    d := h.cache.Get(pdid)
    if d == nil {
        http.Error(w, `{"error":"device not found"}`, http.StatusNotFound)
        return
    }

    // Create a temporary schedule that blocks for 1 hour
    tempSchedID := "sched_pause_" + generateID()
    now := time.Now()
    tempSched := models.Schedule{
        ID:       tempSchedID,
        Name:     "Temporary Pause",
        Mode:     models.ScheduleModeDowntime,
        Timezone: "UTC",
        Rules: []models.ScheduleRule{
            {
                Days:      []string{"sun", "mon", "tue", "wed", "thu", "fri", "sat"},
                StartTime: now.UTC().Format("15:04"),
                EndTime:   now.UTC().Add(1 * time.Hour).Format("15:04"),
                Action:    models.ActionBlock,
            },
        },
    }
    h.schedEng.UpsertSchedule(tempSched)
    if h.store != nil {
        _ = h.store.SaveSchedule(tempSched)
    }

    // Create or Update a device-specific policy
    polID := "pol_pause_" + pdid
    tempPol := models.Policy{
        ID:          polID,
        Name:        "Paused Internet",
        Type:        models.PolicyTypeDevice,
        TargetID:    pdid,
        Action:      models.ActionSchedule,
        ScheduleIDs: []string{tempSchedID},
        Priority:    1000, // Highest priority
        Enabled:     true,
    }
    h.polEng.UpsertPolicy(tempPol)
    if h.store != nil {
        _ = h.store.SavePolicy(tempPol)
    }

    h.tryTrigger()
    w.WriteHeader(http.StatusAccepted)
    _ = json.NewEncoder(w).Encode(map[string]string{"status": "paused for 1 hour"})
}

// RenameDevice manually overrides a device's friendly name.
func (h *Handlers) RenameDevice(w http.ResponseWriter, r *http.Request) {
    pdid := r.PathValue("pdid")
    var req struct {
        Name string `json:"name"`
    }
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        http.Error(w, `{"error":"invalid request"}`, http.StatusBadRequest)
        return
    }

    if h.store != nil {
        if err := h.store.SaveDeviceOverride(pdid, req.Name); err != nil {
            http.Error(w, `{"error":"failed to save rename"}`, http.StatusInternalServerError)
            return
        }
    }

    // Update cache
    d := h.cache.Get(pdid)
    if d != nil {
        d.FriendlyName = req.Name
        h.cache.UpsertDevice(d.Device)
    }

    h.tryTrigger()
    w.WriteHeader(http.StatusNoContent)
}

// CreateUser creates a new human user profile.
func (h *Handlers) CreateUser(w http.ResponseWriter, r *http.Request) {
    var u models.User
    if err := json.NewDecoder(r.Body).Decode(&u); err != nil {
        http.Error(w, `{"error":"invalid request"}`, http.StatusBadRequest)
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

    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(http.StatusCreated)
    _ = json.NewEncoder(w).Encode(u)
}

// AssignDeviceUser maps a device to a human user.
func (h *Handlers) AssignDeviceUser(w http.ResponseWriter, r *http.Request) {
    pdid := r.PathValue("pdid")
    var req struct {
        UserID string `json:"user_id"`
    }
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        http.Error(w, `{"error":"invalid request"}`, http.StatusBadRequest)
        return
    }

    if h.store != nil {
        if err := h.store.AssignDeviceToUser(pdid, req.UserID); err != nil {
            http.Error(w, `{"error":"failed to map user"}`, http.StatusInternalServerError)
            return
        }
    }

    h.tryTrigger()
    w.WriteHeader(http.StatusNoContent)
}

// ... (ListDevices, GetDevice, AssignDeviceTag, ListTags, CreateTag, UpdateTag, DeleteTag, 
// ListPolicies, CreatePolicy, ValidatePolicy, UpdatePolicy, DeletePolicy, ListSchedules, 
// CreateSchedule, UpdateSchedule, DeleteSchedule, FlushNftables, StreamEvents remain unchanged from v2.2, 
// except ApplyEnrichment in CreatePolicy/UpdatePolicy must respect the `Enabled` flag)
// To save space, omitted the unchanged handlers. They are identical to v2.2.
