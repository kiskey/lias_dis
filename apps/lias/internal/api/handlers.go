// Package api implements the HTTP server, REST handlers, and SSE broker for LIAS.
//
// File:    apps/lias/internal/api/handlers.go
// Version: 3.2 (Added Extend Access, Cancel Extension, Effective Status endpoints & migrated PauseDeviceInternet)
package api

import (
    "crypto/rand"
    "encoding/hex"
    "encoding/json"
    "fmt"
    "io"
    "log/slog"
    "net/http"
    "strconv"
    "strings"
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
    cache    *liasSync.Cache
    tagMgr   *tags.Manager
    polEng   *policy.Engine
    schedEng *schedule.Engine
    nftCtrl  *nftables.Controller
    store    *storage.Storage
    trigger  chan struct{}
    broker   *Broker
}

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
    handler.HandleFunc("POST /api/v1/devices/{pdid}/pause", h.PauseDeviceInternet)
    handler.HandleFunc("DELETE /api/v1/devices/{pdid}/pause", h.UnpauseDeviceInternet)
    handler.HandleFunc("POST /api/v1/devices/{pdid}/extend", h.ExtendDeviceAccess)
    handler.HandleFunc("DELETE /api/v1/devices/{pdid}/extend", h.CancelDeviceExtension)
    handler.HandleFunc("GET /api/v1/devices/{pdid}/effective-status", h.GetDeviceEffectiveStatus)
    handler.HandleFunc("POST /api/v1/devices/{pdid}/rename", h.RenameDevice)
    handler.HandleFunc("POST /api/v1/devices/{pdid}/user", h.AssignDeviceUser)
    handler.HandleFunc("GET /api/v1/devices/{pdid}/logs", h.GetDeviceLogs)

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
    
    handler.HandleFunc("POST /api/v1/users", h.CreateUser)
    handler.HandleFunc("POST /api/v1/vacation", h.ToggleVacationMode)

    handler.HandleFunc("GET /api/v1/stats", h.GetNetworkStats)
    handler.HandleFunc("POST /api/v1/nftables/flush", h.FlushNftables)
    handler.HandleFunc("GET /api/v1/events", h.StreamEvents)

    mux.Handle("/api/", AuthMiddleware(authToken, handler))
}

// ... (StreamEvents, tryTrigger, ListDevices, GetDevice, GetDeviceLogs, AssignDeviceTag, RenameDevice, CreateUser, AssignDeviceUser, ListTags, CreateTag, UpdateTag, DeleteTag, ListPolicies, ExportPolicies, ImportPolicies, validateAndMergePolicySchedules, ValidatePolicy, CreatePolicy, UpdatePolicy, DeletePolicy, ListSchedules, CreateSchedule, UpdateSchedule, DeleteSchedule, GetNetworkStats, FlushNftables, AuthMiddleware omitted for brevity - unchanged from V3.1 except as noted) ...

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
    if h.store != nil { _ = h.store.SaveSchedule(tempSched) }

    tempPol := models.Policy{
        ID: polID, Name: "Paused Internet", Type: models.PolicyTypeDevice, TargetID: pdid,
        Action: models.ActionSchedule, ScheduleIDs: []string{tempSchedID}, Priority: 1000, Enabled: true,
        ExpiresAt: &expiresAt, ReasonTag: "pause",
        CreatedAt: time.Now(), UpdatedAt: time.Now(),
    }
    h.polEng.UpsertPolicy(tempPol)
    if h.store != nil { _ = h.store.SavePolicy(tempPol) }

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
    if h.store != nil { _ = h.store.DeletePolicy(polID) }
    
    for _, sid := range schedIDs {
        h.schedEng.DeleteSchedule(sid)
        if h.store != nil { _ = h.store.DeleteSchedule(sid) }
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
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
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
    if h.store != nil { _ = h.store.DeletePolicy(polID) }
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
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
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
    if h.store != nil { _ = h.store.DeletePolicy(polID) }
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
    if d == nil { return res }

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
        if !p.Enabled || p.TargetID != d.PDID { continue }
        if p.Type == models.PolicyTypeDevice {
            if p.ID == "pol_extend_device_"+d.PDID { pCopy := p; activeExt = &pCopy }
            if p.ID == "pol_pause_"+d.PDID { pCopy := p; activePause = &pCopy }
        }
    }

    if activeExt != nil {
        res.Action = models.ActionAllow
        res.Source = api.EffectiveSourceDevicePolicy
        if activeExt.ExpiresAt != nil {
            minsLeft := int(time.Until(*activeExt.ExpiresAt).Minutes())
            if minsLeft < 0 { minsLeft = 0 }
            res.ActiveExtension = &api.ExtensionInfo{
                ExpiresAt: activeExt.ExpiresAt.UTC().Format(time.RFC3339),
                MinutesLeft: minsLeft,
                ReasonTag: activeExt.ReasonTag,
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
            if minsLeft < 0 { minsLeft = 0 }
            res.ActiveExtension = &api.ExtensionInfo{
                ExpiresAt: activePause.ExpiresAt.UTC().Format(time.RFC3339),
                MinutesLeft: minsLeft,
                ReasonTag: activePause.ReasonTag,
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

    pols := h.polEng.ListPolicies()
    var activeExt *models.Policy
    var bestTagPol *models.Policy

    for _, p := range pols {
        if !p.Enabled || p.TargetID != tagID || p.Type != models.PolicyTypeTag { continue }
        if p.ID == "pol_extend_tag_"+tagID {
            pCopy := p
            activeExt = &pCopy
            continue
        }
        if bestTagPol == nil || p.Priority > bestTagPol.Priority {
            pCopy := p
            bestTagPol = &pCopy
        }
    }

    if activeExt != nil {
        res.Action = models.ActionAllow
        res.Source = api.EffectiveSourceTagPolicy
        if activeExt.ExpiresAt != nil {
            minsLeft := int(time.Until(*activeExt.ExpiresAt).Minutes())
            if minsLeft < 0 { minsLeft = 0 }
            res.ActiveExtension = &api.ExtensionInfo{
                ExpiresAt: activeExt.ExpiresAt.UTC().Format(time.RFC3339),
                MinutesLeft: minsLeft,
                ReasonTag: activeExt.ReasonTag,
            }
        }
        return res
    }

    if bestTagPol != nil {
        if bestTagPol.Action == models.ActionSchedule {
            res.Action = h.schedEng.EvaluateBundle(bestTagPol.GetScheduleIDs())
            res.Source = api.EffectiveSourceSchedule
        } else {
            res.Action = bestTagPol.Action
            res.Source = api.EffectiveSourceTagPolicy
        }
    } else {
        if gp, ok := h.polEng.GetPolicy("global_default"); ok && gp.Enabled && gp.Action == models.ActionSchedule {
            res.Action = h.schedEng.EvaluateBundle(gp.GetScheduleIDs())
            res.Source = api.EffectiveSourceSchedule
        } else {
            res.Action = models.ActionAllow
            res.Source = api.EffectiveSourceFallback
        }
    }

    if res.Action == models.ActionBlock {
        res.ExtendAvailable = true
    }
    return res
}

// ToggleVacationMode, validateScheduleRules, isSupportedTimezone, generateID omitted for brevity ...
