// Package api implements the HTTP server, REST handlers, and SSE broker for LIAS.
//
// File:    apps/lias/internal/api/handlers.go
// Version: 2.8
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
    handler.HandleFunc("POST /api/v1/devices/{pdid}/rename", h.RenameDevice)
    handler.HandleFunc("POST /api/v1/devices/{pdid}/user", h.AssignDeviceUser)
    handler.HandleFunc("GET /api/v1/devices/{pdid}/logs", h.GetDeviceLogs)

    handler.HandleFunc("GET /api/v1/tags", h.ListTags)
    handler.HandleFunc("POST /api/v1/tags", h.CreateTag)
    handler.HandleFunc("PUT /api/v1/tags/{id}", h.UpdateTag)
    handler.HandleFunc("DELETE /api/v1/tags/{id}", h.DeleteTag)

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

func (h *Handlers) StreamEvents(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "text/event-stream")
    w.Header().Set("Cache-Control", "no-cache")
    w.Header().Set("Connection", "keep-alive")
    w.Header().Set("Access-Control-Allow-Origin", "null")

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
                slog.Debug("LIAS SSE client socket write error, closing stream", "client_id", clientID, "error", err)
                return
            }
            flusher.Flush()
        }
    }
}

func (h *Handlers) tryTrigger() {
    select {
    case h.trigger <- struct{}{}:
    default:
    }
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

// LIAS-TAG-01 Fix: AssignDeviceTag accepts an array of tags
func (h *Handlers) AssignDeviceTag(w http.ResponseWriter, r *http.Request) {
    pdid := r.PathValue("pdid")
    var req struct {
        TagIDs []string `json:"tag_ids"`
    }
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        // Fallback for legacy single tag_id payload
        var legacyReq struct { TagID string `json:"tag_id"` }
        if err := json.NewDecoder(r.Body).Decode(&legacyReq); err != nil {
            http.Error(w, `{"error":"invalid request"}`, http.StatusBadRequest)
            return
        }
        req.TagIDs = []string{legacyReq.TagID}
    }

    h.cache.SetTags(pdid, req.TagIDs)
    d := h.cache.Get(pdid)
    mac := ""
    if d != nil { mac = d.CurrentMAC }

    if h.store != nil {
        if err := h.store.SaveDeviceTags(pdid, req.TagIDs, mac); err != nil {
            http.Error(w, `{"error":"failed to persist device tags"}`, http.StatusInternalServerError)
            return
        }
    }
    h.tryTrigger()
    w.WriteHeader(http.StatusNoContent)
}

func (h *Handlers) PauseDeviceInternet(w http.ResponseWriter, r *http.Request) {
    pdid := r.PathValue("pdid")
    d := h.cache.Get(pdid)
    if d == nil {
        http.Error(w, `{"error":"device not found"}`, http.StatusNotFound)
        return
    }

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

    polID := "pol_pause_" + pdid
    tempPol := models.Policy{
        ID: polID, Name: "Paused Internet", Type: models.PolicyTypeDevice, TargetID: pdid,
        Action: models.ActionSchedule, ScheduleIDs: []string{tempSchedID}, Priority: 1000, Enabled: true,
    }
    h.polEng.UpsertPolicy(tempPol)
    if h.store != nil { _ = h.store.SavePolicy(tempPol) }

    h.tryTrigger()
    w.WriteHeader(http.StatusAccepted)
    _ = json.NewEncoder(w).Encode(map[string]string{"status": "paused for 1 hour"})
}

func (h *Handlers) ToggleVacationMode(w http.ResponseWriter, r *http.Request) {
    var req struct { Enabled bool `json:"enabled"` }
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
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
    if h.store != nil { _ = h.store.SavePolicy(globalPol) }
    h.tryTrigger()

    w.Header().Set("Content-Type", "application/json")
    _ = json.NewEncoder(w).Encode(map[string]bool{"vacation_mode": req.Enabled})
}

func (h *Handlers) RenameDevice(w http.ResponseWriter, r *http.Request) {
    pdid := r.PathValue("pdid")
    var req struct { Name string `json:"name"` }
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

    d := h.cache.Get(pdid)
    if d != nil {
        d.FriendlyName = req.Name
        h.cache.UpsertDevice(d.Device)
    }

    h.tryTrigger()
    w.WriteHeader(http.StatusNoContent)
}

func (h *Handlers) CreateUser(w http.ResponseWriter, r *http.Request) {
    var u models.User
    if err := json.NewDecoder(r.Body).Decode(&u); err != nil {
        http.Error(w, `{"error":"invalid request"}`, http.StatusBadRequest)
        return
    }
    if u.ID == "" { u.ID = "user_" + generateID() }

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

func (h *Handlers) AssignDeviceUser(w http.ResponseWriter, r *http.Request) {
    pdid := r.PathValue("pdid")
    var req struct { UserID string `json:"user_id"` }
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

    if h.store != nil {
        if err := h.store.SaveTag(created); err != nil {
            http.Error(w, `{"error":"failed to persist tag to storage"}`, http.StatusInternalServerError)
            return
        }
    }
    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(http.StatusCreated)
    _ = json.NewEncoder(w).Encode(created)
}

func (h *Handlers) UpdateTag(w http.ResponseWriter, r *http.Request) {
    id := r.PathValue("id")
    var t tags.Tag
    if err := json.NewDecoder(r.Body).Decode(&t); err != nil {
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
    
    data, err := io.ReadAll(r.Body)
    if err != nil {
        http.Error(w, `{"error":"failed to read request body"}`, http.StatusBadRequest)
        return
    }

    if err := h.store.ImportPolicies(data); err != nil {
        http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusBadRequest)
        return
    }

    // FIX: Reload hydrated state into engine without causing an import cycle
    var policies []models.Policy
    if err := json.Unmarshal(data, &policies); err == nil {
        for _, p := range policies {
            h.polEng.UpsertPolicy(p)
        }
    }

    h.tryTrigger()
    
    w.Header().Set("Content-Type", "application/json")
    _ = json.NewEncoder(w).Encode(map[string]string{"status": "import successful"})
}

func (h *Handlers) validateAndMergePolicySchedules(p *models.Policy) ([]scheduleconflict.Conflict, error) {
    if p.Action != models.ActionSchedule { return nil, nil }
    schedIDs := p.GetScheduleIDs()
    if len(schedIDs) == 0 { return nil, nil }

    var scheds []models.Schedule
    for _, sid := range schedIDs {
        sch, ok := h.schedEng.GetSchedule(sid)
        if !ok {
            return nil, httpError{status: http.StatusBadRequest, msg: "referenced schedule '" + sid + "' does not exist"}
        }
        scheds = append(scheds, sch)
    }
    _, conflicts, err := scheduleconflict.MergeSchedules(scheds)
    return conflicts, err
}

type httpError struct { status int; msg string }
func (e httpError) Error() string { return e.msg }

func toAPIConflicts(sc []scheduleconflict.Conflict) []api.Conflict {
    if len(sc) == 0 { return []api.Conflict{} }
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
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
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
    _, conflicts, _ := scheduleconflict.MergeSchedules(scheds)
    _ = json.NewEncoder(w).Encode(api.ConflictResponse{Conflicts: toAPIConflicts(conflicts)})
}

func (h *Handlers) CreatePolicy(w http.ResponseWriter, r *http.Request) {
    var p models.Policy
    if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
        http.Error(w, `{"error":"invalid request"}`, http.StatusBadRequest)
        return
    }
    if p.ID == "" { p.ID = "pol_" + generateID() }
    if p.Type == models.PolicyTypeTag && p.TargetID == "infrastructure" {
        w.Header().Set("Content-Type", "application/json"); w.WriteHeader(http.StatusBadRequest)
        _ = json.NewEncoder(w).Encode(map[string]string{"error": "policy_immutable_target", "message": "The 'infrastructure' tag is super-immutable."})
        return
    }

    conflicts, err := h.validateAndMergePolicySchedules(&p)
    if err != nil && conflicts == nil {
        if hErr, ok := err.(httpError); ok { http.Error(w, `{"error":"`+hErr.msg+`"}`, hErr.status); return }
    }
    if len(conflicts) > 0 {
        w.Header().Set("Content-Type", "application/json"); w.WriteHeader(http.StatusConflict)
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
    w.Header().Set("Content-Type", "application/json"); w.WriteHeader(http.StatusCreated)
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
    if p.Type == models.PolicyTypeTag && p.TargetID == "infrastructure" {
        w.Header().Set("Content-Type", "application/json"); w.WriteHeader(http.StatusBadRequest)
        _ = json.NewEncoder(w).Encode(map[string]string{"error": "policy_immutable_target", "message": "The 'infrastructure' tag is super-immutable."})
        return
    }

    conflicts, err := h.validateAndMergePolicySchedules(&p)
    if err != nil && conflicts == nil {
        if hErr, ok := err.(httpError); ok { http.Error(w, `{"error":"`+hErr.msg+`"}`, hErr.status); return }
    }
    if len(conflicts) > 0 {
        w.Header().Set("Content-Type", "application/json"); w.WriteHeader(http.StatusConflict)
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
    if tz == "" { return false }
    _, err := time.LoadLocation(tz)
    return err == nil
}

func validateScheduleRules(s *models.Schedule) error {
    for i, rule := range s.Rules {
        // LIAS-SCH-09 Fix: Allow empty days if calendar dates are specified
        if len(rule.Days) == 0 && (rule.StartDate == "" || rule.EndDate == "") {
            return fmt.Errorf("rule %d: days must be non-empty if calendar dates are not specified", i+1)
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
        // LIAS-SCH-09 Fix: Validate calendar dates format
        if rule.StartDate != "" {
            if _, err := time.Parse("2006-01-02", rule.StartDate); err != nil {
                return fmt.Errorf("rule %d: invalid start_date format %q (expected YYYY-MM-DD)", i+1, rule.StartDate)
            }
        }
        if rule.EndDate != "" {
            if _, err := time.Parse("2006-01-02", rule.EndDate); err != nil {
                return fmt.Errorf("rule %d: invalid end_date format %q (expected YYYY-MM-DD)", i+1, rule.EndDate)
            }
        }
    }
    return nil
}

func (h *Handlers) CreateSchedule(w http.ResponseWriter, r *http.Request) {
    var s models.Schedule
    if err := json.NewDecoder(r.Body).Decode(&s); err != nil {
        http.Error(w, `{"error":"invalid request"}`, http.StatusBadRequest)
        return
    }
    if s.ID == "" { s.ID = "sched_" + generateID() }
    if s.Mode == "" {
        hasAllow := false
        for _, r := range s.Rules { if r.Action == models.ActionAllow { hasAllow = true; break } }
        if hasAllow { s.Mode = models.ScheduleModeWhitelist } else { s.Mode = models.ScheduleModeDowntime }
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
        w.Header().Set("Content-Type", "application/json"); w.WriteHeader(http.StatusConflict)
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
    w.Header().Set("Content-Type", "application/json"); w.WriteHeader(http.StatusCreated)
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
    if s.Mode == "" {
        hasAllow := false
        for _, r := range s.Rules { if r.Action == models.ActionAllow { hasAllow = true; break } }
        if hasAllow { s.Mode = models.ScheduleModeWhitelist } else { s.Mode = models.ScheduleModeDowntime }
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
        w.Header().Set("Content-Type", "application/json"); w.WriteHeader(http.StatusConflict)
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
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        if token == "" {
            next.ServeHTTP(w, r)
            return
        }
        authHeader := r.Header.Get("Authorization")
        if authHeader == "" {
            http.Error(w, `{"error":"missing authorization header"}`, http.StatusUnauthorized)
            return
        }
        parts := strings.SplitN(authHeader, " ", 2)
        if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || parts[1] != token {
            http.Error(w, `{"error":"invalid or malformed authorization token"}`, http.StatusUnauthorized)
            return
        }
        next.ServeHTTP(w, r)
    })
}
