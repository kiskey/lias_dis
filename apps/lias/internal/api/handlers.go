// Package api implements the HTTP server, REST handlers, and SSE broker for LIAS.
//
// File:    apps/lias/internal/api/handlers.go
// Version: 2.4
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
    handler.HandleFunc("POST /api/v1/devices/{pdid}/pause", h.PauseDeviceInternet)
    handler.HandleFunc("POST /api/v1/devices/{pdid}/rename", h.RenameDevice)
    handler.HandleFunc("POST /api/v1/devices/{pdid}/user", h.AssignDeviceUser)

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
    
    handler.HandleFunc("POST /api/v1/users", h.CreateUser)

    handler.HandleFunc("POST /api/v1/nftables/flush", h.FlushNftables)
    handler.HandleFunc("GET /api/v1/events", h.StreamEvents)

    mux.Handle("/", AuthMiddleware(authToken, handler))
}

func (h *Handlers) StreamEvents(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "text/event-stream")
    w.Header().Set("Cache-Control", "no-cache")
    w.Header().Set("Connection", "keep-alive")
    // Strict CORS for SSE
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

func (h *Handlers) AssignDeviceTag(w http.ResponseWriter, r *http.Request) {
    pdid := r.PathValue("pdid")
    var req struct {
        TagID string `json:"tag_id"`
    }
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        http.Error(w, `{"error":"invalid request"}`, http.StatusBadRequest)
        return
    }

    h.cache.SetTags(pdid, []string{req.TagID})

    d := h.cache.Get(pdid)
    mac := ""
    if d != nil {
        mac = d.CurrentMAC
    }

    if h.store != nil {
        if err := h.store.SaveDeviceTag(pdid, req.TagID, mac); err != nil {
            slog.Error("Failed to persist device tag assignment to storage", "pdid", pdid, "tag_id", req.TagID, "error", err)
            http.Error(w, `{"error":"failed to persist device tag assignment"}`, http.StatusInternalServerError)
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

    polID := "pol_pause_" + pdid
    tempPol := models.Policy{
        ID:          polID,
        Name:        "Paused Internet",
        Type:        models.PolicyTypeDevice,
        TargetID:    pdid,
        Action:      models.ActionSchedule,
        ScheduleIDs: []string{tempSchedID},
        Priority:    1000,
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
            slog.Error("Failed to persist new tag to storage", "tag_id", created.ID, "error", err)
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
            slog.Error("Failed to persist updated tag to storage", "tag_id", updated.ID, "error", err)
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
            slog.Error("Failed to delete tag from storage", "tag_id", id, "error", err)
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

func (h *Handlers) validateAndMergePolicySchedules(p *models.Policy) ([]scheduleconflict.Conflict, error) {
    if p.Action != models.ActionSchedule {
        return nil, nil
    }

    schedIDs := p.GetScheduleIDs()
    if len(schedIDs) == 0 {
        return nil, nil
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
            ScheduleAID:   c.ScheduleAID,
            ScheduleAName: c.ScheduleAName,
            ScheduleBID:   c.ScheduleBID,
            ScheduleBName: c.ScheduleBName,
            Day:           c.Day,
            OverlapStart:  c.OverlapStart,
            OverlapEnd:    c.OverlapEnd,
            ActionA:       c.ActionA,
            ActionB:       c.ActionB,
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

    _ = json.NewEncoder(w).Encode(api.ConflictResponse{
        Conflicts: toAPIConflicts(conflicts),
    })
}

func (h *Handlers) CreatePolicy(w http.ResponseWriter, r *http.Request) {
    var p models.Policy
    if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
        http.Error(w, `{"error":"invalid request"}`, http.StatusBadRequest)
        return
    }
    if p.ID == "" {
        p.ID = "pol_" + generateID()
    }

    if p.Type == models.PolicyTypeTag && p.TargetID == "infrastructure" {
        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(http.StatusBadRequest)
        _ = json.NewEncoder(w).Encode(map[string]string{
            "error":   "policy_immutable_target",
            "message": "The 'infrastructure' tag is super-immutable and cannot be targeted by tag policies.",
        })
        return
    }

    conflicts, err := h.validateAndMergePolicySchedules(&p)
    if err != nil && conflicts == nil {
        if hErr, ok := err.(httpError); ok {
            http.Error(w, `{"error":"`+hErr.msg+`"}`, hErr.status)
            return
        }
    }
    if len(conflicts) > 0 {
        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(http.StatusConflict)
        _ = json.NewEncoder(w).Encode(api.ConflictResponse{
            Error:     "schedule_conflict",
            Message:   "Attached schedules contain contradictory windows",
            Conflicts: toAPIConflicts(conflicts),
        })
        return
    }

    h.polEng.UpsertPolicy(p)

    if h.store != nil {
        if err := h.store.SavePolicy(p); err != nil {
            slog.Error("Failed to persist policy to storage", "policy_id", p.ID, "error", err)
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
    if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
        http.Error(w, `{"error":"invalid request"}`, http.StatusBadRequest)
        return
    }
    p.ID = id

    if p.Type == models.PolicyTypeTag && p.TargetID == "infrastructure" {
        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(http.StatusBadRequest)
        _ = json.NewEncoder(w).Encode(map[string]string{
            "error":   "policy_immutable_target",
            "message": "The 'infrastructure' tag is super-immutable and cannot be targeted by tag policies.",
        })
        return
    }

    conflicts, err := h.validateAndMergePolicySchedules(&p)
    if err != nil && conflicts == nil {
        if hErr, ok := err.(httpError); ok {
            http.Error(w, `{"error":"`+hErr.msg+`"}`, hErr.status)
            return
        }
    }
    if len(conflicts) > 0 {
        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(http.StatusConflict)
        _ = json.NewEncoder(w).Encode(api.ConflictResponse{
            Error:     "schedule_conflict",
            Message:   "Attached schedules contain contradictory windows",
            Conflicts: toAPIConflicts(conflicts),
        })
        return
    }

    h.polEng.UpsertPolicy(p)

    if h.store != nil {
        if err := h.store.SavePolicy(p); err != nil {
            slog.Error("Failed to update policy in storage", "policy_id", p.ID, "error", err)
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
            slog.Error("Failed to delete policy from storage", "policy_id", id, "error", err)
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

func validateScheduleRules(s *models.Schedule) error {
    for i, rule := range s.Rules {
        if len(rule.Days) == 0 {
            return fmt.Errorf("rule %d: days must be non-empty", i+1)
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
    }
    return nil
}

func (h *Handlers) CreateSchedule(w http.ResponseWriter, r *http.Request) {
    var s models.Schedule
    if err := json.NewDecoder(r.Body).Decode(&s); err != nil {
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
        _ = json.NewEncoder(w).Encode(api.ConflictResponse{
            Error:     "schedule_conflict",
            Message:   "Schedule rules contain internal contradictory windows",
            Conflicts: toAPIConflicts(conflicts),
        })
        return
    }

    h.schedEng.UpsertSchedule(s)

    if h.store != nil {
        if err := h.store.SaveSchedule(s); err != nil {
            slog.Error("Failed to persist schedule to storage", "schedule_id", s.ID, "error", err)
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
    if err := json.NewDecoder(r.Body).Decode(&s); err != nil {
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
        _ = json.NewEncoder(w).Encode(api.ConflictResponse{
            Error:     "schedule_conflict",
            Message:   "Schedule rules contain internal contradictory windows",
            Conflicts: toAPIConflicts(conflicts),
        })
        return
    }

    h.schedEng.UpsertSchedule(s)

    if h.store != nil {
        if err := h.store.SaveSchedule(s); err != nil {
            slog.Error("Failed to update schedule in storage", "schedule_id", s.ID, "error", err)
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
            slog.Error("Failed to delete schedule from storage", "schedule_id", id, "error", err)
            http.Error(w, `{"error":"failed to delete schedule from storage"}`, http.StatusInternalServerError)
            return
        }
    }

    h.tryTrigger()
    w.WriteHeader(http.StatusNoContent)
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

// AuthMiddleware enforces Bearer token authentication if a token is configured.
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
