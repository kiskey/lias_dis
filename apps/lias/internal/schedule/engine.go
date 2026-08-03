// Package schedule implements time-based rule evaluation for LIAS.
//
// File:    apps/lias/internal/schedule/engine.go
// Version: 1.3
package schedule

import (
    "context"
    "log/slog"
    "sort"
    "strings"
    "sync"
    "time"

    "github.com/user/lias-dis/apps/lias/internal/scheduleconflict"
    liasSync "github.com/user/lias-dis/apps/lias/internal/sync"
    "github.com/user/lias-dis/shared/models"
)

// Engine manages schedules and evaluates them in real-time.
type Engine struct {
    mu          sync.RWMutex
    schedules   map[string]models.Schedule
    mergedCache map[string]models.Schedule
    reverseIdx  map[string][]string
    cache       *liasSync.Cache
}

// NewEngine initializes the schedule engine.
func NewEngine(cache *liasSync.Cache) *Engine {
    return &Engine{
        schedules:   make(map[string]models.Schedule),
        mergedCache: make(map[string]models.Schedule),
        reverseIdx:  make(map[string][]string),
        cache:       cache,
    }
}

func bundleKey(scheduleIDs []string) string {
    sorted := make([]string, len(scheduleIDs))
    copy(sorted, scheduleIDs)
    sort.Strings(sorted)
    return strings.Join(sorted, "+")
}

func (e *Engine) invalidateCacheForScheduleLocked(id string) {
    if keys, ok := e.reverseIdx[id]; ok {
        for _, k := range keys {
            delete(e.mergedCache, k)
        }
        delete(e.reverseIdx, id)
    }
}

// UpsertSchedule adds or updates a schedule record and invalidates composite caches.
func (e *Engine) UpsertSchedule(s models.Schedule) {
    e.mu.Lock()
    defer e.mu.Unlock()
    e.schedules[s.ID] = s
    e.invalidateCacheForScheduleLocked(s.ID)
}

// DeleteSchedule removes a schedule record by ID and invalidates composite caches.
func (e *Engine) DeleteSchedule(id string) {
    e.mu.Lock()
    defer e.mu.Unlock()
    delete(e.schedules, id)
    e.invalidateCacheForScheduleLocked(id)
}

// GetSchedule returns a single schedule by ID if found.
func (e *Engine) GetSchedule(id string) (models.Schedule, bool) {
    e.mu.RLock()
    defer e.mu.RUnlock()
    s, ok := e.schedules[id]
    return s, ok
}

// ListSchedules returns all configured schedules.
func (e *Engine) ListSchedules() []models.Schedule {
    e.mu.RLock()
    defer e.mu.RUnlock()

    list := make([]models.Schedule, 0, len(e.schedules))
    for _, s := range e.schedules {
        list = append(list, s)
    }
    return list
}

// EvaluateNow implements policy.ScheduleEvaluator for single schedule evaluation.
func (e *Engine) EvaluateNow(schedID string) models.Action {
    if schedID == "" {
        return models.ActionAllow
    }
    return e.EvaluateBundle([]string{schedID})
}

// EvaluateBundle evaluates a policy's attached multi-schedule bundle.
// If scheduleIDs is empty, returns ActionAllow (no restriction).
// Returns ActionBlock (fail-closed) if any schedule is missing or if conflicts occur.
func (e *Engine) EvaluateBundle(scheduleIDs []string) models.Action {
    // OPTION B FIX: Empty schedule list means no restriction (Allow)
    if len(scheduleIDs) == 0 {
        return models.ActionAllow
    }

    key := bundleKey(scheduleIDs)

    e.mu.RLock()
    merged, cached := e.mergedCache[key]
    e.mu.RUnlock()

    if !cached {
        e.mu.Lock()
        merged, cached = e.mergedCache[key]
        if !cached {
            var resolved []models.Schedule
            for _, id := range scheduleIDs {
                s, ok := e.schedules[id]
                if !ok {
                    e.mu.Unlock()
                    slog.Warn("Schedule in bundle missing, failing closed (block)", "schedule_id", id)
                    return models.ActionBlock
                }
                resolved = append(resolved, s)
            }

            comp, conflicts, err := scheduleconflict.MergeSchedules(resolved)
            if err != nil || len(conflicts) > 0 {
                e.mu.Unlock()
                slog.Error("Schedule bundle contains conflicts, failing closed (block)", "schedule_ids", scheduleIDs, "conflicts", len(conflicts))
                return models.ActionBlock
            }

            merged = comp
            e.mergedCache[key] = merged
            for _, id := range scheduleIDs {
                e.reverseIdx[id] = append(e.reverseIdx[id], key)
            }
        }
        e.mu.Unlock()
    }

    action, err := Evaluate(merged, time.Now())
    if err != nil {
        slog.Error("Schedule bundle evaluation error, failing closed (block)", "key", key, "error", err)
        return models.ActionBlock
    }
    return action
}

// Run starts the background timer that updates NextStateChange timestamps for scheduled devices.
func (e *Engine) Run(ctx context.Context) {
    ticker := time.NewTicker(1 * time.Minute)
    defer ticker.Stop()

    e.updateNextStateChanges()

    for {
        select {
        case <-ctx.Done():
            return
        case <-ticker.C:
            e.updateNextStateChanges()
        }
    }
}

func (e *Engine) updateNextStateChanges() {
    devs := e.cache.List()
    for _, d := range devs {
        if d.Policy != nil && d.Policy.Action == models.ActionSchedule {
            schedIDs := d.Policy.GetScheduleIDs()
            if len(schedIDs) > 0 {
                key := bundleKey(schedIDs)
                e.mu.RLock()
                merged, ok := e.mergedCache[key]
                e.mu.RUnlock()

                if !ok {
                    _ = e.EvaluateBundle(schedIDs)
                    e.mu.RLock()
                    merged, ok = e.mergedCache[key]
                    e.mu.RUnlock()
                }

                if ok {
                    nextChange, err := NextStateChange(merged, time.Now())
                    if err == nil {
                        e.cache.SetNextStateChange(d.PDID, &nextChange)
                    }
                }
            }
        }
    }
}
