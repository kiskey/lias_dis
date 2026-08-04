// Package schedule implements time-based rule evaluation for LIAS.
//
// File:    apps/lias/internal/schedule/engine.go
// Version: 1.4
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

// EffectivePolicyProvider allows the schedule engine to query the active policy for a device
// to accurately compute NextStateChange transitions.
type EffectivePolicyProvider interface {
    GetEffectivePolicy(d *liasSync.LocalDevice) models.Policy
}

type Engine struct {
    mu             sync.RWMutex
    schedules      map[string]models.Schedule
    mergedCache    map[string]models.Schedule
    reverseIdx     map[string][]string
    cache          *liasSync.Cache
    policyProvider EffectivePolicyProvider // GAP-L-CR04 Fix
    trigger        chan struct{}           // GAP-L-H05 Fix
}

// NewEngine initializes the schedule engine.
func NewEngine(cache *liasSync.Cache, policyProvider EffectivePolicyProvider, trigger chan struct{}) *Engine {
    return &Engine{
        schedules:      make(map[string]models.Schedule),
        mergedCache:    make(map[string]models.Schedule),
        reverseIdx:     make(map[string][]string),
        cache:          cache,
        policyProvider: policyProvider,
        trigger:        trigger,
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

func (e *Engine) UpsertSchedule(s models.Schedule) {
    e.mu.Lock()
    defer e.mu.Unlock()
    e.schedules[s.ID] = s
    e.invalidateCacheForScheduleLocked(s.ID)
}

func (e *Engine) DeleteSchedule(id string) {
    e.mu.Lock()
    defer e.mu.Unlock()
    delete(e.schedules, id)
    e.invalidateCacheForScheduleLocked(id)
}

func (e *Engine) GetSchedule(id string) (models.Schedule, bool) {
    e.mu.RLock()
    defer e.mu.RUnlock()
    s, ok := e.schedules[id]
    return s, ok
}

func (e *Engine) ListSchedules() []models.Schedule {
    e.mu.RLock()
    defer e.mu.RUnlock()

    list := make([]models.Schedule, 0, len(e.schedules))
    for _, s := range e.schedules {
        list = append(list, s)
    }
    return list
}

func (e *Engine) EvaluateNow(schedID string) models.Action {
    if schedID == "" {
        return models.ActionAllow
    }
    return e.EvaluateBundle([]string{schedID})
}

func (e *Engine) EvaluateBundle(scheduleIDs []string) models.Action {
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
    var minNextChange *time.Time

    for _, d := range devs {
        // GAP-L-CR04 Fix: Use EffectivePolicyProvider to correctly identify schedule-driven devices
        if e.policyProvider != nil {
            devCopy := d
            pol := e.policyProvider.GetEffectivePolicy(&devCopy)
            
            if pol.Action == models.ActionSchedule {
                schedIDs := pol.GetScheduleIDs()
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
                            
                            // GAP-L-H05 Fix: Track the earliest transition to trigger immediate nftables sync
                            if minNextChange == nil || nextChange.Before(*minNextChange) {
                                n := nextChange
                                minNextChange = &n
                            }
                        }
                    }
                } else {
                    e.cache.SetNextStateChange(d.PDID, nil)
                }
            } else {
                e.cache.SetNextStateChange(d.PDID, nil)
            }
        }
    }

    // GAP-L-H05 Fix: Schedule an immediate resync precisely when the next schedule transition occurs
    if minNextChange != nil {
        duration := time.Until(*minNextChange)
        if duration < 0 {
            duration = 0
        }
        
        time.AfterFunc(duration, func() {
            select {
            case e.trigger <- struct{}{}:
                slog.Info("Triggered immediate nftables sync for schedule transition", "transition_time", minNextChange)
            default:
                // Trigger already pending
            }
        })
    }
}
