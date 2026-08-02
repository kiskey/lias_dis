// Package schedule implements time-based rule evaluation for LIAS.
//
// File:    apps/lias/internal/schedule/engine.go
// Version: 1.1
package schedule

import (
	"context"
	"log/slog"
	"sync"
	"time"

	liasSync "github.com/user/lias-dis/apps/lias/internal/sync"
	"github.com/user/lias-dis/shared/models"
)

// Engine manages schedules and evaluates them in real-time.
// Implements policy.ScheduleEvaluator.
type Engine struct {
	mu        sync.RWMutex
	schedules map[string]models.Schedule
	cache     *liasSync.Cache
}

// NewEngine initializes the schedule engine.
func NewEngine(cache *liasSync.Cache) *Engine {
	return &Engine{
		schedules: make(map[string]models.Schedule),
		cache:     cache,
	}
}

// UpsertSchedule adds or updates a schedule record.
func (e *Engine) UpsertSchedule(s models.Schedule) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.schedules[s.ID] = s
}

// DeleteSchedule removes a schedule record by ID.
func (e *Engine) DeleteSchedule(id string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	delete(e.schedules, id)
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

// EvaluateNow implements policy.ScheduleEvaluator.
// Returns ActionBlock (fail-closed) if the schedule is missing or invalid.
func (e *Engine) EvaluateNow(schedID string) models.Action {
	e.mu.RLock()
	s, ok := e.schedules[schedID]
	e.mu.RUnlock()

	if !ok {
		slog.Warn("Schedule missing, failing closed (block)", "schedule_id", schedID)
		return models.ActionBlock
	}

	action, err := Evaluate(s, time.Now())
	if err != nil {
		slog.Error("Schedule evaluation error, failing closed (block)", "schedule_id", schedID, "error", err)
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
		if d.Policy != nil && d.Policy.Action == models.ActionSchedule && d.Policy.ScheduleID != nil {
			e.mu.RLock()
			s, ok := e.schedules[*d.Policy.ScheduleID]
			e.mu.RUnlock()

			if ok {
				nextChange, err := NextStateChange(s, time.Now())
				if err == nil {
					e.cache.SetNextStateChange(d.PDID, &nextChange)
				}
			}
		}
	}
}
