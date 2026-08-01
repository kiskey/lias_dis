// Package schedule implements the time-based rule evaluation for LIAS.
//
// File:    apps/lias/internal/schedule/parser.go
// Version: 1.0
package schedule

import (
    "fmt"
    "time"

    "github.com/user/lias-dis/shared/models"
)

var dayMap = map[string]time.Weekday{
    "sun": time.Sunday,
    "mon": time.Monday,
    "tue": time.Tuesday,
    "wed": time.Wednesday,
    "thu": time.Thursday,
    "fri": time.Friday,
    "sat": time.Saturday,
}

// Evaluate determines the active action for a schedule at a specific moment.
// If multiple rules match, the one with the narrowest time window wins.
// If no rules match, it fails closed (block).
func Evaluate(s models.Schedule, now time.Time) (models.Action, error) {
    loc, err := time.LoadLocation(s.Timezone)
    if err != nil {
        return models.ActionBlock, fmt.Errorf("invalid timezone '%s': %w", s.Timezone, err)
    }
    now = now.In(loc)

    var bestMatch *models.ScheduleRule
    var bestDuration time.Duration = -1

    for _, rule := range s.Rules {
        matchesDay := false
        for _, dayStr := range rule.Days {
            if day, ok := dayMap[dayStr]; ok && day == now.Weekday() {
                matchesDay = true
                break
            }
        }
        if !matchesDay {
            continue
        }

        startTime, err := time.Parse("15:04", rule.StartTime)
        if err != nil {
            continue
        }
        endTime, err := time.Parse("15:04", rule.EndTime)
        if err != nil {
            continue
        }

        year, month, day := now.Date()
        start := time.Date(year, month, day, startTime.Hour(), startTime.Minute(), 0, 0, loc)
        end := time.Date(year, month, day, endTime.Hour(), endTime.Minute(), 0, 0, loc)

        // v1.0: Only support same-day windows (start < end)
        if !end.After(start) {
            continue
        }

        // Check if now is within the window [start, end)
        if now.Sub(start) >= 0 && now.Sub(end) < 0 {
            dur := end.Sub(start)
            if bestDuration == -1 || dur < bestDuration {
                bestDuration = dur
                r := rule
                bestMatch = &r
            }
        }
    }

    if bestMatch != nil {
        return bestMatch.Action, nil
    }

    return models.ActionBlock, nil
}

// NextStateChange calculates the next time the schedule action will change.
// Uses a naive 1-minute resolution search for simplicity and reliability in v1.0.
func NextStateChange(s models.Schedule, now time.Time) (time.Time, error) {
    loc, err := time.LoadLocation(s.Timezone)
    if err != nil {
        return time.Time{}, fmt.Errorf("invalid timezone: %w", err)
    }
    now = now.In(loc)

    currentAction, _ := Evaluate(s, now)
    
    // Check up to 7 days in 1-minute increments
    for i := 1; i <= 7*24*60; i++ {
        t := now.Add(time.Duration(i) * time.Minute)
        nextAction, _ := Evaluate(s, t)
        if currentAction != nextAction {
            return t, nil
        }
    }

    return now.Add(24 * time.Hour), nil // Fallback
}
