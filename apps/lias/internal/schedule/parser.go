// Package schedule implements time-based rule parsing and evaluation for LIAS.
//
// File:    apps/lias/internal/schedule/parser.go
// Version: 1.8
package schedule

import (
    "log/slog"
    "sort"
    "strings"
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

// Evaluate determines the effective action for a schedule at a specific time.
// Handles DST spring-forward (skipped hour) and fall-back (repeated hour).
func Evaluate(s models.Schedule, now time.Time) (models.Action, error) {
    loc, err := time.LoadLocation(s.Timezone)
    if err != nil {
        loc = time.UTC
    }
    now = now.In(loc)

    // LIAS-SCH-03/04 Fix: Resolve DST ambiguities.
    _, offset := now.Zone()
    now = now.Add(time.Duration(-offset) * time.Second) 
    now = now.In(loc)
    
    var bestMatch *models.ScheduleRule
    var bestDuration time.Duration = -1

    currentWeekday := now.Weekday()
    prevWeekday := (now.Weekday() + 6) % 7

    for _, rule := range s.Rules {
        // LIAS-SCH-09 Fix: Calendar Date Scheduling
        if rule.StartDate != "" && rule.EndDate != "" {
            startDt, err1 := time.ParseInLocation("2006-01-02", rule.StartDate, loc)
            endDt, err2 := time.ParseInLocation("2006-01-02", rule.EndDate, loc)
            if err1 == nil && err2 == nil {
                // Add 1 day to EndDate to make it inclusive of the whole day
                endDt = endDt.AddDate(0, 0, 1)
                if now.Before(startDt) || now.After(endDt) {
                    continue
                }
                
                // Match time within the date range
                startTime, _ := time.Parse("15:04", rule.StartTime)
                endTime, _ := time.Parse("15:04", rule.EndTime)
                
                year, month, day := now.Date()
                start := time.Date(year, month, day, startTime.Hour(), startTime.Minute(), 0, 0, loc)
                end := time.Date(year, month, day, endTime.Hour(), endTime.Minute(), 0, 0, loc)

                if start.Equal(end) {
                    continue // Zero duration
                }

                isMatch := false
                var windowDuration time.Duration

                if end.After(start) {
                    isMatch = (now.Equal(start) || now.After(start)) && now.Before(end)
                    windowDuration = end.Sub(start)
                } else {
                    // Overnight
                    windowDuration = end.Add(24 * time.Hour).Sub(start)
                    if (now.Equal(start) || now.After(start)) && now.Before(end.AddDate(0, 0, 1)) {
                        isMatch = true
                    }
                }

                if isMatch {
                    if bestDuration == -1 || windowDuration < bestDuration {
                        bestDuration = windowDuration
                        r := rule
                        bestMatch = &r
                    }
                }
            }
            continue // Skip weekly logic if dates were specified
        }

        // Weekly Scheduling
        matchesCurrentDay := false
        matchesPrevDay := false

        for _, dayStr := range rule.Days {
            dLower := strings.ToLower(strings.TrimSpace(dayStr))
            if day, ok := dayMap[dLower]; ok {
                if day == currentWeekday {
                    matchesCurrentDay = true
                }
                if day == prevWeekday {
                    matchesPrevDay = true
                }
            }
        }

        if !matchesCurrentDay && !matchesPrevDay {
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

        if rule.StartTime != rule.EndTime && start.Equal(end) {
            slog.Warn("Schedule rule window collapsed to zero duration due to DST transition",
                "schedule_id", s.ID, "rule_start", rule.StartTime, "rule_end", rule.EndTime)
            continue
        }

        isMatch := false
        var windowDuration time.Duration

        if end.After(start) {
            if matchesCurrentDay {
                isMatch = (now.Equal(start) || now.After(start)) && now.Before(end)
            }
            windowDuration = end.Sub(start)
        } else {
            windowDuration = end.Add(24 * time.Hour).Sub(start)

            if matchesPrevDay {
                startOvernight := start.AddDate(0, 0, -1)
                if (now.Equal(startOvernight) || now.After(startOvernight)) && now.Before(end) {
                    isMatch = true
                }
            }

            if matchesCurrentDay {
                if (now.Equal(start) || now.After(start)) && now.Before(end.AddDate(0, 0, 1)) {
                    isMatch = true
                }
            }
        }

        if isMatch {
            if bestDuration == -1 || windowDuration < bestDuration {
                bestDuration = windowDuration
                r := rule
                bestMatch = &r
            }
        }
    }

    if bestMatch != nil {
        return bestMatch.Action, nil
    }

    if s.Mode == models.ScheduleModeWhitelist {
        return models.ActionBlock, nil
    }

    return models.ActionAllow, nil
}

// NextStateChange calculates the exact next timestamp when the schedule action will transition.
func NextStateChange(s models.Schedule, now time.Time) (time.Time, error) {
    loc, err := time.LoadLocation(s.Timezone)
    if err != nil {
        loc = time.UTC
    }
    now = now.In(loc)

    currentAction, _ := Evaluate(s, now)

    var transitionPoints []time.Time
    year, month, day := now.Date()

    for i := 0; i < 8; i++ {
        baseDate := time.Date(year, month, day+i, 0, 0, 0, 0, loc)

        for _, rule := range s.Rules {
            // LIAS-SCH-09 Fix: Check calendar date transitions
            if rule.StartDate != "" && rule.EndDate != "" {
                startDt, err1 := time.ParseInLocation("2006-01-02", rule.StartDate, loc)
                endDt, err2 := time.ParseInLocation("2006-01-02", rule.EndDate, loc)
                if err1 == nil && err2 == nil {
                    endDt = endDt.AddDate(0, 0, 1) // Include full end date
                    if baseDate.Before(startDt) || baseDate.After(endDt) {
                        continue
                    }
                }
            }

            if startT, err := time.Parse("15:04", rule.StartTime); err == nil {
                t := time.Date(baseDate.Year(), baseDate.Month(), baseDate.Day(), startT.Hour(), startT.Minute(), 0, 0, loc)
                if t.After(now) {
                    transitionPoints = append(transitionPoints, t)
                }
            }

            if endT, err := time.Parse("15:04", rule.EndTime); err == nil {
                t := time.Date(baseDate.Year(), baseDate.Month(), baseDate.Day(), endT.Hour(), endT.Minute(), 0, 0, loc)
                if t.After(now) {
                    transitionPoints = append(transitionPoints, t)
                }
            }
        }
    }

    if len(transitionPoints) == 0 {
        return now.Add(24 * time.Hour), nil
    }

    sort.Slice(transitionPoints, func(i, j int) bool {
        return transitionPoints[i].Before(transitionPoints[j])
    })

    for _, t := range transitionPoints {
        nextAction, _ := Evaluate(s, t.Add(1*time.Second))
        if nextAction != currentAction {
            return t, nil
        }
    }

    return now.Add(24 * time.Hour), nil
}
