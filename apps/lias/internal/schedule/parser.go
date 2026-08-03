// Package schedule implements time-based rule parsing and evaluation for LIAS.
//
// File:    apps/lias/internal/schedule/parser.go
// Version: 1.5
package schedule

import (
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
//
// Handles both:
// 1. Scheduled Whitelist Mode (Action: ALLOW rules) -> Default state outside windows is BLOCK.
// 2. Scheduled Downtime Mode (Action: BLOCK rules)  -> Default state outside windows is ALLOW.
func Evaluate(s models.Schedule, now time.Time) (models.Action, error) {
	loc, err := time.LoadLocation(s.Timezone)
	if err != nil {
		loc = time.UTC
	}
	now = now.In(loc)

	var bestMatch *models.ScheduleRule
	var bestDuration time.Duration = -1

	for _, rule := range s.Rules {
		matchesDay := false
		currentWeekday := now.Weekday()
		prevWeekday := (now.Weekday() + 6) % 7 // Day prior to handle overnight windows starting yesterday

		for _, dayStr := range rule.Days {
			dLower := strings.ToLower(strings.TrimSpace(dayStr))
			if day, ok := dayMap[dLower]; ok {
				if day == currentWeekday || day == prevWeekday {
					matchesDay = true
					break
				}
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

		// Calculate start and end time boundaries relative to current day
		year, month, day := now.Date()
		start := time.Date(year, month, day, startTime.Hour(), startTime.Minute(), 0, 0, loc)
		end := time.Date(year, month, day, endTime.Hour(), endTime.Minute(), 0, 0, loc)

		isMatch := false
		var windowDuration time.Duration

		if end.After(start) {
			// Normal same-day window (e.g., 12:00 to 18:00)
			isMatch = (now.Equal(start) || now.After(start)) && now.Before(end)
			windowDuration = end.Sub(start)
		} else {
			// Cross-midnight window (e.g., 22:00 to 06:00)
			startOvernight := start.AddDate(0, 0, -1) // Yesterday's start

			isMatchYesterday := (now.Equal(startOvernight) || now.After(startOvernight)) && now.Before(end)
			isMatchToday := (now.Equal(start) || now.After(start)) && now.Before(end.AddDate(0, 0, 1))

			isMatch = isMatchYesterday || isMatchToday
			windowDuration = end.Add(24 * time.Hour).Sub(start)
		}

		if isMatch {
			// Narrowest window wins precedence
			if bestDuration == -1 || windowDuration < bestDuration {
				bestDuration = windowDuration
				r := rule
				bestMatch = &r
			}
		}
	}

	// 1. If a rule window is currently active, enforce the rule's specified action (ALLOW or BLOCK)
	if bestMatch != nil {
		return bestMatch.Action, nil
	}

	// 2. DYNAMIC DEFAULT FALLBACK (When outside all configured windows):
	// Check if the schedule contains any ALLOW rules or explicitly declares Whitelist Mode
	hasAllowRules := false
	for _, r := range s.Rules {
		if r.Action == models.ActionAllow {
			hasAllowRules = true
			break
		}
	}

	// If schedule is Whitelist Mode: default state outside window is BLOCK.
	if hasAllowRules || s.Mode == models.ScheduleModeWhitelist {
		return models.ActionBlock, nil
	}

	// If schedule is Downtime Mode: default state outside window is ALLOW.
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
