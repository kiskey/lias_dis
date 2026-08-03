// Package scheduleconflict provides conflict detection and multi-schedule projection logic for LIAS.
//
// File:    apps/lias/internal/scheduleconflict/conflict.go
// Version: 1.0
package scheduleconflict

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/user/lias-dis/shared/models"
)

var dayToWeekday = map[string]time.Weekday{
	"sun":       time.Sunday,
	"sunday":    time.Sunday,
	"mon":       time.Monday,
	"monday":    time.Monday,
	"tue":       time.Tuesday,
	"tuesday":   time.Tuesday,
	"wed":       time.Wednesday,
	"wednesday": time.Wednesday,
	"thu":       time.Thursday,
	"thursday":  time.Thursday,
	"fri":       time.Friday,
	"friday":    time.Friday,
	"sat":       time.Saturday,
	"saturday":  time.Saturday,
}

// Segment represents a non-wrapping time range [Start, End) in week-minutes (0..10079).
type Segment struct {
	Start         int
	End           int
	Action        models.Action
	ScheduleID    string
	ScheduleName  string
	SourceRuleIdx int
}

// Conflict describes a time window where two schedule rules collide with opposing actions.
type Conflict struct {
	ScheduleAID   string        `json:"schedule_a_id"`
	ScheduleAName string        `json:"schedule_a_name"`
	ScheduleBID   string        `json:"schedule_b_id"`
	ScheduleBName string        `json:"schedule_b_name"`
	Day           string        `json:"day"`
	OverlapStart  string        `json:"overlap_start"`
	OverlapEnd    string        `json:"overlap_end"`
	ActionA       models.Action `json:"action_a"`
	ActionB       models.Action `json:"action_b"`
}

// MinuteOfWeek calculates minute index (0..10079) for a weekday and time.
func MinuteOfWeek(weekday time.Weekday, hour, min int) int {
	return int(weekday)*1440 + hour*60 + min
}

// FormatMinuteOfWeek converts a minute of week index to (dayName, "HH:MM").
func FormatMinuteOfWeek(m int) (string, string) {
	m = ((m % 10080) + 10080) % 10080
	dayIdx := m / 1440
	minOfDay := m % 1440
	hh := minOfDay / 60
	mm := minOfDay % 60

	days := []string{"sunday", "monday", "tuesday", "wednesday", "thursday", "friday", "saturday"}
	dayStr := days[dayIdx]
	timeStr := fmt.Sprintf("%02d:%02d", hh, mm)
	return dayStr, timeStr
}

// ProjectSchedule converts a Schedule into a slice of non-wrapping week-minute segments.
func ProjectSchedule(s models.Schedule) ([]Segment, error) {
	var segments []Segment

	for ruleIdx, rule := range s.Rules {
		startT, err := time.Parse("15:04", rule.StartTime)
		if err != nil {
			return nil, fmt.Errorf("invalid start_time %q in rule %d: %w", rule.StartTime, ruleIdx, err)
		}
		endT, err := time.Parse("15:04", rule.EndTime)
		if err != nil {
			return nil, fmt.Errorf("invalid end_time %q in rule %d: %w", rule.EndTime, ruleIdx, err)
		}

		startMinOfDay := startT.Hour()*60 + startT.Minute()
		endMinOfDay := endT.Hour()*60 + endT.Minute()

		if startMinOfDay == endMinOfDay {
			continue // Zero duration window
		}

		for _, dayStr := range rule.Days {
			dLower := strings.ToLower(strings.TrimSpace(dayStr))
			weekday, ok := dayToWeekday[dLower]
			if !ok {
				continue
			}

			dayIdx := int(weekday)

			if startMinOfDay < endMinOfDay {
				startW := dayIdx*1440 + startMinOfDay
				endW := dayIdx*1440 + endMinOfDay
				segments = append(segments, Segment{
					Start:         startW,
					End:           endW,
					Action:        rule.Action,
					ScheduleID:    s.ID,
					ScheduleName:  s.Name,
					SourceRuleIdx: ruleIdx,
				})
			} else {
				// Overnight window (e.g. 22:00 -> 06:00)
				// Segment 1: startMinOfDay to midnight (1440) on current day
				startW1 := dayIdx*1440 + startMinOfDay
				endW1 := (dayIdx + 1) * 1440
				segments = append(segments, Segment{
					Start:         startW1,
					End:           endW1,
					Action:        rule.Action,
					ScheduleID:    s.ID,
					ScheduleName:  s.Name,
					SourceRuleIdx: ruleIdx,
				})

				// Segment 2: midnight (0) to endMinOfDay on next day
				nextDayIdx := (dayIdx + 1) % 7
				startW2 := nextDayIdx * 1440
				endW2 := nextDayIdx*1440 + endMinOfDay
				segments = append(segments, Segment{
					Start:         startW2,
					End:           endW2,
					Action:        rule.Action,
					ScheduleID:    s.ID,
					ScheduleName:  s.Name,
					SourceRuleIdx: ruleIdx,
				})
			}
		}
	}

	return segments, nil
}

// MergeSchedules projects N schedules into composite segments, verifies conflict-freedom,
// and returns a merged composite models.Schedule.
func MergeSchedules(schedules []models.Schedule) (models.Schedule, []Conflict, error) {
	if len(schedules) == 0 {
		return models.Schedule{}, nil, nil
	}

	var allSegments []Segment
	var mergedRules []models.ScheduleRule
	var schedNames []string
	var schedIDs []string

	hasWhitelist := false

	for _, s := range schedules {
		schedNames = append(schedNames, s.Name)
		schedIDs = append(schedIDs, s.ID)

		if s.Mode == models.ScheduleModeWhitelist {
			hasWhitelist = true
		}

		segs, err := ProjectSchedule(s)
		if err != nil {
			return models.Schedule{}, nil, err
		}
		allSegments = append(allSegments, segs...)

		for _, r := range s.Rules {
			if r.Action == models.ActionAllow {
				hasWhitelist = true
			}
			mergedRules = append(mergedRules, r)
		}
	}

	// Sweep-line conflict detection
	sort.Slice(allSegments, func(i, j int) bool {
		if allSegments[i].Start == allSegments[j].Start {
			return allSegments[i].End < allSegments[j].End
		}
		return allSegments[i].Start < allSegments[j].Start
	})

	var conflicts []Conflict
	seenConflicts := make(map[string]bool)

	for i := 0; i < len(allSegments); i++ {
		for j := i + 1; j < len(allSegments); j++ {
			if allSegments[j].Start >= allSegments[i].End {
				break
			}

			overlapStart := maxInt(allSegments[i].Start, allSegments[j].Start)
			overlapEnd := minInt(allSegments[i].End, allSegments[j].End)

			if overlapStart < overlapEnd {
				if allSegments[i].Action != allSegments[j].Action {
					// Conflict if different schedules OR different rules in same schedule
					if allSegments[i].ScheduleID != allSegments[j].ScheduleID || allSegments[i].SourceRuleIdx != allSegments[j].SourceRuleIdx {
						dayStr, timeStart := FormatMinuteOfWeek(overlapStart)
						_, timeEnd := FormatMinuteOfWeek(overlapEnd)

						cKey := fmt.Sprintf("%s|%s|%s|%s|%s", allSegments[i].ScheduleID, allSegments[j].ScheduleID, dayStr, timeStart, timeEnd)
						if !seenConflicts[cKey] {
							seenConflicts[cKey] = true
							conflicts = append(conflicts, Conflict{
								ScheduleAID:   allSegments[i].ScheduleID,
								ScheduleAName: allSegments[i].ScheduleName,
								ScheduleBID:   allSegments[j].ScheduleID,
								ScheduleBName: allSegments[j].ScheduleName,
								Day:           dayStr,
								OverlapStart:  timeStart,
								OverlapEnd:    timeEnd,
								ActionA:       allSegments[i].Action,
								ActionB:       allSegments[j].Action,
							})
						}
					}
				}
			}
		}
	}

	mode := models.ScheduleModeDowntime
	if hasWhitelist {
		mode = models.ScheduleModeWhitelist
	}

	composite := models.Schedule{
		ID:       strings.Join(schedIDs, "+"),
		Name:     strings.Join(schedNames, " + "),
		Mode:     mode,
		Timezone: schedules[0].Timezone,
		Rules:    mergedRules,
	}

	if len(conflicts) > 0 {
		return composite, conflicts, fmt.Errorf("schedule conflict detected: %d overlapping contradictory window(s)", len(conflicts))
	}

	return composite, nil, nil
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
