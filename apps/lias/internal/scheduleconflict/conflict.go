// Package scheduleconflict provides conflict detection and multi-schedule projection logic for LIAS.
//
// File:    apps/lias/internal/scheduleconflict/conflict.go
// Version: 1.1
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

type Segment struct {
	Start         int
	End           int
	Action        models.Action
	ScheduleID    string
	ScheduleName  string
	SourceRuleIdx int
}

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

func MinuteOfWeek(weekday time.Weekday, hour, min int) int {
	return int(weekday)*1440 + hour*60 + min
}

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

func ProjectSchedule(s models.Schedule) ([]Segment, error) {
	var segments []Segment

	for ruleIdx, rule := range s.Rules {
		// Calendar-date rules are checked by the date-aware pass below.
		if rule.StartDate != "" && rule.EndDate != "" {
			continue
		}
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
			continue
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

	// GAP-L-CR03 Fix: Reject bundles with mixed timezones to prevent silent evaluation shifts
	bundleTimezone := schedules[0].Timezone
	for _, s := range schedules {
		if s.Timezone != bundleTimezone {
			return models.Schedule{}, nil, fmt.Errorf("cannot merge schedules with mixed timezones: expected %s, got %s for schedule %s", bundleTimezone, s.Timezone, s.Name)
		}
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

	calendarConflicts := detectCalendarConflicts(schedules)
	conflicts = append(conflicts, calendarConflicts...)

	mode := models.ScheduleModeDowntime
	if hasWhitelist {
		mode = models.ScheduleModeWhitelist
	}

	composite := models.Schedule{
		ID:       strings.Join(schedIDs, "+"),
		Name:     strings.Join(schedNames, " + "),
		Mode:     mode,
		Timezone: bundleTimezone,
		Rules:    mergedRules,
	}

	if len(conflicts) > 0 {
		return composite, conflicts, fmt.Errorf("schedule conflict detected: %d overlapping contradictory window(s)", len(conflicts))
	}

	return composite, nil, nil
}

type calendarOccurrence struct{ Start, End time.Time }

func isCalendarRule(rule models.ScheduleRule) bool { return rule.StartDate != "" && rule.EndDate != "" }
func normalizedDate(t time.Time) time.Time {
	return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC)
}

func occurrenceForRule(rule models.ScheduleRule, base time.Time) (calendarOccurrence, bool) {
	base = normalizedDate(base)
	if isCalendarRule(rule) {
		start, e1 := time.Parse("2006-01-02", rule.StartDate)
		end, e2 := time.Parse("2006-01-02", rule.EndDate)
		if e1 != nil || e2 != nil || base.Before(start) || base.After(end) {
			return calendarOccurrence{}, false
		}
	} else {
		match := false
		for _, d := range rule.Days {
			if wd, ok := dayToWeekday[strings.ToLower(strings.TrimSpace(d))]; ok && wd == base.Weekday() {
				match = true
				break
			}
		}
		if !match {
			return calendarOccurrence{}, false
		}
	}
	st, e1 := time.Parse("15:04", rule.StartTime)
	et, e2 := time.Parse("15:04", rule.EndTime)
	if e1 != nil || e2 != nil || rule.StartTime == rule.EndTime {
		return calendarOccurrence{}, false
	}
	start := time.Date(base.Year(), base.Month(), base.Day(), st.Hour(), st.Minute(), 0, 0, time.UTC)
	end := time.Date(base.Year(), base.Month(), base.Day(), et.Hour(), et.Minute(), 0, 0, time.UTC)
	if !end.After(start) {
		end = end.AddDate(0, 0, 1)
	}
	return calendarOccurrence{Start: start, End: end}, true
}

func addRepresentativeDates(dst map[string]time.Time, rule models.ScheduleRule) {
	if !isCalendarRule(rule) {
		return
	}
	start, e1 := time.Parse("2006-01-02", rule.StartDate)
	end, e2 := time.Parse("2006-01-02", rule.EndDate)
	if e1 != nil || e2 != nil || end.Before(start) {
		return
	}
	add := func(d time.Time) { d = normalizedDate(d); dst[d.Format("2006-01-02")] = d }
	for i := -1; i <= 8; i++ {
		d := start.AddDate(0, 0, i)
		if d.After(end.AddDate(0, 0, 1)) {
			break
		}
		add(d)
	}
	for i := -1; i <= 1; i++ {
		add(end.AddDate(0, 0, i))
	}
}

func detectCalendarConflicts(schedules []models.Schedule) []Conflict {
	var out []Conflict
	seen := map[string]bool{}
	for si, sa := range schedules {
		for ri, ra := range sa.Rules {
			for sj := si; sj < len(schedules); sj++ {
				sb := schedules[sj]
				startRule := 0
				if sj == si {
					startRule = ri + 1
				}
				for rj := startRule; rj < len(sb.Rules); rj++ {
					rb := sb.Rules[rj]
					if ra.Action == rb.Action || (!isCalendarRule(ra) && !isCalendarRule(rb)) {
						continue
					}
					dates := map[string]time.Time{}
					addRepresentativeDates(dates, ra)
					addRepresentativeDates(dates, rb)
					var oa, ob []calendarOccurrence
					for _, d := range dates {
						for _, base := range []time.Time{d.AddDate(0, 0, -1), d, d.AddDate(0, 0, 1)} {
							if o, ok := occurrenceForRule(ra, base); ok {
								oa = append(oa, o)
							}
							if o, ok := occurrenceForRule(rb, base); ok {
								ob = append(ob, o)
							}
						}
					}
					for _, a := range oa {
						for _, b := range ob {
							start := a.Start
							if b.Start.After(start) {
								start = b.Start
							}
							end := a.End
							if b.End.Before(end) {
								end = b.End
							}
							if !start.Before(end) {
								continue
							}
							key := fmt.Sprintf("%s|%d|%s|%d|%s|%s", sa.ID, ri, sb.ID, rj, start.Format(time.RFC3339), end.Format(time.RFC3339))
							if seen[key] {
								continue
							}
							seen[key] = true
							out = append(out, Conflict{ScheduleAID: sa.ID, ScheduleAName: sa.Name, ScheduleBID: sb.ID, ScheduleBName: sb.Name, Day: start.Format("2006-01-02"), OverlapStart: start.Format("15:04"), OverlapEnd: end.Format("15:04"), ActionA: ra.Action, ActionB: rb.Action})
						}
					}
				}
			}
		}
	}
	return out
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
