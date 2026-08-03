// Package scheduleconflict provides unit tests for conflict detection and multi-schedule projection.
//
// File:    apps/lias/internal/scheduleconflict/conflict_test.go
// Version: 1.0
package scheduleconflict

import (
	"testing"

	"github.com/user/lias-dis/shared/models"
)

func TestWorkedExampleConflict(t *testing.T) {
	// Schedule A: Bedtime (downtime mode, Mon-Fri 21:00-07:00 block)
	schedA := models.Schedule{
		ID:       "sched_bedtime01",
		Name:     "Bedtime",
		Mode:     models.ScheduleModeDowntime,
		Timezone: "UTC",
		Rules: []models.ScheduleRule{
			{
				Days:      []string{"mon", "tue", "wed", "thu", "fri"},
				StartTime: "21:00",
				EndTime:   "07:00",
				Action:    models.ActionBlock,
			},
		},
	}

	// Schedule B: Gaming Hour (whitelist mode, Mon-Fri 22:00-23:00 allow)
	schedB := models.Schedule{
		ID:       "sched_gaming02",
		Name:     "Gaming Hour",
		Mode:     models.ScheduleModeWhitelist,
		Timezone: "UTC",
		Rules: []models.ScheduleRule{
			{
				Days:      []string{"mon", "tue", "wed", "thu", "fri"},
				StartTime: "22:00",
				EndTime:   "23:00",
				Action:    models.ActionAllow,
			},
		},
	}

	_, conflicts, err := MergeSchedules([]models.Schedule{schedA, schedB})
	if err == nil {
		t.Fatalf("Expected conflict error, got nil")
	}

	if len(conflicts) == 0 {
		t.Fatalf("Expected at least one conflict, got 0")
	}

	foundMon22 := false
	for _, c := range conflicts {
		if c.Day == "monday" && c.OverlapStart == "22:00" && c.OverlapEnd == "23:00" {
			foundMon22 = true
			if c.ActionA != models.ActionBlock || c.ActionB != models.ActionAllow {
				t.Errorf("Unexpected actions in conflict: ActionA=%s, ActionB=%s", c.ActionA, c.ActionB)
			}
		}
	}

	if !foundMon22 {
		t.Errorf("Expected conflict on Monday 22:00-23:00, conflicts reported: %+v", conflicts)
	}
}

func TestSameActionOverlapAllowed(t *testing.T) {
	schedA := models.Schedule{
		ID:       "sched_1",
		Name:     "Downtime 1",
		Mode:     models.ScheduleModeDowntime,
		Timezone: "UTC",
		Rules: []models.ScheduleRule{
			{
				Days:      []string{"mon"},
				StartTime: "15:00",
				EndTime:   "17:00",
				Action:    models.ActionBlock,
			},
		},
	}

	schedB := models.Schedule{
		ID:       "sched_2",
		Name:     "Downtime 2",
		Mode:     models.ScheduleModeDowntime,
		Timezone: "UTC",
		Rules: []models.ScheduleRule{
			{
				Days:      []string{"mon"},
				StartTime: "16:00",
				EndTime:   "18:00",
				Action:    models.ActionBlock,
			},
		},
	}

	_, conflicts, err := MergeSchedules([]models.Schedule{schedA, schedB})
	if err != nil {
		t.Fatalf("Unexpected error for same-action overlap: %v", err)
	}
	if len(conflicts) > 0 {
		t.Fatalf("Expected 0 conflicts for same-action overlap, got %d", len(conflicts))
	}
}

func TestWrapAroundOvernightProjection(t *testing.T) {
	sched := models.Schedule{
		ID:       "sched_overnight",
		Name:     "Weekend Night",
		Mode:     models.ScheduleModeDowntime,
		Timezone: "UTC",
		Rules: []models.ScheduleRule{
			{
				Days:      []string{"sat"},
				StartTime: "22:00",
				EndTime:   "06:00",
				Action:    models.ActionBlock,
			},
		},
	}

	segs, err := ProjectSchedule(sched)
	if err != nil {
		t.Fatalf("Failed to project overnight schedule: %v", err)
	}

	if len(segs) != 2 {
		t.Fatalf("Expected 2 segments for overnight rule, got %d", len(segs))
	}

	// Saturday is day 6. Segment 1: Sat 22:00 to 24:00 -> 6*1440+1320 = 9960 to 7*1440 = 10080
	if segs[0].Start != 9960 || segs[0].End != 10080 {
		t.Errorf("Segment 0 expected [9960, 10080), got [%d, %d)", segs[0].Start, segs[0].End)
	}

	// Sunday is day 0. Segment 2: Sun 00:00 to 06:00 -> 0 to 360
	if segs[1].Start != 0 || segs[1].End != 360 {
		t.Errorf("Segment 1 expected [0, 360), got [%d, %d)", segs[1].Start, segs[1].End)
	}
}
