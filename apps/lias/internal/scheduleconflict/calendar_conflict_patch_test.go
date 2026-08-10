package scheduleconflict

import (
	"github.com/user/lias-dis/shared/models"
	"testing"
)

func TestCalendarVsWeeklyContradictionIsDetected(t *testing.T) {
	d := models.Schedule{ID: "date", Mode: models.ScheduleModeWhitelist, Timezone: "UTC", Rules: []models.ScheduleRule{{StartDate: "2026-08-10", EndDate: "2026-08-15", StartTime: "19:00", EndTime: "20:00", Action: models.ActionAllow}}}
	w := models.Schedule{ID: "weekly", Mode: models.ScheduleModeDowntime, Timezone: "UTC", Rules: []models.ScheduleRule{{Days: []string{"mon"}, StartTime: "19:30", EndTime: "20:30", Action: models.ActionBlock}}}
	_, c, e := MergeSchedules([]models.Schedule{d, w})
	if e == nil || len(c) == 0 {
		t.Fatalf("missed calendar conflict: %+v %v", c, e)
	}
}
func TestCalendarRuleWithDaysNotProjectedWeekly(t *testing.T) {
	s := models.Schedule{ID: "finite", Mode: models.ScheduleModeDowntime, Timezone: "UTC", Rules: []models.ScheduleRule{{Days: []string{"mon"}, StartDate: "2026-08-10", EndDate: "2026-08-10", StartTime: "18:00", EndTime: "19:00", Action: models.ActionBlock}}}
	segs, e := ProjectSchedule(s)
	if e != nil || len(segs) != 0 {
		t.Fatalf("calendar leaked weekly: %+v %v", segs, e)
	}
}
