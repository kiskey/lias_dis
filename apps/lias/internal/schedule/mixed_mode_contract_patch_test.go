package schedule

import (
	"github.com/user/lias-dis/apps/lias/internal/scheduleconflict"
	"github.com/user/lias-dis/shared/models"
	"testing"
	"time"
)

func TestMixedWhitelistDowntimeBundleDefaultsBlockOutsideWindows(t *testing.T) {
	b := models.Schedule{ID: "block", Mode: models.ScheduleModeDowntime, Timezone: "UTC", Rules: []models.ScheduleRule{{Days: []string{"mon"}, StartTime: "18:00", EndTime: "19:00", Action: models.ActionBlock}}}
	a := models.Schedule{ID: "allow", Mode: models.ScheduleModeWhitelist, Timezone: "UTC", Rules: []models.ScheduleRule{{Days: []string{"mon"}, StartTime: "20:00", EndTime: "21:00", Action: models.ActionAllow}}}
	m, c, e := scheduleconflict.MergeSchedules([]models.Schedule{b, a})
	if e != nil || len(c) != 0 {
		t.Fatalf("merge %+v %v", c, e)
	}
	if m.Mode != models.ScheduleModeWhitelist {
		t.Fatalf("mode %s", m.Mode)
	}
	at := time.Date(2026, 8, 10, 17, 0, 0, 0, time.UTC)
	g, e := Evaluate(m, at)
	if e != nil || g != models.ActionBlock {
		t.Fatalf("got %s %v", g, e)
	}
}
