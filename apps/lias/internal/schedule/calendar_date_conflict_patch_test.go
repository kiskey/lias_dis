package schedule

import (
	"github.com/user/lias-dis/shared/models"
	"testing"
	"time"
)

func TestCalendarOvernightContinuesAfterMidnight(t *testing.T) {
	s := models.Schedule{ID: "calendar-overnight", Mode: models.ScheduleModeDowntime, Timezone: "UTC", Rules: []models.ScheduleRule{{StartDate: "2026-08-10", EndDate: "2026-08-10", StartTime: "22:00", EndTime: "06:00", Action: models.ActionBlock}}}
	for _, tc := range []struct {
		at   string
		want models.Action
	}{{"2026-08-10T23:30:00Z", models.ActionBlock}, {"2026-08-11T02:00:00Z", models.ActionBlock}, {"2026-08-11T06:00:00Z", models.ActionAllow}} {
		at, _ := time.Parse(time.RFC3339, tc.at)
		got, err := Evaluate(s, at)
		if err != nil || got != tc.want {
			t.Fatalf("%s got=%s err=%v want=%s", tc.at, got, err, tc.want)
		}
	}
}
