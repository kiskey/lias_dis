package api

import (
	"github.com/user/lias-dis/shared/models"
	"testing"
)

func validPatchSchedule() models.Schedule {
	return models.Schedule{Mode: models.ScheduleModeDowntime, Timezone: "UTC", Rules: []models.ScheduleRule{{Days: []string{"mon"}, StartTime: "18:00", EndTime: "19:00", Action: models.ActionBlock}}}
}
func TestPatchScheduleValidation(t *testing.T) {
	s := validPatchSchedule()
	s.Rules[0].Days = nil
	s.Rules[0].StartDate = "2026-08-10"
	if validateScheduleRules(&s) == nil {
		t.Fatal("partial date accepted")
	}
	s = validPatchSchedule()
	s.Rules[0].Days = []string{"funday"}
	if validateScheduleRules(&s) == nil {
		t.Fatal("bad day accepted")
	}
	s = validPatchSchedule()
	s.Rules[0].Action = models.Action("maybe")
	if validateScheduleRules(&s) == nil {
		t.Fatal("bad action accepted")
	}
}
