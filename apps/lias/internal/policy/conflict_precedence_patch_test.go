package policy

import (
	liasSync "github.com/user/lias-dis/apps/lias/internal/sync"
	"github.com/user/lias-dis/shared/models"
	"testing"
	"time"
)

type patchScheduleEval struct{}

func (*patchScheduleEval) EvaluateNow(string) models.Action      { return models.ActionBlock }
func (*patchScheduleEval) EvaluateBundle([]string) models.Action { return models.ActionBlock }
func pd(tags ...string) *liasSync.LocalDevice {
	return &liasSync.LocalDevice{Device: models.Device{PDID: "pdid_test"}, Tags: tags}
}
func TestEqualPriorityDevicePoliciesDeterministicFailClosed(t *testing.T) {
	e := NewEngine()
	now := time.Now()
	e.UpsertPolicy(models.Policy{ID: "allow", Type: models.PolicyTypeDevice, TargetID: "pdid_test", Action: models.ActionAllow, Priority: 10, Enabled: true, UpdatedAt: now})
	e.UpsertPolicy(models.Policy{ID: "block", Type: models.PolicyTypeDevice, TargetID: "pdid_test", Action: models.ActionBlock, Priority: 10, Enabled: true, UpdatedAt: now})
	for i := 0; i < 100; i++ {
		if g := e.EvaluateAction(pd(), nil); g != models.ActionBlock {
			t.Fatalf("%d got %s", i, g)
		}
	}
}
func TestTagExtensionPriorityOverridesSameTagBase(t *testing.T) {
	e := NewEngine()
	e.UpsertPolicy(models.Policy{ID: "base", Type: models.PolicyTypeTag, TargetID: "kids", Action: models.ActionBlock, Priority: 10, Enabled: true})
	e.UpsertPolicy(models.Policy{ID: "pol_extend_tag_kids", Type: models.PolicyTypeTag, TargetID: "kids", Action: models.ActionAllow, Priority: 2000, Enabled: true})
	if g := e.EvaluateAction(pd("kids"), nil); g != models.ActionAllow {
		t.Fatalf("got %s", g)
	}
}
func TestCrossTagBlockStillWins(t *testing.T) {
	e := NewEngine()
	e.UpsertPolicy(models.Policy{ID: "a", Type: models.PolicyTypeTag, TargetID: "kids", Action: models.ActionAllow, Priority: 100, Enabled: true})
	e.UpsertPolicy(models.Policy{ID: "b", Type: models.PolicyTypeTag, TargetID: "restricted", Action: models.ActionBlock, Priority: 1, Enabled: true})
	if g := e.EvaluateAction(pd("kids", "restricted"), nil); g != models.ActionBlock {
		t.Fatalf("got %s", g)
	}
}
func TestEmptyDeviceScheduleFailsClosed(t *testing.T) {
	e := NewEngine()
	e.UpsertPolicy(models.Policy{ID: "empty", Type: models.PolicyTypeDevice, TargetID: "pdid_test", Action: models.ActionSchedule, Priority: 10, Enabled: true})
	if g := e.EvaluateAction(pd(), &patchScheduleEval{}); g != models.ActionBlock {
		t.Fatalf("got %s", g)
	}
}
