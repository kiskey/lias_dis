package identitymigration

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/user/lias-dis/apps/lias/internal/policy"
	"github.com/user/lias-dis/apps/lias/internal/schedule"
	"github.com/user/lias-dis/apps/lias/internal/storage"
	liasSync "github.com/user/lias-dis/apps/lias/internal/sync"
	"github.com/user/lias-dis/apps/lias/internal/tags"
	"github.com/user/lias-dis/shared/models"
)

func TestCoordinatorMigratesFullFixtureImmediatelyAndAfterRestart(t *testing.T) {
	store, err := storage.NewStorage(filepath.Join(t.TempDir(), "migration.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	const oldPDID, newPDID = "pdid_old", "pdid_new"
	if err := store.SaveDeviceTags(oldPDID, []string{"kids", "infrastructure"}, "02:00:00:00:00:01"); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveDeviceTags(newPDID, []string{"trusted"}, "02:00:00:00:00:02"); err != nil {
		t.Fatal(err)
	}
	_ = store.SaveDeviceOverride(oldPDID, "Source Name")
	_ = store.SaveDeviceOverride(newPDID, "Target Name")
	_ = store.SaveUser(models.User{ID: "source_user", Name: "Source User"})
	_ = store.SaveUser(models.User{ID: "target_user", Name: "Target User"})
	_ = store.AssignDeviceToUser(oldPDID, "source_user")
	_ = store.AssignDeviceToUser(newPDID, "target_user")
	_ = store.SaveFlowLog(oldPDID, models.ActionBlock, 10)
	_ = store.SaveFlowLog(newPDID, models.ActionAllow, 20)

	now := time.Now()
	policies := []models.Policy{
		{ID: "source_block", Name: "Source block", Type: models.PolicyTypeDevice, TargetID: oldPDID, Action: models.ActionBlock, Priority: 10, Enabled: true},
		{ID: "target_allow", Name: "Target allow", Type: models.PolicyTypeDevice, TargetID: newPDID, Action: models.ActionAllow, Priority: 20, Enabled: true},
		{ID: "pol_pause_" + oldPDID, Name: "Pause", Type: models.PolicyTypeDevice, TargetID: oldPDID, Action: models.ActionBlock, Priority: 1000, Enabled: true, ExpiresAt: ptrTime(now.Add(time.Hour))},
	}
	engine := policy.NewEngine()
	for _, item := range policies {
		engine.UpsertPolicy(item)
		if err := store.SavePolicy(item); err != nil {
			t.Fatal(err)
		}
	}
	cache := liasSync.NewCache()
	cache.UpsertDevice(models.Device{PDID: oldPDID, FriendlyName: "Source Name", UserID: "source_user", MACs: []string{"02:00:00:00:00:01"}})
	cache.UpsertDevice(models.Device{PDID: newPDID, FriendlyName: "Target Name", UserID: "target_user", MACs: []string{"02:00:00:00:00:02"}})
	cache.SetTags(oldPDID, []string{"kids", "infrastructure"})
	cache.SetTags(newPDID, []string{"trusted"})

	coordinator := New(store, cache, engine)
	result, err := coordinator.MigrateIdentity(oldPDID, newPDID, []string{"02:00:00:00:00:01"})
	if err != nil {
		t.Fatal(err)
	}
	if result.Replayed || result.Conflicts == 0 {
		t.Fatalf("migration result=%+v", result)
	}
	if cache.Get(oldPDID) != nil {
		t.Fatal("obsolete cache identity survived")
	}
	target := cache.Get(newPDID)
	if target == nil || target.FriendlyName != "Target Name" || target.UserID != "target_user" ||
		!target.HasTag("kids") || !target.HasTag("trusted") || !target.HasTag("infrastructure") {
		t.Fatalf("target cache=%+v", target)
	}
	if _, exists := engine.GetPolicy("pol_pause_" + oldPDID); exists {
		t.Fatal("old temporary policy ID survived")
	}
	if migrated, exists := engine.GetPolicy("pol_pause_" + newPDID); !exists || migrated.TargetID != newPDID {
		t.Fatalf("temporary policy not retargeted: %+v exists=%v", migrated, exists)
	}
	if got := engine.EvaluateAction(target, nil); got != models.ActionAllow {
		t.Fatalf("infrastructure immunity changed immediately: %q", got)
	}

	overrides, _ := store.LoadDeviceOverrides()
	assignments, _ := store.LoadUserAssignments()
	if overrides[oldPDID] != "" || overrides[newPDID] != "Target Name" || assignments[oldPDID] != "" || assignments[newPDID] != "target_user" {
		t.Fatalf("overrides=%v assignments=%v", overrides, assignments)
	}
	if logs, _ := store.GetDeviceFlowLogs(oldPDID, 100); len(logs) != 0 {
		t.Fatalf("source logs survived: %+v", logs)
	}
	if err := store.SaveFlowLog(oldPDID, models.ActionBlock, 30); err != nil {
		t.Fatal(err)
	}
	if logs, _ := store.GetDeviceFlowLogs(newPDID, 100); len(logs) != 3 {
		t.Fatalf("flow continuity lost: %+v", logs)
	}

	replay, err := coordinator.MigrateIdentity(oldPDID, newPDID, []string{"02:00:00:00:00:01"})
	if err != nil || !replay.Replayed || replay.Conflicts != result.Conflicts {
		t.Fatalf("replay=%+v err=%v", replay, err)
	}

	restartTags := tags.NewManager()
	restartPolicies := policy.NewEngine()
	restartCache := liasSync.NewCache()
	restartSchedules := schedule.NewEngine(restartCache, restartPolicies, make(chan struct{}, 1))
	pdidTags, macTags, err := store.LoadHydrate(restartTags, restartPolicies, restartSchedules)
	if err != nil {
		t.Fatal(err)
	}
	restartCache.LoadStickyTags(pdidTags, macTags)
	restartCache.UpsertDevice(models.Device{PDID: newPDID, MACs: []string{"02:00:00:00:00:01", "02:00:00:00:00:02"}})
	restarted := restartCache.Get(newPDID)
	if restarted == nil || !restarted.HasTag("infrastructure") || restartPolicies.EvaluateAction(restarted, restartSchedules) != models.ActionAllow {
		t.Fatalf("restart enforcement changed: device=%+v", restarted)
	}
}

func ptrTime(value time.Time) *time.Time { return &value }
