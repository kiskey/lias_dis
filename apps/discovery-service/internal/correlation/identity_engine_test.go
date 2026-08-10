package correlation

import (
	"errors"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/user/lias-dis/apps/discovery-service/internal/api"
	"github.com/user/lias-dis/apps/discovery-service/internal/discovery"
	identitycore "github.com/user/lias-dis/apps/discovery-service/internal/identity"
	"github.com/user/lias-dis/apps/discovery-service/internal/inventory"
	"github.com/user/lias-dis/apps/discovery-service/internal/storage"
	"github.com/user/lias-dis/shared/models"
)

func TestPromotionDoesNotRewritePDID(t *testing.T) {
	cache := inventory.NewCache()
	defer cache.Stop()
	broker := api.NewBroker(cache)
	eng := NewEngine(cache, broker)
	d := &models.Device{DeviceID: "dev_test", PDID: "pdid_public", IdentityTier: models.TierTentative,
		CurrentMAC: "00:11:22:33:44:55", MACs: []string{"00:11:22:33:44:55"}}
	cache.Upsert(d)
	eng.promoteDevice(d, models.TierBIA, d.CurrentMAC, "phone", "test")
	if cache.Get("pdid_public") == nil || d.PDID != "pdid_public" {
		t.Fatal("metadata promotion rewrote the public PDID")
	}
}

func TestIdentityCandidateReviewDecisionContract(t *testing.T) {
	cache := inventory.NewCache()
	defer cache.Stop()
	broker := api.NewBroker(cache)
	defer broker.Stop()
	store, err := storage.NewStorage(filepath.Join(t.TempDir(), "review.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	eng := NewEngine(cache, broker)
	eng.SetStorage(store)
	now := time.Now().UTC().Truncate(time.Millisecond)
	source := &models.Device{DeviceID: "dev_source", PDID: "pdid_source", CurrentMAC: "02:00:00:00:00:01",
		MACs: []string{"02:00:00:00:00:01"}, Hostname: "New Phone", Online: true, FirstSeen: now, LastSeen: now}
	target := &models.Device{DeviceID: "dev_target", PDID: "pdid_target", CurrentMAC: "02:00:00:00:00:02",
		MACs: []string{"02:00:00:00:00:02"}, FriendlyName: "Known Phone", Online: true, FirstSeen: now.Add(-time.Hour), LastSeen: now}
	for _, device := range []*models.Device{source, target} {
		if err := store.SaveDevice(device); err != nil {
			t.Fatal(err)
		}
		cache.Upsert(device)
	}
	id, err := store.UpsertIdentityCandidate(models.IdentityCandidateLink{SourcePDID: source.PDID,
		TargetPDID: target.PDID, Probability: .83, Ambiguous: true,
		Factors: []models.IdentityFactor{{Kind: "hostname", Matched: true}, {Kind: "simultaneous_presence", Matched: false}}})
	if err != nil {
		t.Fatal(err)
	}
	detail, err := eng.GetIdentityCandidate(id)
	if err != nil || detail.SourceDevice == nil || detail.TargetDevice == nil || len(detail.Factors) != 1 || len(detail.Conflicts) != 1 {
		t.Fatalf("detail=%+v err=%v", detail, err)
	}
	if _, err := eng.ConfirmIdentityCandidate(id, models.IdentityCandidateDecisionRequest{}); !errors.Is(err, ErrCandidateStaleOrConflicting) {
		t.Fatalf("simultaneously-online devices were mergeable: %v", err)
	}
	target.Online = false
	cache.Upsert(target)
	wrong := "wrong"
	if _, err := eng.ConfirmIdentityCandidate(id, models.IdentityCandidateDecisionRequest{ExpectedSourcePDID: wrong}); !errors.Is(err, ErrCandidateStaleOrConflicting) {
		t.Fatalf("stale expectation accepted: %v", err)
	}
	updated := detail.UpdatedAt
	merged, err := eng.ConfirmIdentityCandidate(id, models.IdentityCandidateDecisionRequest{
		ExpectedSourcePDID: source.PDID, ExpectedTargetPDID: target.PDID, ExpectedUpdatedAt: &updated, DecisionNote: "same phone",
	})
	if err != nil || merged.PDID != target.PDID || cache.Get(source.PDID) != nil {
		t.Fatalf("merge=%+v err=%v", merged, err)
	}
	repeated, err := eng.ConfirmIdentityCandidate(id, models.IdentityCandidateDecisionRequest{})
	if err != nil || repeated.PDID != target.PDID {
		t.Fatalf("confirmation was not idempotent: %+v %v", repeated, err)
	}
	persisted, err := store.GetIdentityCandidate(id)
	if err != nil || persisted.Status != "confirmed" || persisted.DecisionNote != "same phone" {
		t.Fatalf("persisted decision=%+v err=%v", persisted, err)
	}
	if resolved, err := store.ResolvePDID(source.PDID); err != nil || resolved != target.PDID {
		t.Fatalf("redirect=%q err=%v", resolved, err)
	}
	if _, err := eng.ReopenIdentityCandidate(id, models.IdentityCandidateDecisionRequest{}); !errors.Is(err, ErrCandidateStaleOrConflicting) {
		t.Fatalf("confirmed merge was reopened: %v", err)
	}
}

func TestIdentityCandidatePaginationAndReopen(t *testing.T) {
	cache := inventory.NewCache()
	defer cache.Stop()
	broker := api.NewBroker(cache)
	defer broker.Stop()
	store, err := storage.NewStorage(filepath.Join(t.TempDir(), "pages.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	eng := NewEngine(cache, broker)
	eng.SetStorage(store)
	for i := 0; i < 3; i++ {
		if _, err := store.UpsertIdentityCandidate(models.IdentityCandidateLink{SourcePDID: "source_" + string(rune('a'+i)), TargetPDID: "target", Probability: .8}); err != nil {
			t.Fatal(err)
		}
		time.Sleep(time.Millisecond)
	}
	first, err := eng.ListIdentityCandidates("pending", 2, "")
	if err != nil || len(first.Candidates) != 2 || first.NextCursor == "" {
		t.Fatalf("first page=%+v err=%v", first, err)
	}
	second, err := eng.ListIdentityCandidates("pending", 2, first.NextCursor)
	if err != nil || len(second.Candidates) != 1 || second.NextCursor != "" || second.Candidates[0].ID == first.Candidates[0].ID {
		t.Fatalf("second page=%+v err=%v", second, err)
	}
	id := second.Candidates[0].ID
	client := broker.Subscribe("candidate-events", 0)
	defer broker.Unsubscribe("candidate-events")
	if _, err := eng.RejectIdentityCandidate(id, models.IdentityCandidateDecisionRequest{DecisionNote: "different hardware"}); err != nil {
		t.Fatal(err)
	}
	select {
	case event := <-client.Events:
		if event.Type != models.EventIdentityCandidateDecided {
			t.Fatalf("event type=%q", event.Type)
		}
	case <-time.After(time.Second):
		t.Fatal("candidate decision event was not emitted")
	}
	if _, err := eng.ReopenIdentityCandidate(id, models.IdentityCandidateDecisionRequest{DecisionNote: "review again"}); err != nil {
		t.Fatal(err)
	}
	pending, err := eng.GetIdentityCandidate(id)
	if err != nil || pending.Status != "pending" || pending.DecisionNote != "review again" {
		t.Fatalf("reopened=%+v err=%v", pending, err)
	}
	if _, err := eng.ListIdentityCandidates("pending", 2, "not-a-cursor"); err == nil {
		t.Fatal("invalid cursor accepted")
	}
}

func TestAliasActivityRehydratesDurableBaselineThenStaysVolatile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "alias-restart.db")
	initialSeen := time.Now().Add(-time.Hour).UTC().Truncate(time.Millisecond)
	store, err := storage.NewStorage(path)
	if err != nil {
		t.Fatal(err)
	}
	device := &models.Device{DeviceID: "dev_restart", PDID: "pdid_restart", FirstSeen: initialSeen, LastSeen: initialSeen}
	if err := store.SaveDevice(device); err != nil {
		t.Fatal(err)
	}
	hash, err := identitycore.HashAlias(models.AliasMAC, "00:11:22:33:44:55")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.UpsertIdentityAlias(models.IdentityAlias{DeviceID: device.DeviceID, PDID: device.PDID,
		Type: models.AliasMAC, ValueHash: hash, Source: "openwrt_ap", Confidence: .9,
		FirstSeen: initialSeen, LastSeen: initialSeen}); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	store, err = storage.NewStorage(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	cache := inventory.NewCache()
	defer cache.Stop()
	cache.Upsert(device)
	broker := api.NewBroker(cache)
	defer broker.Stop()
	eng := NewEngine(cache, broker)
	eng.SetStorage(store)
	profile, err := eng.GetIdentityProfile(device.PDID)
	if err != nil || len(profile.Aliases) != 1 || !profile.Aliases[0].LastSeen.Equal(initialSeen) {
		t.Fatalf("durable activity baseline did not rehydrate: profile=%+v err=%v", profile, err)
	}

	liveSeen := initialSeen.Add(30 * time.Minute)
	eng.recordIdentitySignals(device, []identitycore.Signal{{Type: models.AliasMAC, Value: "00:11:22:33:44:55", Source: "openwrt_ap", Confidence: .9}}, nil, identitycore.Decision{}, liveSeen)
	profile, err = eng.GetIdentityProfile(device.PDID)
	if err != nil || !profile.Aliases[0].LastSeen.Equal(liveSeen) {
		t.Fatalf("fresh activity was not available after restart: profile=%+v err=%v", profile, err)
	}
	durable, err := store.ListIdentityAliases(device.PDID)
	if err != nil || len(durable) != 1 || !durable[0].LastSeen.Equal(initialSeen) {
		t.Fatalf("fresh activity was persisted after restart: aliases=%+v err=%v", durable, err)
	}
}

func TestConcurrentCandidateDecisionsHaveOneOutcome(t *testing.T) {
	cache := inventory.NewCache()
	defer cache.Stop()
	broker := api.NewBroker(cache)
	defer broker.Stop()
	store, err := storage.NewStorage(filepath.Join(t.TempDir(), "concurrent.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	eng := NewEngine(cache, broker)
	eng.SetStorage(store)
	now := time.Now()
	source := &models.Device{DeviceID: "concurrent-source", PDID: "concurrent-source", FirstSeen: now, LastSeen: now}
	target := &models.Device{DeviceID: "concurrent-target", PDID: "concurrent-target", FirstSeen: now, LastSeen: now}
	for _, device := range []*models.Device{source, target} {
		if err := store.SaveDevice(device); err != nil {
			t.Fatal(err)
		}
		cache.Upsert(device)
	}
	id, err := store.UpsertIdentityCandidate(models.IdentityCandidateLink{SourcePDID: source.PDID, TargetPDID: target.PDID, Probability: .9})
	if err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	errorsCh := make(chan error, 2)
	go func() {
		<-start
		_, err := eng.ConfirmIdentityCandidate(id, models.IdentityCandidateDecisionRequest{})
		errorsCh <- err
	}()
	go func() {
		<-start
		_, err := eng.RejectIdentityCandidate(id, models.IdentityCandidateDecisionRequest{})
		errorsCh <- err
	}()
	close(start)
	firstErr, secondErr := <-errorsCh, <-errorsCh
	if firstErr != nil && secondErr != nil {
		t.Fatalf("both decisions failed: %v / %v", firstErr, secondErr)
	}
	candidate, err := store.GetIdentityCandidate(id)
	if err != nil || (candidate.Status != "confirmed" && candidate.Status != "rejected") {
		t.Fatalf("candidate=%+v err=%v", candidate, err)
	}
	if candidate.Status == "confirmed" {
		if resolved, err := store.ResolvePDID(source.PDID); err != nil || resolved != target.PDID {
			t.Fatalf("confirmed without atomic redirect: %q %v", resolved, err)
		}
	} else if cache.Get(source.PDID) == nil {
		t.Fatal("rejected decision removed the source device")
	}
}

func TestPrivateMACPassiveMatchCreatesCandidateNotMerge(t *testing.T) {
	cache := inventory.NewCache()
	defer cache.Stop()
	broker := api.NewBroker(cache)
	store, err := storage.NewStorage(filepath.Join(t.TempDir(), "engine.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	eng := NewEngine(cache, broker)
	eng.SetStorage(store)
	now := time.Now()
	existing := &models.Device{DeviceID: "dev_old", PDID: "pdid_old", IdentityTier: models.TierTentative,
		CurrentMAC: "02:00:00:00:00:01", MACs: []string{"02:00:00:00:00:01"},
		CurrentIP: "192.168.1.5", IPs: []string{"192.168.1.5"}, Hostname: "phone",
		CanonicalHostname: "phone", Services: []string{"_airplay._tcp"}, FirstSeen: now.Add(-time.Hour), LastSeen: now.Add(-30 * time.Second)}
	if err := store.SaveDevice(existing); err != nil {
		t.Fatal(err)
	}
	cache.Upsert(existing)
	eng.processObservation(discovery.Observation{MAC: mustMAC(t, "02:00:00:00:00:02"), IP: net.ParseIP("192.168.1.5"),
		Hostname: "phone", Services: []string{"_airplay._tcp"}, Source: "netlink", Timestamp: now})
	if got := cache.Get("pdid_old"); got == nil || len(got.MACs) != 1 {
		t.Fatalf("passive observation merged into existing device: %+v", got)
	}
	all := cache.List()
	if len(all) != 2 {
		t.Fatalf("expected separate device, got %d", len(all))
	}
	var created models.Device
	for _, d := range all {
		if d.PDID != "pdid_old" {
			created = d
		}
	}
	profile, err := store.IdentityProfile(created.PDID)
	if err != nil {
		t.Fatal(err)
	}
	if !profile.Ambiguous || len(profile.Candidates) != 1 || profile.Candidates[0].TargetPDID != "pdid_old" {
		t.Fatalf("candidate not recorded: %+v", profile)
	}
}

func mustMAC(t *testing.T, value string) net.HardwareAddr {
	t.Helper()
	mac, err := net.ParseMAC(value)
	if err != nil {
		t.Fatal(err)
	}
	return mac
}
