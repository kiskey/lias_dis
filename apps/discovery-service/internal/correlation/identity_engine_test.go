package correlation

import (
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/user/lias-dis/apps/discovery-service/internal/api"
	"github.com/user/lias-dis/apps/discovery-service/internal/discovery"
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
