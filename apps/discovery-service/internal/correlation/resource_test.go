package correlation

import (
	"encoding/json"
	"fmt"
	"net"
	"runtime"
	"testing"
	"time"

	"github.com/user/lias-dis/apps/discovery-service/internal/api"
	"github.com/user/lias-dis/apps/discovery-service/internal/discovery"
	"github.com/user/lias-dis/apps/discovery-service/internal/inventory"
	"github.com/user/lias-dis/apps/discovery-service/internal/storage"
	"github.com/user/lias-dis/shared/models"
)

func TestDeferredOnlineUsesOneBoundedScheduler(t *testing.T) {
	cache := inventory.NewCache()
	defer cache.Stop()
	broker := api.NewBroker(cache)
	defer broker.Stop()
	engine := NewEngine(cache, broker)
	before := runtime.NumGoroutine()

	for i := 0; i < 200; i++ {
		pdid := fmt.Sprintf("pdid_deferred_%03d", i)
		cache.Upsert(&models.Device{
			PDID: pdid, CurrentMAC: fmt.Sprintf("02:00:00:00:%02x:%02x", i/256, i%256),
			PendingOnlineObs: []string{"netlink"},
		})
		engine.scheduleDeferredOnline(pdid, time.Minute)
	}
	if growth := runtime.NumGoroutine() - before; growth > 1 {
		t.Fatalf("deferred scheduling created per-device goroutines: growth=%d", growth)
	}
	engine.deferredMu.Lock()
	queued := len(engine.deferredOnline)
	engine.deferredMu.Unlock()
	if queued != 200 {
		t.Fatalf("expected 200 coalesced deadlines, got %d", queued)
	}

	engine.flushDeferredOnline(time.Now().Add(2 * time.Minute))
	for _, d := range cache.List() {
		if !d.Online {
			t.Fatalf("due device was not promoted online: %s", d.PDID)
		}
	}
}

func TestDeferredOnlineRemainsLiveOnlyAndEmitsExistingEvent(t *testing.T) {
	cache := inventory.NewCache()
	defer cache.Stop()
	broker := api.NewBroker(cache)
	defer broker.Stop()
	client := broker.Subscribe("volatile-online", 0)
	defer broker.Unsubscribe(client.ID)
	store, err := storage.NewStorage(t.TempDir() + "/volatile-online.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	engine := NewEngine(cache, broker)
	engine.SetStorage(store)
	now := time.Now().UTC().Truncate(time.Millisecond)
	device := &models.Device{DeviceID: "dev_online", PDID: "pdid_online", FirstSeen: now, LastSeen: now,
		PendingOnlineObs: []string{"netlink"}}
	if err := store.SaveDevice(device); err != nil {
		t.Fatal(err)
	}
	cache.Upsert(device)
	engine.scheduleDeferredOnline(device.PDID, time.Minute)
	engine.flushDeferredOnline(now.Add(2 * time.Minute))

	if live := cache.Get(device.PDID); live == nil || !live.Online || len(live.PendingOnlineObs) != 0 {
		t.Fatalf("live presence was not promoted: %+v", live)
	}
	select {
	case event := <-client.Events:
		if event.Type != models.EventDeviceOnline || event.DeviceID != device.PDID {
			t.Fatalf("existing SSE event contract changed: %+v", event)
		}
	case <-time.After(time.Second):
		t.Fatal("online SSE event was not emitted")
	}
	durable, err := store.LoadHydrate()
	if err != nil || len(durable) != 1 || durable[0].Online || len(durable[0].PendingOnlineObs) != 0 {
		t.Fatalf("volatile online state reached SQLite: devices=%+v err=%v", durable, err)
	}
}

func TestObservationStormIsDeduplicatedAndBounded(t *testing.T) {
	cache := inventory.NewCache()
	defer cache.Stop()
	broker := api.NewBroker(cache)
	defer broker.Stop()
	engine := NewEngine(cache, broker)
	mac, _ := net.ParseMAC("02:00:00:00:00:01")
	obs := discovery.Observation{
		Source: "netlink", Group: discovery.GroupA, MAC: mac,
		IP: net.ParseIP("192.168.1.20"), Online: true, Timestamp: time.Now(),
	}
	for i := 0; i < 10_000; i++ {
		engine.processObservation(obs)
	}
	if got := len(cache.List()); got != 1 {
		t.Fatalf("duplicate storm created %d devices", got)
	}
	engine.dedupMu.Lock()
	dedupEntries := len(engine.lastSeenObs)
	engine.dedupMu.Unlock()
	if dedupEntries != 1 {
		t.Fatalf("duplicate storm grew dedup cache to %d", dedupEntries)
	}
}

func TestStableHeartbeatAndAliasActivityAreMemoryOnly(t *testing.T) {
	cache := inventory.NewCache()
	defer cache.Stop()
	broker := api.NewBroker(cache)
	defer broker.Stop()
	store, err := storage.NewStorage(t.TempDir() + "/heartbeat.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	engine := NewEngine(cache, broker)
	engine.SetStorage(store)
	mac, _ := net.ParseMAC("00:11:22:33:44:55")
	initialSeen := time.Now().Add(-20 * time.Minute).UTC().Truncate(time.Millisecond)
	obs := discovery.Observation{
		Source: "openwrt_ap", Group: discovery.GroupA, MAC: mac,
		IP: net.ParseIP("192.168.1.20"), Online: true, Confidence: .9,
		Timestamp: initialSeen,
	}
	engine.processObservation(obs)
	devices := cache.List()
	if len(devices) != 1 {
		t.Fatalf("expected one correlated device, got %d", len(devices))
	}
	pdid := devices[0].PDID
	durableDevices, err := store.LoadHydrate()
	if err != nil || len(durableDevices) != 1 {
		t.Fatalf("initial durable device: devices=%+v err=%v", durableDevices, err)
	}
	durableSeen := durableDevices[0].LastSeen
	durableAliases, err := store.ListIdentityAliases(pdid)
	if err != nil || len(durableAliases) == 0 {
		t.Fatalf("initial durable aliases: aliases=%+v err=%v", durableAliases, err)
	}
	durableAliasSeen := durableAliases[0].LastSeen

	// Bypass only the two-second input deduplicator; this models the next
	// normal heartbeat without waiting in the test.
	engine.dedupMu.Lock()
	engine.lastSeenObs = make(map[string]time.Time)
	engine.dedupMu.Unlock()
	liveSeen := initialSeen.Add(10 * time.Minute)
	obs.Timestamp = liveSeen
	engine.processObservation(obs)
	engine.flushDirty()

	live := cache.Get(pdid)
	if live == nil || !live.LastSeen.Equal(liveSeen) || !live.Online {
		t.Fatalf("live REST/SSE cache was not refreshed: %+v", live)
	}
	profile, err := engine.GetIdentityProfile(pdid)
	if err != nil || len(profile.Aliases) == 0 || !profile.Aliases[0].LastSeen.Equal(liveSeen) {
		t.Fatalf("live identity activity was not overlaid: profile=%+v err=%v", profile, err)
	}
	durableDevices, err = store.LoadHydrate()
	if err != nil || !durableDevices[0].LastSeen.Equal(durableSeen) {
		t.Fatalf("heartbeat reached durable device state: devices=%+v err=%v", durableDevices, err)
	}
	durableAliases, err = store.ListIdentityAliases(pdid)
	if err != nil || !durableAliases[0].LastSeen.Equal(durableAliasSeen) {
		t.Fatalf("alias refresh reached durable state: aliases=%+v err=%v", durableAliases, err)
	}
}

func TestPendingEventRecoversAcrossRestart(t *testing.T) {
	cache := inventory.NewCache()
	defer cache.Stop()
	broker := api.NewBroker(cache)
	defer broker.Stop()
	client := broker.Subscribe("recovery-test", 0)
	defer broker.Unsubscribe(client.ID)
	store, err := storage.NewStorage(t.TempDir() + "/pending-recovery.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	payload, err := json.Marshal(models.DeviceEventPayload{PDID: "pdid_recovery", Hostname: "phone"})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if err := store.SavePendingEvent("pdid_recovery", string(models.EventHostnameChanged), payload, now.Add(-11*time.Second), now, 1, "dhcp"); err != nil {
		t.Fatal(err)
	}

	restarted := NewEngine(cache, broker)
	restarted.SetStorage(store)
	restarted.debouncer.Flush()
	select {
	case event := <-client.Events:
		if event.Type != models.EventHostnameChanged || event.DeviceID != "pdid_recovery" {
			t.Fatalf("unexpected recovered event: %+v", event)
		}
	case <-time.After(time.Second):
		t.Fatal("recovered pending event was not emitted")
	}
	records, err := store.LoadPendingEvents()
	if err != nil || len(records) != 0 {
		t.Fatalf("confirmed recovery event was not deleted: records=%+v err=%v", records, err)
	}
}
