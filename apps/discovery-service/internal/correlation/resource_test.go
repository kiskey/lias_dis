package correlation

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net"
	"runtime"
	"sync"
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

func TestConcurrentFirstSightOfSameMACCreatesOneIdentity(t *testing.T) {
	cache := inventory.NewCache()
	defer cache.Stop()
	broker := api.NewBroker(cache)
	defer broker.Stop()
	store, err := storage.NewStorage(t.TempDir() + "/concurrent-claim.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	engine := NewEngine(cache, broker)
	engine.SetStorage(store)
	const workers = 100
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			mac, _ := net.ParseMAC("00:11:22:33:44:55")
			engine.processObservation(discovery.Observation{Source: fmt.Sprintf("source_%d", i),
				Group: discovery.GroupA, MAC: mac, Timestamp: time.Now(), Confidence: .9})
		}(i)
	}
	close(start)
	wg.Wait()
	if got := cache.List(); len(got) != 1 {
		t.Fatalf("concurrent first sight created %d cached identities: %+v", len(got), got)
	}
	durable, err := store.LoadHydrate()
	if err != nil || len(durable) != 1 || len(durable[0].MACs) != 1 {
		t.Fatalf("concurrent first sight durable=%+v err=%v", durable, err)
	}
}

func TestReconcileConfirmedZeroMACOrphan(t *testing.T) {
	cache := inventory.NewCache()
	defer cache.Stop()
	broker := api.NewBroker(cache)
	defer broker.Stop()
	client := broker.Subscribe("orphan-repair", 0)
	defer broker.Unsubscribe(client.ID)
	dbPath := t.TempDir() + "/orphan-repair.db"
	store, err := storage.NewStorage(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	now := time.Now().UTC().Truncate(time.Millisecond)
	owner := &models.Device{DeviceID: "dev_owner", PDID: "pdid_owner", CurrentMAC: "60:be:b4:08:a9:5f",
		MACs: []string{"60:be:b4:08:a9:5f"}, Vendor: "S-Bluetech co., limited",
		IdentityAssurance: models.IdentityStrong, IdentityProbability: .999, FirstSeen: now.Add(-time.Hour), LastSeen: now}
	orphan := &models.Device{DeviceID: "dev_orphan", PDID: "pdid_orphan", CurrentMAC: owner.CurrentMAC,
		FriendlyName: "duplicate display name", FirstSeen: now, LastSeen: now}
	if err := store.SaveDevice(owner); err != nil {
		t.Fatal(err)
	}
	// Insert the historical corruption shape directly: modern storage now
	// refuses to create it through SaveDevice.
	if err := insertOrphanFixture(dbPath, orphan); err != nil {
		t.Fatal(err)
	}
	hydrated, err := store.LoadHydrate()
	if err != nil {
		t.Fatal(err)
	}
	for i := range hydrated {
		cache.Upsert(&hydrated[i])
	}
	engine := NewEngine(cache, broker)
	engine.SetStorage(store)
	repaired, err := engine.ReconcileOrphanMACDuplicates()
	if err != nil || repaired != 1 {
		t.Fatalf("repaired=%d err=%v", repaired, err)
	}
	select {
	case event := <-client.Events:
		if event.Type != models.EventDeviceReidentified || event.DeviceID != owner.PDID {
			t.Fatalf("repair event changed contract: %+v", event)
		}
	case <-time.After(time.Second):
		t.Fatal("repair did not emit device.reidentified")
	}
	durable, err := store.LoadHydrate()
	if err != nil || len(durable) != 1 || durable[0].PDID != owner.PDID || durable[0].FriendlyName != orphan.FriendlyName {
		t.Fatalf("reconciled durable=%+v err=%v", durable, err)
	}
	if durable[0].IdentityAssurance != models.IdentityStrong {
		t.Fatalf("repair incorrectly promoted assurance: %+v", durable[0])
	}
	if resolved := engine.ResolvePDID(orphan.PDID); resolved != owner.PDID {
		t.Fatalf("orphan redirect=%q", resolved)
	}
	if repeated, err := engine.ReconcileOrphanMACDuplicates(); err != nil || repeated != 0 {
		t.Fatalf("orphan repair was not idempotent: repaired=%d err=%v", repeated, err)
	}
}

func TestReconcileLeavesVerifiedConflictForReview(t *testing.T) {
	cache := inventory.NewCache()
	defer cache.Stop()
	broker := api.NewBroker(cache)
	defer broker.Stop()
	dbPath := t.TempDir() + "/orphan-conflict.db"
	store, err := storage.NewStorage(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	now := time.Now()
	owner := &models.Device{DeviceID: "dev_owner", PDID: "pdid_owner", CurrentMAC: "00:11:22:33:44:55",
		MACs: []string{"00:11:22:33:44:55"}, FirstSeen: now, LastSeen: now}
	orphan := &models.Device{DeviceID: "dev_orphan", PDID: "pdid_orphan", CurrentMAC: owner.CurrentMAC,
		FirstSeen: now, LastSeen: now}
	if err := store.SaveDevice(owner); err != nil {
		t.Fatal(err)
	}
	if err := insertOrphanFixture(dbPath, orphan); err != nil {
		t.Fatal(err)
	}
	if _, err := store.UpsertIdentityAlias(models.IdentityAlias{DeviceID: orphan.DeviceID, Type: models.AliasMDMDeviceID,
		ValueHash: "independent-verified-hash", Source: "mdm", Confidence: 1, Verified: true,
		FirstSeen: now, LastSeen: now}); err != nil {
		t.Fatal(err)
	}
	hydrated, err := store.LoadHydrate()
	if err != nil {
		t.Fatal(err)
	}
	for i := range hydrated {
		cache.Upsert(&hydrated[i])
	}
	engine := NewEngine(cache, broker)
	engine.SetStorage(store)
	if repaired, err := engine.ReconcileOrphanMACDuplicates(); err != nil || repaired != 0 {
		t.Fatalf("verified conflict repaired=%d err=%v", repaired, err)
	}
	if durable, err := store.LoadHydrate(); err != nil || len(durable) != 2 {
		t.Fatalf("verified conflict was merged: devices=%+v err=%v", durable, err)
	}
}

func insertOrphanFixture(dbPath string, orphan *models.Device) error {
	// Kept in the correlation test package so production storage exposes no
	// escape hatch around MAC ownership. The fixture uses a separate SQLite
	// connection to reproduce a row created by the former INSERT-OR-IGNORE path.
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return err
	}
	defer db.Close()
	_, err = db.Exec(`INSERT INTO devices(device_id, pdid, current_mac, friendly_name, first_seen, last_seen)
        VALUES (?, ?, ?, ?, ?, ?)`, orphan.DeviceID, orphan.PDID, orphan.CurrentMAC,
		orphan.FriendlyName, orphan.FirstSeen, orphan.LastSeen)
	return err
}

func TestDistinctProxmoxMACsRemainSeparate(t *testing.T) {
	cache := inventory.NewCache()
	defer cache.Stop()
	broker := api.NewBroker(cache)
	defer broker.Stop()
	engine := NewEngine(cache, broker)
	for i, value := range []string{"bc:24:11:91:c0:5b", "bc:24:11:a9:4b:a0"} {
		mac, _ := net.ParseMAC(value)
		engine.processObservation(discovery.Observation{Source: fmt.Sprintf("proxmox_%d", i), Group: discovery.GroupA,
			MAC: mac, Vendor: "Proxmox Server Solutions GmbH", Timestamp: time.Now()})
	}
	if devices := cache.List(); len(devices) != 2 || devices[0].PDID == devices[1].PDID {
		t.Fatalf("distinct Proxmox MACs were collapsed: %+v", devices)
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
