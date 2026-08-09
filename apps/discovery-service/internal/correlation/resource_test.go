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

func TestStableHeartbeatWriteBudget(t *testing.T) {
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
	now := time.Now()

	engine.markSeenDirty("pdid_heartbeat", now)
	engine.dirtyMu.Lock()
	delete(engine.dirtyDevices, "pdid_heartbeat")
	engine.dirtyMu.Unlock()
	engine.markSeenDirty("pdid_heartbeat", now.Add(stableHeartbeatWriteInterval-time.Second))
	engine.dirtyMu.Lock()
	_, tooSoon := engine.dirtyDevices["pdid_heartbeat"]
	engine.dirtyMu.Unlock()
	if tooSoon {
		t.Fatal("stable heartbeat scheduled a write before the five-minute budget")
	}
	engine.markSeenDirty("pdid_heartbeat", now.Add(stableHeartbeatWriteInterval))
	engine.dirtyMu.Lock()
	_, due := engine.dirtyDevices["pdid_heartbeat"]
	engine.dirtyMu.Unlock()
	if !due {
		t.Fatal("stable heartbeat was not scheduled at the five-minute boundary")
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
