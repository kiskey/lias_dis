package sync

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/user/lias-dis/apps/lias/internal/config"
	sharedapi "github.com/user/lias-dis/shared/api"
	"github.com/user/lias-dis/shared/models"
)

type contractBroadcaster struct {
	mu     sync.Mutex
	events []models.Event
}

type contractMigrator struct {
	oldPDID, newPDID string
	macs             []string
}

func (m *contractMigrator) MigrateIdentity(oldPDID, newPDID string, macs []string) (MigrationResult, error) {
	m.oldPDID, m.newPDID = oldPDID, newPDID
	m.macs = append([]string(nil), macs...)
	return MigrationResult{}, nil
}

func (b *contractBroadcaster) Broadcast(event models.Event) {
	b.mu.Lock()
	b.events = append(b.events, event)
	b.mu.Unlock()
}

func (b *contractBroadcaster) SignalSSEConnected() {}

func (b *contractBroadcaster) snapshot() []models.Event {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]models.Event(nil), b.events...)
}

func TestResolveEventPDIDAcrossV1AndAdditivePayloads(t *testing.T) {
	tests := []struct {
		name      string
		eventType models.EventType
		payload   string
		want      string
	}{
		{name: "explicit pdid", eventType: models.EventDeviceOnline, payload: `{"pdid":"pdid_current","device_id":"internal-id"}`, want: "pdid_current"},
		{name: "legacy device id", eventType: models.EventDeviceOnline, payload: `{"device_id":"pdid_legacy"}`, want: "pdid_legacy"},
		{name: "reidentified fallback", eventType: models.EventDeviceReidentified, payload: `{"old_pdid":"old","new_pdid":"new"}`, want: "new"},
		{name: "global event", eventType: models.EventType("future.global"), payload: `{"scope":"global"}`, want: ""},
		{name: "malformed", eventType: models.EventDeviceOnline, payload: `{`, want: ""},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := resolveEventPDID(test.eventType, json.RawMessage(test.payload)); got != test.want {
				t.Fatalf("resolveEventPDID()=%q want=%q", got, test.want)
			}
		})
	}
}

func TestUnknownGlobalEventRelaysWithoutEnforcement(t *testing.T) {
	trigger := make(chan struct{}, 1)
	broker := &contractBroadcaster{}
	client := NewDISClient(config.DISConfig{}, NewCache(), trigger, broker, nil)
	event := models.NewEvent(models.EventType("future.global"), "", map[string]any{"feature": "future"})

	client.handleEvent(event)

	events := broker.snapshot()
	if len(events) != 1 || events[0].Type != models.EventType("future.global") {
		t.Fatalf("future event was not relayed: %+v", events)
	}
	select {
	case <-trigger:
		t.Fatal("unknown event triggered policy enforcement")
	default:
	}
	if len(client.cache.List()) != 0 {
		t.Fatal("unknown event mutated the device cache")
	}
}

func TestLIASDeviceDecoderIgnoresAdditiveFields(t *testing.T) {
	wire := []byte(`{
		"devices":[{
			"pdid":"pdid_public",
			"device_id":"internal-id",
			"current_mac":"02:00:00:00:00:01",
			"online":true,
			"future_field":{"value":1}
		}],
		"total":1,
		"future_top_level":true
	}`)
	var response sharedapi.DeviceListResponse
	if err := json.Unmarshal(wire, &response); err != nil {
		t.Fatalf("additive response failed to decode: %v", err)
	}
	if len(response.Devices) != 1 || response.Devices[0].PDID != "pdid_public" ||
		response.Devices[0].DeviceID != "internal-id" {
		t.Fatalf("known fields changed: %+v", response)
	}
}

func TestSSEPayloadLimitRemainsBounded(t *testing.T) {
	if maxSSEEventBytes != 1<<20 {
		t.Fatalf("SSE event bound changed to %d", maxSSEEventBytes)
	}
}

func TestMissedRedirectReconcilesIdentityState(t *testing.T) {
	cache := NewCache()
	cache.UpsertDevice(models.Device{PDID: "pdid_orphan", CurrentMAC: "60:be:b4:08:a9:5f",
		MACs: []string{"60:be:b4:08:a9:5f"}})
	broker := &contractBroadcaster{}
	migrator := &contractMigrator{}
	client := NewDISClient(config.DISConfig{}, cache, make(chan struct{}, 1), broker, migrator)
	resolved := models.Device{PDID: "pdid_owner", CurrentMAC: "60:be:b4:08:a9:5f",
		MACs: []string{"60:be:b4:08:a9:5f"}}
	if !client.reconcileMissedRedirect("pdid_orphan", resolved) {
		t.Fatal("missed redirect was not reconciled")
	}
	if migrator.oldPDID != "pdid_orphan" || migrator.newPDID != "pdid_owner" || len(migrator.macs) != 1 {
		t.Fatalf("migration=%+v", migrator)
	}
	if cache.Get("pdid_orphan") != nil || cache.Get("pdid_owner") == nil {
		t.Fatalf("cache was not retargeted: old=%+v new=%+v", cache.Get("pdid_orphan"), cache.Get("pdid_owner"))
	}
	events := broker.snapshot()
	if len(events) != 1 || events[0].Type != models.EventDeviceReidentified {
		t.Fatalf("redirect event contract changed: %+v", events)
	}
}

func TestSSERequestsStartupAndReconnectReplay(t *testing.T) {
	headers := make(chan string, 2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		headers <- r.Header.Get("Last-Event-ID")
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()
	client := NewDISClient(config.DISConfig{URL: server.URL}, NewCache(), make(chan struct{}, 1), nil, nil)
	_ = client.consumeSSE(context.Background())
	if got := <-headers; got != "1" {
		t.Fatalf("initial replay header=%q", got)
	}
	client.stateMu.Lock()
	client.lastEventID = 123
	client.stateMu.Unlock()
	_ = client.consumeSSE(context.Background())
	if got := <-headers; got != "123" {
		t.Fatalf("reconnect replay header=%q", got)
	}
}
