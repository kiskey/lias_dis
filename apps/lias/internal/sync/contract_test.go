package sync

import (
	"encoding/json"
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
