package models

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestNewEventCarriesExplicitAndLegacyPDID(t *testing.T) {
	event := NewEvent(EventDeviceOnline, "pdid_public", DeviceEventPayload{PDID: "pdid_public"})
	if event.PDID != "pdid_public" || event.DeviceID != "pdid_public" || event.TargetPDID() != "pdid_public" {
		t.Fatalf("event target aliases diverged: %+v", event)
	}

	type legacyEnvelope struct {
		DeviceID string `json:"device_id"`
	}
	wire, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	var legacy legacyEnvelope
	if err := json.Unmarshal(wire, &legacy); err != nil || legacy.DeviceID != "pdid_public" {
		t.Fatalf("legacy event envelope broke: envelope=%+v err=%v", legacy, err)
	}
}

func TestTargetPDIDAcceptsLegacyProducer(t *testing.T) {
	event := Event{DeviceID: "pdid_legacy"}
	if got := event.TargetPDID(); got != "pdid_legacy" {
		t.Fatalf("legacy event target=%q", got)
	}
	event.SetTargetPDID("pdid_current")
	if event.PDID != "pdid_current" || event.DeviceID != "pdid_current" {
		t.Fatalf("event aliases were not normalized: %+v", event)
	}
}

func TestSSEV1FrameRemainsBackwardCompatible(t *testing.T) {
	event := Event{
		Type:      EventDeviceOnline,
		DeviceID:  "pdid_public",
		PDID:      "pdid_public",
		Payload:   json.RawMessage(`{"pdid":"pdid_public","online":true}`),
		Timestamp: time.Unix(0, 123),
	}
	frame := event.SSEFrame()
	for _, required := range []string{
		"event: device.online\n",
		"id: 123\n",
		"data: {\"pdid\":\"pdid_public\",\"online\":true}\n\n",
	} {
		if !strings.Contains(frame, required) {
			t.Fatalf("missing legacy SSE fragment %q in %q", required, frame)
		}
	}
}
