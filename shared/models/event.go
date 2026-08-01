// File:    shared/models/event.go
// Version: 1.0
package models

import (
    "encoding/json"
    "time"
)

// EventType enumerates the device lifecycle events emitted by DIS and proxied
// by LIAS to connected dashboard clients. Values are stable wire identifiers
// and must never be renamed across versions — new events get new constants.
type EventType string

const (
    EventDeviceAdded        EventType = "device.added"
    EventDeviceRemoved      EventType = "device.removed"
    EventDeviceOnline       EventType = "device.online"
    EventDeviceOffline      EventType = "device.offline"
    EventHostnameChanged    EventType = "device.hostname_changed"
    EventFingerprintUpdated EventType = "device.fingerprint_updated"
    EventIPChanged          EventType = "device.ip_changed"
    EventMACChanged         EventType = "device.mac_changed"
)

// Event is the canonical envelope for every state change in the system. The
// Payload is intentionally json.RawMessage so producers can encode typed
// payloads while consumers can decode lazily or forward verbatim over SSE.
type Event struct {
    Type      EventType       `json:"type"`
    Timestamp time.Time       `json:"timestamp"`
    DeviceID  string          `json:"device_id"`
    Payload   json.RawMessage `json:"payload,omitempty"`
}

// DeviceEventPayload is the canonical payload shape for events that carry
// device state deltas (online/offline/ip_changed/mac_changed/hostname_changed).
// Old* fields are populated only for *_changed events and are omitted on the
// wire when empty.
type DeviceEventPayload struct {
    PDID      string    `json:"pdid,omitempty"`
    MAC       string    `json:"mac,omitempty"`
    IP        string    `json:"ip,omitempty"`
    Hostname  string    `json:"hostname,omitempty"`
    OldMAC    string    `json:"old_mac,omitempty"`
    OldIP     string    `json:"old_ip,omitempty"`
    OldHost   string    `json:"old_hostname,omitempty"`
    Timestamp time.Time `json:"timestamp"`
}

// NewEvent constructs an Event with the supplied type, device id, and JSON-
// encoded payload. If payload marshalling fails, the event is still returned
// with an empty payload so event emission never blocks the discovery pipeline.
// The returned timestamp is UTC-normalized for stable ordering across nodes.
func NewEvent(t EventType, deviceID string, payload interface{}) Event {
    ts := time.Now().UTC()
    var raw json.RawMessage
    if payload != nil {
        if b, err := json.Marshal(payload); err == nil {
            raw = json.RawMessage(b)
        }
    }
    return Event{
        Type:      t,
        Timestamp: ts,
        DeviceID:  deviceID,
        Payload:   raw,
    }
}

// SSEFrame renders the Event in the Server-Sent Events wire format expected by
// both the LIAS backend EventSource client and the dashboard EventSource. The
// id field is derived from the Unix-nano timestamp so reconnecting clients can
// send `Last-Event-ID` to DIS for at-least-once replay (implemented in a later
// version of the SSE broker).
func (e Event) SSEFrame() string {
    var b []byte
    b = append(b, "event: "...)
    b = append(b, string(e.Type)...)
    b = append(b, '\n')
    b = append(b, "id: "...)
    b = append(b, itoa(e.Timestamp.UnixNano())...)
    b = append(b, '\n')
    if len(e.Payload) > 0 {
        b = append(b, "data: "...)
        b = append(b, e.Payload...)
        b = append(b, '\n')
    }
    b = append(b, '\n')
    return string(b)
}

// itoa is a small allocation-free int64-to-string helper used by SSEFrame so
// the hot event-broadcast path does not pull in fmt or strconv's heavier
// formatting machinery.
func itoa(n int64) string {
    if n == 0 {
        return "0"
    }
    neg := n < 0
    if neg {
        n = -n
    }
    var buf [20]byte
    i := len(buf)
    for n > 0 {
        i--
        buf[i] = byte('0' + n%10)
        n /= 10
    }
    if neg {
        i--
        buf[i] = '-'
    }
    return string(buf[i:])
}
