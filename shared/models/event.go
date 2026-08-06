// Package models defines canonical data structures shared between DIS and LIAS.
//
// File:    shared/models/event.go
// Version: 2.3 (Added EventEffectiveStatusChanged for Extend Access feature)
package models

import (
    "encoding/json"
    "time"
)

// EventType is the discriminant for SSE event routing.
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
    EventDeviceReidentified EventType = "device.reidentified"
    EventSecurityAlert      EventType = "security.alert"

    // EventEffectiveStatusChanged is fired whenever a device or tag's
    // effective policy status changes (e.g. temporary extension activated
    // or expired, global switch toggled, schedule transition). The frontend
    // should re-fetch /effective-status for the indicated target.
    EventEffectiveStatusChanged EventType = "effective.status_changed"
)

// Event is the canonical SSE wire envelope exchanged between DIS, LIAS,
// and all connected dashboard/app clients.
type Event struct {
    Type      EventType       `json:"type"`
    DeviceID  string          `json:"device_id,omitempty"`
    Payload   json.RawMessage `json:"payload,omitempty"`
    Timestamp time.Time       `json:"timestamp"`
}

// NewEvent constructs an Event, marshaling the supplied payload to JSON.
// If payload is already a json.RawMessage or []byte, it is used as-is.
func NewEvent(t EventType, deviceID string, payload interface{}) Event {
    var raw json.RawMessage
    if payload != nil {
        if r, ok := payload.(json.RawMessage); ok {
            raw = r
        } else {
            b, err := json.Marshal(payload)
            if err == nil {
                raw = json.RawMessage(b)
            }
        }
    }
    return Event{
        Type:      t,
        DeviceID:  deviceID,
        Payload:   raw,
        Timestamp: time.Now(),
    }
}

// SSEFrame renders the Event as an SSE text frame compliant with the
// Server-Sent Events wire format. The id field is the event timestamp
// in Unix nanoseconds, which the broker uses for replay on reconnect.
func (e Event) SSEFrame() string {
    frame := "event: " + string(e.Type) + "\n"
    if !e.Timestamp.IsZero() {
        idBytes, _ := json.Marshal(e.Timestamp.UnixNano())
        frame += "id: " + string(idBytes) + "\n"
    }
    if len(e.Payload) > 0 {
        frame += "data: " + string(e.Payload) + "\n"
    } else {
        frame += "data: {}\n"
    }
    frame += "\n"
    return frame
}

// DeviceEventPayload is the common payload for device-level events
// (online, offline, ip/mac/hostname change).
type DeviceEventPayload struct {
    PDID                 string    `json:"pdid"`
    MAC                  string    `json:"mac,omitempty"`
    IP                   string    `json:"ip,omitempty"`
    Hostname             string    `json:"hostname,omitempty"`
    CanonicalHostname    string    `json:"canonical_hostname,omitempty"`
    OldMAC               string    `json:"old_mac,omitempty"`
    OldIP                string    `json:"old_ip,omitempty"`
    OldHost              string    `json:"old_host,omitempty"`
    OldCanonicalHostname string    `json:"old_canonical_hostname,omitempty"`
    ConfirmedBy          []string  `json:"confirmed_by,omitempty"`
    Timestamp            time.Time `json:"timestamp"`
}

// SecurityAlertPayload is the payload for security alert events.
type SecurityAlertPayload struct {
    AlertType string    `json:"alert_type"`
    PDID      string    `json:"pdid"`
    Details   string    `json:"details"`
    Timestamp time.Time `json:"timestamp"`
}

// DeviceReidentifiedPayload is the payload for device identity promotion events.
type DeviceReidentifiedPayload struct {
    OldPDID      string    `json:"old_pdid"`
    NewPDID      string    `json:"new_pdid"`
    Reason       string    `json:"reason"`
    MigratedMACs []string  `json:"migrated_macs,omitempty"`
    Timestamp    time.Time `json:"timestamp"`
}

// EffectiveStatusChangedPayload is the payload for EventEffectiveStatusChanged.
// It tells SSE clients which device or tag's effective policy status changed
// so they can re-fetch the authoritative status from the REST API.
type EffectiveStatusChangedPayload struct {
    TargetType string    `json:"target_type"` // "device" | "tag"
    TargetID   string    `json:"target_id"`
    Timestamp  time.Time `json:"timestamp"`
}

// FlowLog is a single recorded policy decision used for analytics and
// per-device activity history.
type FlowLog struct {
    PDID      string    `json:"pdid"`
    Action    Action    `json:"action"`
    Bytes     int64     `json:"bytes,omitempty"`
    Timestamp time.Time `json:"timestamp"`
}

// NetworkStats is the aggregate analytics snapshot returned by /api/v1/stats.
type NetworkStats struct {
    BlockedEvents24h     int    `json:"blocked_events_24h"`
    TopBlockedDevicePDID string `json:"top_blocked_device_pdid"`
}
