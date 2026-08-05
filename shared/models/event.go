// File:    shared/models/event.go
// Version: 2.2
package models

import (
    "encoding/json"
    "time"
)

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
    EventSecurityAlert      EventType = "security.alert" // NEW: DIS-SEC-06
)

type Event struct {
    Type      EventType       `json:"type"`
    Timestamp time.Time       `json:"timestamp"`
    DeviceID  string          `json:"device_id"`
    Payload   json.RawMessage `json:"payload,omitempty"`
}

type DeviceEventPayload struct {
    PDID                 string    `json:"pdid,omitempty"`
    MAC                  string    `json:"mac,omitempty"`
    IP                   string    `json:"ip,omitempty"`
    Hostname             string    `json:"hostname,omitempty"`
    CanonicalHostname    string    `json:"canonical_hostname,omitempty"`
    OldMAC               string    `json:"old_mac,omitempty"`
    OldIP                string    `json:"old_ip,omitempty"`
    OldHost              string    `json:"old_hostname,omitempty"`
    OldCanonicalHostname string    `json:"old_canonical_hostname,omitempty"`
    ConfirmedBy          []string  `json:"confirmed_by,omitempty"`
    Timestamp            time.Time `json:"timestamp"`
}

// DeviceReidentifiedPayload represents the event payload when a PDID is promoted.
type DeviceReidentifiedPayload struct {
    OldPDID          string    `json:"old_pdid"`
    NewPDID          string    `json:"new_pdid"`
    Reason           string    `json:"reason"`
    MigratedTags     []string  `json:"migrated_tags,omitempty"`
    MigratedMACs     []string  `json:"migrated_macs,omitempty"`
    Timestamp        time.Time `json:"timestamp"`
}

// SecurityAlertPayload represents a security anomaly detected by DIS.
type SecurityAlertPayload struct {
    AlertType string    `json:"alert_type"` // e.g. "mac_spoof_detected"
    PDID      string    `json:"pdid"`
    Details   string    `json:"details"`
    Timestamp time.Time `json:"timestamp"`
}

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
