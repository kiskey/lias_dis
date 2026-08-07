// Package models defines canonical data structures shared between DIS and LIAS.
//
// File:    shared/models/reporting.go
// Version: 1.0 (Restored to resolve build conflict)
package models

import "time"

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
