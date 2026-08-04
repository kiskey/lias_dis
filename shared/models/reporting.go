// Package models defines canonical data structures shared between DIS and LIAS.
//
// File:    shared/models/reporting.go
// Version: 1.0
package models

import "time"

// FlowLog represents a single network flow event for analytics and reporting.
type FlowLog struct {
    Timestamp time.Time `json:"timestamp"`
    PDID      string    `json:"pdid"`
    Action    Action    `json:"action"`
    Bytes     int64     `json:"bytes"`
}

// NetworkStats represents aggregate network statistics for the dashboard.
type NetworkStats struct {
    BlockedEvents24h      int64  `json:"blocked_events_24h"`
    TopBlockedDevicePDID string `json:"top_blocked_device_pdid"`
}
