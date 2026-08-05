// Package models defines canonical data structures shared between DIS and LIAS.
//
// File:    shared/models/policy.go
// Version: 1.3
package models

import "time"

// PolicyType enumerates the scopes at which a policy can be applied.
type PolicyType string

const (
    PolicyTypeGlobal PolicyType = "global"
    PolicyTypeTag    PolicyType = "tag"
    PolicyTypeDevice PolicyType = "device"
    PolicyTypeUser   PolicyType = "user" // SYS-FEAT-03 Fix: Per-user identity mapping
)

// Action defines the enforcement behavior for network traffic.
type Action string

const (
    ActionAllow    Action = "allow"
    ActionBlock    Action = "block"
    ActionSchedule Action = "schedule"
)

// Policy represents a firewall access rule for a global switch, tag group, or single device.
type Policy struct {
    ID          string     `json:"id"`
    Name        string     `json:"name"`
    Type        PolicyType `json:"type"`
    TargetID    string     `json:"target_id"`           // "" for global, Tag ID, PDID, or User ID
    Action      Action     `json:"action"`              // allow, block, or schedule
    ScheduleIDs []string   `json:"schedule_ids,omitempty"` // ordered list, evaluated as a composite
    ScheduleID  *string    `json:"schedule_id,omitempty`  // Deprecated: retained for backwards compatibility
    Priority    int        `json:"priority"`            // Higher number = higher precedence
    Enabled     bool       `json:"enabled"`             // LIAS-POL-01 Fix: Enable/disable toggle
    CreatedAt   time.Time  `json:"created_at"`
    UpdatedAt   time.Time  `json:"updated_at"`
}

// GetScheduleIDs returns the non-empty ScheduleIDs slice, falling back to ScheduleID if populated.
func (p *Policy) GetScheduleIDs() []string {
    if len(p.ScheduleIDs) > 0 {
        return p.ScheduleIDs
    }
    if p.ScheduleID != nil && *p.ScheduleID != "" {
        return []string{*p.ScheduleID}
    }
    return nil
}
