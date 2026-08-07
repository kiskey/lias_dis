// Package models defines canonical data structures shared between DIS and LIAS.
//
// File:    shared/models/policy.go
// Version: 2.0 (Added ExpiresAt & ReasonTag for Extend Access; removed accidental schedule duplicates)
package models

import "time"

// PolicyType enumerates the scoping types a Policy can target.
type PolicyType string

const (
    PolicyTypeGlobal PolicyType = "global"
    PolicyTypeTag    PolicyType = "tag"
    PolicyTypeDevice PolicyType = "device"
)

// Action is the enforcement verdict a Policy applies to its target.
type Action string

const (
    ActionAllow    Action = "allow"
    ActionBlock    Action = "block"
    ActionSchedule Action = "schedule"
)

// Policy is the canonical policy rule exchanged between LIAS components.
type Policy struct {
    ID          string     `json:"id"`
    Name        string     `json:"name"`
    Type        PolicyType `json:"type"`
    TargetID    string     `json:"target_id"`
    Action      Action     `json:"action"`
    ScheduleIDs []string   `json:"schedule_ids,omitempty"`
    ScheduleID  *string    `json:"schedule_id,omitempty"`
    Priority    int        `json:"priority"`
    Enabled     bool       `json:"enabled"`
    CreatedAt   time.Time  `json:"created_at,omitempty"`
    UpdatedAt   time.Time  `json:"updated_at,omitempty"`

    // ExpiresAt, when set, marks this policy as temporary: it is honored
    // normally until ExpiresAt, then automatically removed on the next
    // engine sweep tick. nil means "permanent". Used by Pause & Extend Access.
    ExpiresAt *time.Time `json:"expires_at,omitempty"`

    // ReasonTag is informational only (e.g. "pause", "extend_access") and
    // lets the dashboard/app render provenance without recomputing it.
    ReasonTag string `json:"reason_tag,omitempty"`
}

// GetScheduleIDs returns the merged list of schedule IDs attached to this
// policy, tolerating both the modern ScheduleIDs slice and the legacy
// singular ScheduleID pointer for backward compatibility.
func (p Policy) GetScheduleIDs() []string {
    if len(p.ScheduleIDs) > 0 {
        out := make([]string, len(p.ScheduleIDs))
        copy(out, p.ScheduleIDs)
        return out
    }
    if p.ScheduleID != nil && *p.ScheduleID != "" {
        return []string{*p.ScheduleID}
    }
    return nil
}
