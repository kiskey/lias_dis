// Package models defines canonical data structures shared between DIS and LIAS.
//
// File:    shared/models/policy.go
// Version: 2.0 (Added ExpiresAt, ReasonTag, CreatedAt, UpdatedAt for Extend Access)
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

// ScheduleMode determines the default behavior outside a schedule's rules.
type ScheduleMode string

const (
    ScheduleModeDowntime  ScheduleMode = "downtime"
    ScheduleModeWhitelist ScheduleMode = "whitelist"
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
    // engine sweep tick. nil means "permanent" — all existing policies
    // keep working unchanged. Used by Pause Internet and Extend Access.
    ExpiresAt *time.Time `json:"expires_at,omitempty"`

    // ReasonTag is informational only (e.g. "pause", "extend_access") and
    // lets the dashboard/app render provenance ("Extending access — 42m left")
    // without recomputing it. Not used for any policy evaluation logic.
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

// Schedule is a reusable time window bundle that can be attached to any
// number of policies.
type Schedule struct {
    ID       string         `json:"id"`
    Name     string         `json:"name"`
    Mode     ScheduleMode   `json:"mode"`
    Timezone string         `json:"timezone"`
    Rules    []ScheduleRule `json:"rules"`
}

// ScheduleRule defines a single time window within a Schedule.
type ScheduleRule struct {
    Days      []string `json:"days"`
    StartTime string   `json:"start_time"`
    EndTime   string   `json:"end_time"`
    Action    Action   `json:"action"`
    StartDate string   `json:"start_date,omitempty"`
    EndDate   string   `json:"end_date,omitempty"`
}
