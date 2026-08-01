// Package models defines canonical data structures shared between the
// Discovery Intelligence Service (DIS) and the LAN Internet Access Scheduler
// (LIAS). Keeping these in a shared module prevents wire-format drift between
// the two binaries that communicate solely via REST + SSE.
//
// File:    shared/models/policy.go
// Version: 1.0
package models

import "time"

// PolicyType enumerates the scopes at which a policy can be applied.
type PolicyType string

const (
    PolicyTypeGlobal PolicyType = "global"
    PolicyTypeTag    PolicyType = "tag"
    PolicyTypeDevice PolicyType = "device"
)

// Action defines the enforcement behavior for a device's traffic.
type Action string

const (
    ActionAllow    Action = "allow"
    ActionBlock    Action = "block"
    ActionSchedule Action = "schedule"
)

// Policy represents a rule that dictates how traffic for a device, tag, or
// the entire network should be handled by the nftables controller.
// See §4.5 for the precedence evaluation flow.
type Policy struct {
    ID         string     `json:"id"`
    Name       string     `json:"name"`
    Type       PolicyType `json:"type"`
    TargetID   string     `json:"target_id"`           // "" for global, tag ID, or PDID
    Action     Action     `json:"action"`
    ScheduleID *string    `json:"schedule_id,omitempty"` // Reference to schedule if action=schedule
    Priority   int        `json:"priority"`              // Higher number = higher precedence
    CreatedAt  time.Time  `json:"created_at"`
    UpdatedAt  time.Time  `json:"updated_at"`
}
