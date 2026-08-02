// Package models defines canonical data structures shared between DIS and LIAS.
//
// File:    shared/models/policy.go
// Version: 1.1
package models

import "time"

// PolicyType enumerates the scopes at which a policy can be applied.
type PolicyType string

const (
	PolicyTypeGlobal PolicyType = "global"
	PolicyTypeTag    PolicyType = "tag"
	PolicyTypeDevice PolicyType = "device"
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
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	Type       PolicyType `json:"type"`
	TargetID   string     `json:"target_id"`           // "" for global, Tag ID (e.g. "kids"), or PDID
	Action     Action     `json:"action"`              // allow, block, or schedule
	ScheduleID *string    `json:"schedule_id,omitempty"` // Reference to Schedule if action == schedule
	Priority   int        `json:"priority"`            // Higher number = higher precedence
	CreatedAt  time.Time  `json:"created_at"`
	UpdatedAt  time.Time  `json:"updated_at"`
}
