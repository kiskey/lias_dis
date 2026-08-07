// Package models defines canonical data structures shared between DIS and LIAS.
//
// File:    shared/models/schedule.go
// Version: 1.0 (Restored to resolve build conflict)
package models

// ScheduleMode determines the default behavior outside a schedule's rules.
type ScheduleMode string

const (
    ScheduleModeDowntime  ScheduleMode = "downtime"
    ScheduleModeWhitelist ScheduleMode = "whitelist"
)

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
