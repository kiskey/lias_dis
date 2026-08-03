// Package models defines canonical data structures shared between the
// Discovery Intelligence Service (DIS) and the LAN Internet Access Scheduler
// (LIAS). Keeping these in a shared module prevents wire-format drift between
// the two binaries that communicate solely via REST + SSE.
//
// File:    shared/models/schedule.go
// Version: 1.1
package models

// ScheduleMode declares the schedule's intended default-outside-window behavior explicitly.
type ScheduleMode string

const (
	ScheduleModeWhitelist ScheduleMode = "whitelist" // rules define ALLOW windows; default OUTSIDE = block
	ScheduleModeDowntime  ScheduleMode = "downtime"  // rules define BLOCK windows; default OUTSIDE = allow
)

// Schedule defines a collection of time-based rules that determine whether
// traffic is allowed or blocked for associated devices.
type Schedule struct {
	ID       string         `json:"id"`
	Name     string         `json:"name"`
	Mode     ScheduleMode   `json:"mode"`     // Mode explicitly defines default outside window behavior
	Timezone string         `json:"timezone"` // IANA timezone name, e.g. "America/Los_Angeles"
	Rules    []ScheduleRule `json:"rules"`
}

// ScheduleRule defines a specific time window on specific days of the week
// during which an Action (allow or block) is enforced.
type ScheduleRule struct {
	Days      []string `json:"days"`       // ["mon", "tue", "wed", "thu", "fri", "sat", "sun"]
	StartTime string   `json:"start_time"` // "15:04" 24-hour format
	EndTime   string   `json:"end_time"`   // "15:04" 24-hour format
	Action    Action   `json:"action"`     // allow or block within this window
}
