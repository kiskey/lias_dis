// Package models defines canonical data structures shared between the
// Discovery Intelligence Service (DIS) and the LAN Internet Access Scheduler
// (LIAS). Keeping these in a shared module prevents wire-format drift between
// the two binaries that communicate solely via REST + SSE.
//
// File:    shared/models/schedule.go
// Version: 1.0
package models

// Schedule defines a collection of time-based rules that determine whether
// traffic is allowed or blocked for associated devices.
// See §4.6 for the evaluation logic.
type Schedule struct {
    ID       string         `json:"id"`
    Name     string         `json:"name"`
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
