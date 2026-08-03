// Package api defines the standard request and response types used across
// the REST boundaries of DIS and LIAS. Centralizing these prevents drift
// between the server implementations and any client consumers.
//
// File:    shared/api/types.go
// Version: 1.1
package api

import (
	"encoding/json"

	"github.com/user/lias-dis/shared/models"
)

// DeviceListResponse is the wire format for GET /devices endpoints.
type DeviceListResponse struct {
	Devices []models.Device `json:"devices"`
	Total   int             `json:"total"`
}

// HealthResponse is the wire format for GET /health endpoints.
type HealthResponse struct {
	Status  string `json:"status"`
	Version string `json:"version"`
}

// ErrorResponse is the standard JSON error payload returned for any
// non-2xx HTTP response.
type ErrorResponse struct {
	Error   string `json:"error"`
	Details string `json:"details,omitempty"`
}

// AcceptedResponse is used for endpoints that trigger background tasks,
// such as POST /devices/:pdid/refresh.
type AcceptedResponse struct {
	Message string `json:"message"`
	TaskID  string `json:"task_id,omitempty"`
}

// PolicyValidateRequest is the payload for POST /api/v1/policies/validate.
type PolicyValidateRequest struct {
	ScheduleIDs []string `json:"schedule_ids"`
}

// Conflict describes a schedule rule collision.
type Conflict struct {
	ScheduleAID   string        `json:"schedule_a_id"`
	ScheduleAName string        `json:"schedule_a_name"`
	ScheduleBID   string        `json:"schedule_b_id"`
	ScheduleBName string        `json:"schedule_b_name"`
	Day           string        `json:"day"`
	OverlapStart  string        `json:"overlap_start"`
	OverlapEnd    string        `json:"overlap_end"`
	ActionA       models.Action `json:"action_a"`
	ActionB       models.Action `json:"action_b"`
}

// ConflictResponse represents a 409 Conflict error payload listing active schedule collisions.
type ConflictResponse struct {
	Error     string     `json:"error,omitempty"`
	Message   string     `json:"message,omitempty"`
	Conflicts []Conflict `json:"conflicts"`
}

// MarshalJSON is a helper to easily serialize responses.
func (r DeviceListResponse) MarshalJSON() ([]byte, error) {
	if r.Devices == nil {
		r.Devices = []models.Device{}
	}
	type Alias DeviceListResponse
	return json.Marshal((Alias)(r))
}
