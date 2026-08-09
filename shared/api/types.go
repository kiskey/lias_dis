// Package api defines the standard request and response types used across
// the REST boundaries of DIS and LIAS. Centralizing these prevents drift
// between the server implementations and any client consumers.
//
// File:    shared/api/types.go
// Version: 1.2 (Added Extend Access and Effective Status types)
package api

import (
	"encoding/json"

	"github.com/user/lias-dis/shared/models"
)

const (
	// APIVersionV1 is the stable REST and SSE contract exposed under /api/v1.
	APIVersionV1 = "v1"

	// APISchemaVersion increments only for additive v1 schema extensions.
	// Breaking wire changes require a new URL namespace instead.
	APISchemaVersion = 1
)

const (
	FeatureDeviceInventory       = "device_inventory"
	FeatureSSEEvents             = "sse_events"
	FeatureSSEReplay             = "sse_replay"
	FeatureIdentityBindings      = "identity_bindings"
	FeatureIdentityCandidates    = "identity_candidates"
	FeatureIdentitySplit         = "identity_split"
	FeatureAuthenticatedIdentity = "authenticated_identity"
)

// CapabilitiesResponse lets LIAS and other clients negotiate optional features
// without probing endpoints or depending on build-version strings.
type CapabilitiesResponse struct {
	APIVersion            string   `json:"api_version"`
	SchemaVersion         int      `json:"schema_version"`
	MinClientAPIVersion   string   `json:"min_client_api_version"`
	PublicDeviceKey       string   `json:"public_device_key"`
	ResponseCompatibility string   `json:"response_compatibility"`
	Features              []string `json:"features"`
}

// DISCapabilities returns a fresh, immutable-by-convention capability
// snapshot. It performs no I/O and is safe for infrequent client discovery.
func DISCapabilities() CapabilitiesResponse {
	return CapabilitiesResponse{
		APIVersion:            APIVersionV1,
		SchemaVersion:         APISchemaVersion,
		MinClientAPIVersion:   APIVersionV1,
		PublicDeviceKey:       "pdid",
		ResponseCompatibility: "additive",
		Features: []string{
			FeatureAuthenticatedIdentity,
			FeatureDeviceInventory,
			FeatureIdentityBindings,
			FeatureIdentityCandidates,
			FeatureIdentitySplit,
			FeatureSSEEvents,
			FeatureSSEReplay,
		},
	}
}

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

// ConflictResponse represents a 409 Conflict error payload listing active
// schedule collisions.
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

// ============================================================================
// Extend Access (Temporary Unblock) Feature Types
// ============================================================================

// ExtendAccessRequest is the payload for POST /api/v1/devices/{pdid}/extend
// and POST /api/v1/tags/{id}/extend. Minutes must be between 1 and 120
// inclusive.
type ExtendAccessRequest struct {
	Minutes int `json:"minutes"`
}

// ExtendAccessResponse is returned when an extension is successfully created
// or replaced.
type ExtendAccessResponse struct {
	Status    string `json:"status"`     // "extended"
	ExpiresAt string `json:"expires_at"` // RFC3339 UTC
	Minutes   int    `json:"minutes"`
}

// EffectiveStatusSource identifies which branch of the policy precedence
// tree produced the current effective action for a target.
type EffectiveStatusSource string

const (
	EffectiveSourceInfrastructure EffectiveStatusSource = "infrastructure"
	EffectiveSourceGlobal         EffectiveStatusSource = "global"
	EffectiveSourceDevicePolicy   EffectiveStatusSource = "device_policy"
	EffectiveSourceTagPolicy      EffectiveStatusSource = "tag_policy"
	EffectiveSourceSchedule       EffectiveStatusSource = "schedule"
	EffectiveSourceFallback       EffectiveStatusSource = "fallback"
)

// ExtensionInfo describes an active temporary extension (or pause) on a
// target, letting the dashboard render a live countdown without recomputing
// it from CreatedAt.
type ExtensionInfo struct {
	ExpiresAt   string `json:"expires_at"` // RFC3339 UTC
	MinutesLeft int    `json:"minutes_left"`
	ReasonTag   string `json:"reason_tag,omitempty"` // "extend_access" | "pause"
}

// EffectiveStatusResponse is the wire format for
// GET /api/v1/devices/{pdid}/effective-status and
// GET /api/v1/tags/{id}/effective-status. It exposes the authoritative
// server-computed enforcement state for a single target, eliminating the
// need for clients to re-derive it from raw policy + schedule lists.
type EffectiveStatusResponse struct {
	Action          models.Action         `json:"action"`           // allow | block
	Source          EffectiveStatusSource `json:"source"`           // which precedence branch produced this action
	ExtendAvailable bool                  `json:"extend_available"` // false if already allowed, infra, or global kill-switch
	PauseAvailable  bool                  `json:"pause_available"`  // false if infra or global kill-switch
	ActiveExtension *ExtensionInfo        `json:"active_extension,omitempty"`
}
