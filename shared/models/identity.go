// Package models defines identity-assurance wire and persistence types shared
// by DIS and LIAS. These fields are additive to the existing device contract.
package models

import (
	"errors"
	"time"
)

var (
	ErrCandidateStaleOrConflicting = errors.New("candidate stale or conflicting")
	ErrCandidateNotFound           = errors.New("candidate not found")
)

type IdentityAssurance string

const (
	IdentityUnverified IdentityAssurance = "unverified"
	IdentityCandidate  IdentityAssurance = "candidate"
	IdentityStrong     IdentityAssurance = "strong"
	IdentityVerified   IdentityAssurance = "verified"
)

type IdentityAliasType string

const (
	AliasMAC             IdentityAliasType = "mac"
	AliasHostname        IdentityAliasType = "hostname"
	AliasServiceSet      IdentityAliasType = "service_set"
	AliasDHCPClientID    IdentityAliasType = "dhcp_client_id"
	AliasPPSK            IdentityAliasType = "ppsk_id"
	AliasEAPTLSSubject   IdentityAliasType = "eap_tls_subject"
	AliasMDMDeviceID     IdentityAliasType = "mdm_device_id"
	AliasDevicePublicKey IdentityAliasType = "device_public_key"
	AliasManual          IdentityAliasType = "manual"
)

type IdentityAlias struct {
	ID         int64             `json:"id"`
	DeviceID   string            `json:"device_id"`
	PDID       string            `json:"pdid"`
	Type       IdentityAliasType `json:"type"`
	ValueHash  string            `json:"value_hash"`
	Source     string            `json:"source"`
	Confidence float64           `json:"confidence"`
	Verified   bool              `json:"verified"`
	FirstSeen  time.Time         `json:"first_seen"`
	LastSeen   time.Time         `json:"last_seen"`
	RevokedAt  *time.Time        `json:"revoked_at,omitempty"`
}

type IdentityFactor struct {
	Kind            string  `json:"kind"`
	LikelihoodRatio float64 `json:"likelihood_ratio"`
	Matched         bool    `json:"matched"`
}

// IdentityCandidateDevice is the bounded device summary returned with an
// identity candidate. Full device and identity profiles remain lazy routes.
type IdentityCandidateDevice struct {
	PDID        string    `json:"pdid"`
	DisplayName string    `json:"display_name"`
	CurrentMAC  string    `json:"current_mac"`
	Online      bool      `json:"online"`
	LastSeen    time.Time `json:"last_seen"`
}

type IdentityCandidateLink struct {
	ID             int64            `json:"id"`
	SourcePDID     string           `json:"source_pdid"`
	TargetPDID     string           `json:"target_pdid"`
	Probability    float64          `json:"probability"`
	Ambiguous      bool             `json:"ambiguous"`
	Status         string           `json:"status"`
	Factors        []IdentityFactor `json:"factors"`
	CreatedAt      time.Time        `json:"created_at"`
	UpdatedAt      time.Time        `json:"updated_at"`
	DecisionSource string           `json:"decision_source,omitempty"`
	DecisionNote   string           `json:"decision_note,omitempty"`
}

// IdentityCandidate decorates the persisted correlation record with the two
// current device summaries required by administrator review clients.
type IdentityCandidateDetail struct {
	ID             int64                    `json:"id"`
	SourcePDID     string                   `json:"source_pdid"`
	TargetPDID     string                   `json:"target_pdid"`
	Probability    float64                  `json:"probability"`
	Ambiguous      bool                     `json:"ambiguous"`
	Status         string                   `json:"status"`
	Factors        []IdentityFactor         `json:"factors"`
	Conflicts      []IdentityFactor         `json:"conflicts"`
	SourceDevice   *IdentityCandidateDevice `json:"source_device,omitempty"`
	TargetDevice   *IdentityCandidateDevice `json:"target_device,omitempty"`
	CreatedAt      time.Time                `json:"created_at"`
	UpdatedAt      time.Time                `json:"updated_at"`
	DecisionSource string                   `json:"decision_source,omitempty"`
	DecisionNote   string                   `json:"decision_note,omitempty"`
}

type IdentityCandidateListResponse struct {
	Candidates []IdentityCandidateDetail `json:"candidates"`
	NextCursor string                    `json:"next_cursor,omitempty"`
}

// IdentityCandidateDecisionRequest is optional on confirm/reject/reopen. The
// expected fields protect a human decision from acting on a changed candidate.
type IdentityCandidateDecisionRequest struct {
	ExpectedSourcePDID string     `json:"expected_source_pdid,omitempty"`
	ExpectedTargetPDID string     `json:"expected_target_pdid,omitempty"`
	ExpectedUpdatedAt  *time.Time `json:"expected_updated_at,omitempty"`
	DecisionNote       string     `json:"decision_note,omitempty"`
}

type IdentityEvidence struct {
	ID                int64      `json:"id"`
	DeviceID          string     `json:"device_id"`
	CandidateDeviceID string     `json:"candidate_device_id,omitempty"`
	Kind              string     `json:"kind"`
	ValueHash         string     `json:"value_hash,omitempty"`
	Source            string     `json:"source"`
	LogLikelihood     float64    `json:"log_likelihood"`
	ObservedAt        time.Time  `json:"observed_at"`
	ExpiresAt         *time.Time `json:"expires_at,omitempty"`
}

type IdentityProfile struct {
	DeviceID    string                  `json:"device_id"`
	PDID        string                  `json:"pdid"`
	Assurance   IdentityAssurance       `json:"assurance"`
	Probability float64                 `json:"probability"`
	Ambiguous   bool                    `json:"ambiguous"`
	Aliases     []IdentityAlias         `json:"aliases"`
	Candidates  []IdentityCandidateLink `json:"candidates"`
	Evidence    []IdentityEvidence      `json:"evidence"`
}

type IdentityBindingRequest struct {
	Type   IdentityAliasType `json:"type"`
	Value  string            `json:"value"`
	Source string            `json:"source,omitempty"`
}

type IdentitySplitRequest struct {
	MAC     string   `json:"mac"`
	MoveIPs []string `json:"move_ips,omitempty"`
}
