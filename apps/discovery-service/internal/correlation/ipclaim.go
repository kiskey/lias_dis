// Package correlation implements the correlation, identity, and enrichment engine for DIS.
//
// File:    apps/discovery-service/internal/correlation/ipclaim.go
// Version: 1.3 (Removed Unused Import)
package correlation

import (
    "github.com/user/lias-dis/apps/discovery-service/internal/discovery"
	identitycore "github.com/user/lias-dis/apps/discovery-service/internal/identity"
    "github.com/user/lias-dis/shared/models"
)

type IPClaimResult int

const (
    ClaimAttach IPClaimResult = iota
    ClaimCreateNew
    ClaimCreateNewSilent
)

func ValidateIPClaim(obs discovery.Observation, existing *models.Device) IPClaimResult {
    if existing == nil || obs.MAC == nil {
        return ClaimCreateNewSilent
    }
	decision := identitycore.ScorePassive(identitycore.PassiveInput{
		SameIP: true, CanonicalHostname: CanonicalizeHostname(obs.Hostname),
		ExistingHostname: existing.CanonicalHostname, Services: obs.Services,
		ExistingServices: existing.Services, Vendor: obs.Vendor, ExistingVendor: existing.Vendor,
		NewMAC: obs.MAC.String(), ExistingMAC: existing.CurrentMAC,
		ExistingOnline: existing.Online, ExistingLastSeen: existing.LastSeen,
		ObservedAt: normalizedObservationTime(obs.Timestamp),
	})
	// Compatibility wrapper: passive evidence is never allowed to return
	// ClaimAttach. A high score is stored as a candidate by Engine.
	if decision.Probability >= identitycore.PassiveCandidateThreshold {
        return ClaimCreateNewSilent
    }
    return ClaimCreateNew
}
