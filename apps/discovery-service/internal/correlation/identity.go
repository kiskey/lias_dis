// Package correlation implements the correlation, identity, and enrichment engine for DIS.
//
// File:    apps/discovery-service/internal/correlation/identity.go
// Version: 2.2
package correlation

import (
	"github.com/user/lias-dis/apps/discovery-service/internal/inventory"
	"github.com/user/lias-dis/shared/models"
)

// TierPrefix delegates to inventory.TierPrefix.
func TierPrefix(tier models.IdentityTier) string {
	return inventory.TierPrefix(tier)
}

// GeneratePDID delegates to inventory.GeneratePDID.
func GeneratePDID(tier models.IdentityTier, anchor string) string {
	return inventory.GeneratePDID(tier, anchor)
}

// DeriveTierAndAnchor delegates to inventory.DeriveTierAndAnchor.
func DeriveTierAndAnchor(mac, hostname, vendor string) (models.IdentityTier, string) {
	return inventory.DeriveTierAndAnchor(mac, hostname, vendor)
}

// CanPromote delegates to inventory.CanPromote.
func CanPromote(from, to models.IdentityTier) bool {
	return inventory.CanPromote(from, to)
}
