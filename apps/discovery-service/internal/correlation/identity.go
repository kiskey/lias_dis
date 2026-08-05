// Package correlation implements the correlation, identity, and enrichment engine for DIS.
//
// File:    apps/discovery-service/internal/correlation/identity.go
// Version: 2.4 (Verified Identity Helpers)
package correlation

import (
    "github.com/user/lias-dis/apps/discovery-service/internal/inventory"
    "github.com/user/lias-dis/shared/models"
)

func TierPrefix(tier models.IdentityTier) string {
    return inventory.TierPrefix(tier)
}

func GeneratePDID(tier models.IdentityTier, anchor string) string {
    return inventory.GeneratePDID(tier, anchor)
}

func DeriveTierAndAnchor(mac, hostname, vendor string) (models.IdentityTier, string) {
    return inventory.DeriveTierAndAnchor(mac, hostname, vendor)
}

func CanPromote(from, to models.IdentityTier) bool {
    return inventory.CanPromote(from, to)
}
