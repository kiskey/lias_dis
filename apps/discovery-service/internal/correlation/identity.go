// Package correlation implements the correlation, identity, and enrichment engine for DIS.
//
// File:    apps/discovery-service/internal/correlation/identity.go
// Version: 1.0
package correlation

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"time"

	"github.com/user/lias-dis/apps/discovery-service/internal/inventory"
	"github.com/user/lias-dis/pkg/oui"
	"github.com/user/lias-dis/shared/models"
)

// TierPrefix returns the string prefix corresponding to an IdentityTier.
func TierPrefix(tier models.IdentityTier) string {
	switch tier {
	case models.TierBIA:
		return "pdid_bia_"
	case models.TierL7:
		return "pdid_l7_"
	default:
		return "pdid_tent_"
	}
}

// GeneratePDID produces a deterministic Tiered Persistent Device Identity.
func GeneratePDID(tier models.IdentityTier, anchor string) string {
	h := sha256.New()
	switch tier {
	case models.TierBIA:
		h.Write([]byte("bia_v2:"))
		h.Write([]byte(anchor))
	case models.TierL7:
		h.Write([]byte("l7_v2:"))
		h.Write([]byte(anchor))
	case models.TierTentative:
		h.Write([]byte("tent_v2:"))
		h.Write([]byte(anchor))
	}
	return TierPrefix(tier) + hex.EncodeToString(h.Sum(nil))[:16]
}

// DeriveTierAndAnchor determines the appropriate identity tier and anchor string for a new observation.
func DeriveTierAndAnchor(mac, hostname, vendor string) (models.IdentityTier, string) {
	cleanMAC := inventory.NormalizeMAC(mac)
	canonicalHost := CanonicalizeHostname(hostname)

	// 1. Burned-In Address (BIA) Anchor
	if cleanMAC != "" && !oui.IsRandomizedMAC(cleanMAC) {
		return models.TierBIA, cleanMAC
	}

	// 2. L7 Fingerprint Anchor
	if canonicalHost != "" {
		anchor := canonicalHost
		if vendor != "" {
			anchor += ":" + vendor
		}
		return models.TierL7, anchor
	}

	// 3. Tentative Identity Anchor
	anchor := cleanMAC
	if anchor == "" {
		anchor = "tent_" + strconv.FormatInt(time.Now().UnixNano(), 10)
	}
	return models.TierTentative, anchor
}

// CanPromote reports whether a transition from fromTier to toTier is permitted.
func CanPromote(from, to models.IdentityTier) bool {
	if from == models.TierTentative {
		return to == models.TierL7 || to == models.TierBIA
	}
	if from == models.TierL7 {
		return to == models.TierBIA
	}
	return false
}
