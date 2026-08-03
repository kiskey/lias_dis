// Package inventory provides identity helpers for DIS.
//
// File:    apps/discovery-service/internal/inventory/pdid.go
// Version: 2.3
package inventory

import (
	"crypto/sha256"
	"encoding/hex"
	"net"
	"strconv"
	"strings"
	"time"

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

// GeneratePDID produces a deterministic Tiered Persistent Device Identity using sha256 and v2 salts.
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
	cleanMAC := NormalizeMAC(mac)
	cleanHost := strings.ToLower(strings.TrimSpace(hostname))

	// 1. Burned-In Address (BIA) Anchor
	if cleanMAC != "" && !oui.IsRandomizedMAC(cleanMAC) {
		return models.TierBIA, cleanMAC
	}

	// 2. L7 Fingerprint Anchor
	if cleanHost != "" {
		anchor := cleanHost
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

// NormalizeMAC cleans and formats hardware addresses to colon-separated lowercase form.
func NormalizeMAC(macStr string) string {
	if macStr == "" {
		return ""
	}

	hw, err := net.ParseMAC(macStr)
	if err != nil {
		clean := strings.ReplaceAll(macStr, "-", "")
		clean = strings.ReplaceAll(clean, ".", "")
		clean = strings.ReplaceAll(clean, ":", "")
		if len(clean) == 12 {
			hw, err = net.ParseMAC(
				clean[0:2] + ":" + clean[2:4] + ":" + clean[4:6] + ":" +
					clean[6:8] + ":" + clean[8:10] + ":" + clean[10:12],
			)
		}
	}

	if err != nil || len(hw) == 0 {
		return ""
	}

	return hw.String()
}
