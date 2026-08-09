// Package identity implements conservative device-identity evidence handling.
package identity

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"sort"
	"strings"

	"github.com/user/lias-dis/shared/models"
)

var ErrInvalidAlias = errors.New("invalid identity alias")

func NormalizeAlias(aliasType models.IdentityAliasType, value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", ErrInvalidAlias
	}

	switch aliasType {
	case models.AliasMAC:
		hw, err := net.ParseMAC(value)
		if err != nil || len(hw) != 6 {
			return "", ErrInvalidAlias
		}
		return strings.ToLower(hw.String()), nil
	case models.AliasHostname:
		value = strings.TrimSuffix(strings.ToLower(value), ".")
	case models.AliasServiceSet:
		parts := strings.Split(value, ",")
		normalized := make([]string, 0, len(parts))
		for _, part := range parts {
			if item := strings.ToLower(strings.TrimSpace(part)); item != "" {
				normalized = append(normalized, item)
			}
		}
		if len(normalized) == 0 {
			return "", ErrInvalidAlias
		}
		sort.Strings(normalized)
		value = strings.Join(normalized, ",")
	case models.AliasDHCPClientID, models.AliasPPSK, models.AliasEAPTLSSubject,
		models.AliasMDMDeviceID, models.AliasDevicePublicKey, models.AliasManual:
		// Stable credentials and administrator-provided bindings are opaque.
		// Trim surrounding whitespace but retain case because some IDs are
		// case-sensitive.
	default:
		return "", ErrInvalidAlias
	}

	if len(value) > 1024 {
		return "", ErrInvalidAlias
	}
	return value, nil
}

func HashAlias(aliasType models.IdentityAliasType, value string) (string, error) {
	normalized, err := NormalizeAlias(aliasType, value)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256([]byte(string(aliasType) + "\x00" + normalized))
	return hex.EncodeToString(digest[:]), nil
}

func IsLocallyAdministeredMAC(value string) bool {
	hw, err := net.ParseMAC(value)
	if err != nil || len(hw) != 6 {
		return false
	}
	return hw[0]&0x02 != 0
}

func IsUnicastMAC(value string) bool {
	hw, err := net.ParseMAC(value)
	if err != nil || len(hw) != 6 {
		return false
	}
	return hw[0]&0x01 == 0
}

func ServiceSetValue(services []string) string {
	normalized := make([]string, 0, len(services))
	seen := make(map[string]struct{}, len(services))
	for _, service := range services {
		value := strings.ToLower(strings.TrimSpace(service))
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		normalized = append(normalized, value)
	}
	sort.Strings(normalized)
	return strings.Join(normalized, ",")
}
