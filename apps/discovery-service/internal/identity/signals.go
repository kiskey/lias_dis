package identity

import (
	"fmt"
	"strings"

	"github.com/user/lias-dis/apps/discovery-service/internal/discovery"
	"github.com/user/lias-dis/shared/models"
)

type Signal struct {
	Type       models.IdentityAliasType
	Value      string
	Source     string
	Confidence float64
	Verified   bool
}

var trustedAuthenticatedSources = map[string]struct{}{
	"openwrt_ap": {},
	"controller": {},
	"mdm":        {},
	"companion":  {},
}

// ObservationSignals extracts aliases without trusting arbitrary provider Raw
// data. Stable credentials are marked verified only when both the provider is
// allow-listed and it explicitly asserts identity_authenticated=true.
func ObservationSignals(obs discovery.Observation, mac, canonicalHost string) []Signal {
	signals := make([]Signal, 0, 5)
	if mac != "" {
		signals = append(signals, Signal{
			Type: models.AliasMAC, Value: mac, Source: obs.Source,
			Confidence: obs.Confidence, Verified: false,
		})
	}
	if canonicalHost != "" {
		signals = append(signals, Signal{
			Type: models.AliasHostname, Value: canonicalHost, Source: obs.Source,
			Confidence: obs.Confidence, Verified: false,
		})
	}
	if services := ServiceSetValue(obs.Services); services != "" {
		signals = append(signals, Signal{
			Type: models.AliasServiceSet, Value: services, Source: obs.Source,
			Confidence: obs.Confidence, Verified: false,
		})
	}

	if !rawAuthenticated(obs.Raw) {
		return signals
	}
	if _, trusted := trustedAuthenticatedSources[strings.ToLower(obs.Source)]; !trusted {
		return signals
	}

	stableKeys := []struct {
		key       string
		aliasType models.IdentityAliasType
	}{
		{"dhcp_client_id", models.AliasDHCPClientID},
		{"ppsk_id", models.AliasPPSK},
		{"eap_tls_subject", models.AliasEAPTLSSubject},
		{"mdm_device_id", models.AliasMDMDeviceID},
		{"device_public_key", models.AliasDevicePublicKey},
	}
	for _, item := range stableKeys {
		if value := rawString(obs.Raw[item.key]); value != "" {
			signals = append(signals, Signal{
				Type: item.aliasType, Value: value, Source: obs.Source,
				Confidence: 1, Verified: true,
			})
		}
	}
	return signals
}

func rawAuthenticated(raw map[string]interface{}) bool {
	if raw == nil {
		return false
	}
	value, ok := raw["identity_authenticated"]
	if !ok {
		return false
	}
	switch typed := value.(type) {
	case bool:
		return typed
	case string:
		return strings.EqualFold(strings.TrimSpace(typed), "true")
	default:
		return false
	}
}

func rawString(value interface{}) string {
	switch typed := value.(type) {
	case string:
		return strings.TrimSpace(typed)
	case fmt.Stringer:
		return strings.TrimSpace(typed.String())
	default:
		return ""
	}
}
