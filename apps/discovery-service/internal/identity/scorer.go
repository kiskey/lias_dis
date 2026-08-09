package identity

import (
	"math"
	"strings"
	"time"

	"github.com/user/lias-dis/shared/models"
)

const (
	// PassiveCandidateThreshold controls whether an uncertain relationship is
	// retained for administrator review. It never authorizes an automatic
	// merge.
	PassiveCandidateThreshold = 0.50
	// AutoMergeThreshold is intentionally unreachable by passive factors.
	// Only a verified/manual alias path may authorize an automatic attachment.
	AutoMergeThreshold = 0.999999
)

type PassiveInput struct {
	SameIP            bool
	CanonicalHostname string
	ExistingHostname  string
	Services          []string
	ExistingServices  []string
	Vendor            string
	ExistingVendor    string
	NewMAC            string
	ExistingMAC       string
	ExistingOnline    bool
	ExistingLastSeen  time.Time
	ObservedAt        time.Time
}

type Decision struct {
	Probability float64
	Ambiguous   bool
	Conflict    bool
	AutoMerge   bool
	Factors     []models.IdentityFactor
}

// ScorePassive computes a conservative Bayesian policy score. The likelihood
// ratios are explicit and auditable; they are not represented as empirical
// calibration. Batch 5 can replace them with measured values from a labeled
// corpus without changing the decision contract.
func ScorePassive(input PassiveInput) Decision {
	const priorSameDevice = 0.05
	logOdds := math.Log(priorSameDevice / (1 - priorSameDevice))
	factors := make([]models.IdentityFactor, 0, 6)

	add := func(kind string, matched bool, lr float64) {
		factors = append(factors, models.IdentityFactor{Kind: kind, Matched: matched, LikelihoodRatio: lr})
		if matched {
			logOdds += math.Log(lr)
		}
	}

	add("same_ip", input.SameIP, 2.0)

	hostMatch := input.CanonicalHostname != "" && input.ExistingHostname != "" &&
		strings.EqualFold(input.CanonicalHostname, input.ExistingHostname)
	add("canonical_hostname", hostMatch, 8.0)

	serviceSimilarity := jaccard(input.Services, input.ExistingServices)
	add("service_jaccard_gte_0_5", serviceSimilarity >= 0.5, 4.0)

	recentHandoff := !input.ExistingLastSeen.IsZero() && !input.ObservedAt.IsZero() &&
		input.ObservedAt.Sub(input.ExistingLastSeen) >= 0 &&
		input.ObservedAt.Sub(input.ExistingLastSeen) <= 60*time.Second
	add("temporal_handoff_lte_60s", recentHandoff, 3.0)

	trustedVendorComparable := input.Vendor != "" && input.ExistingVendor != "" &&
		!IsLocallyAdministeredMAC(input.NewMAC) && !IsLocallyAdministeredMAC(input.ExistingMAC)
	vendorMatch := trustedVendorComparable && strings.EqualFold(input.Vendor, input.ExistingVendor)
	add("global_mac_vendor", vendorMatch, 1.5)

	simultaneous := input.ExistingOnline && recentHandoff
	add("simultaneous_presence_conflict", simultaneous, 0.02)

	probability := 1 / (1 + math.Exp(-logOdds))
	conflict := simultaneous && probability < PassiveCandidateThreshold
	return Decision{
		Probability: probability,
		Ambiguous:   probability >= PassiveCandidateThreshold,
		Conflict:    conflict,
		AutoMerge:   false,
		Factors:     factors,
	}
}

func jaccard(a, b []string) float64 {
	left := make(map[string]struct{}, len(a))
	right := make(map[string]struct{}, len(b))
	for _, value := range a {
		if value = strings.ToLower(strings.TrimSpace(value)); value != "" {
			left[value] = struct{}{}
		}
	}
	for _, value := range b {
		if value = strings.ToLower(strings.TrimSpace(value)); value != "" {
			right[value] = struct{}{}
		}
	}
	if len(left) == 0 || len(right) == 0 {
		return 0
	}
	intersection := 0
	for value := range left {
		if _, exists := right[value]; exists {
			intersection++
		}
	}
	union := len(left) + len(right) - intersection
	return float64(intersection) / float64(union)
}
