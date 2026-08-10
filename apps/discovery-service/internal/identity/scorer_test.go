package identity

import (
	"math"
	"testing"
	"time"
)

func TestPassiveEvidenceNeverAutoMerges(t *testing.T) {
	now := time.Now()
	decision := ScorePassive(PassiveInput{
		SameIP: true, CanonicalHostname: "phone", ExistingHostname: "phone",
		Services:         []string{"_airplay._tcp", "_companion-link._tcp"},
		ExistingServices: []string{"_airplay._tcp", "_companion-link._tcp"},
		Vendor:           "Apple", ExistingVendor: "Apple",
		NewMAC: "00:11:22:33:44:55", ExistingMAC: "00:11:22:33:44:66",
		ExistingLastSeen: now.Add(-30 * time.Second), ObservedAt: now,
	})
	if decision.AutoMerge || decision.Probability >= AutoMergeThreshold {
		t.Fatalf("passive evidence authorized merge: %+v", decision)
	}
	if decision.Probability < PassiveCandidateThreshold {
		t.Fatalf("strong passive evidence should create candidate: %.6f", decision.Probability)
	}
}

func TestSimultaneousPresenceIsNegativeEvidence(t *testing.T) {
	now := time.Now()
	base := PassiveInput{SameIP: true, CanonicalHostname: "phone", ExistingHostname: "phone",
		Services: []string{"a"}, ExistingServices: []string{"a"},
		ExistingLastSeen: now.Add(-10 * time.Second), ObservedAt: now}
	offline := ScorePassive(base)
	base.ExistingOnline = true
	online := ScorePassive(base)
	if !(online.Probability < offline.Probability) {
		t.Fatalf("simultaneous presence did not reduce probability: online=%f offline=%f", online.Probability, offline.Probability)
	}
}

func TestPrivateMACDisablesOUILikelihood(t *testing.T) {
	decision := ScorePassive(PassiveInput{Vendor: "Apple", ExistingVendor: "Apple",
		NewMAC: "02:11:22:33:44:55", ExistingMAC: "00:11:22:33:44:66"})
	for _, factor := range decision.Factors {
		if factor.Kind == "global_mac_vendor" && factor.Matched {
			t.Fatal("locally administered address was treated as vendor identity")
		}
		if factor.LikelihoodRatio <= 0 || math.IsNaN(factor.LikelihoodRatio) {
			t.Fatalf("invalid likelihood ratio: %+v", factor)
		}
	}
}
