package identity

import (
	"math"
	"testing"
	"time"
)

func TestPrivateMACIdentityCorrectnessMatrix(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	cases := []struct {
		name          string
		input         PassiveInput
		wantCandidate bool
		wantConflict  bool
	}{
		{
			name: "dhcp address reuse alone",
			input: PassiveInput{SameIP: true, NewMAC: "02:00:00:00:00:02",
				ExistingMAC: "02:00:00:00:00:01", ObservedAt: now},
		},
		{
			name: "apple private MAC rotation with strong passive continuity",
			input: PassiveInput{SameIP: true, CanonicalHostname: "iphone", ExistingHostname: "iphone",
				Services: []string{"_airplay._tcp", "_companion-link._tcp"}, ExistingServices: []string{"_airplay._tcp", "_companion-link._tcp"},
				Vendor: "Apple", ExistingVendor: "Apple", NewMAC: "02:00:00:00:00:02", ExistingMAC: "02:00:00:00:00:01",
				ExistingLastSeen: now.Add(-30 * time.Second), ObservedAt: now},
			wantCandidate: true,
		},
		{
			name: "android persistent randomization after network reset",
			input: PassiveInput{SameIP: true, CanonicalHostname: "pixel-6a", ExistingHostname: "pixel-6a",
				Services: []string{"_googlecast._tcp"}, ExistingServices: []string{"_googlecast._tcp"},
				NewMAC: "02:10:20:30:40:50", ExistingMAC: "02:aa:bb:cc:dd:ee",
				ExistingLastSeen: now.Add(-24 * time.Hour), ObservedAt: now},
			wantCandidate: true,
		},
		{
			name: "simultaneous identical devices",
			input: PassiveInput{SameIP: true, CanonicalHostname: "iphone", ExistingHostname: "iphone",
				Services: []string{"_airplay._tcp"}, ExistingServices: []string{"_airplay._tcp"},
				NewMAC: "02:00:00:00:00:03", ExistingMAC: "02:00:00:00:00:04",
				ExistingOnline: true, ExistingLastSeen: now.Add(-5 * time.Second), ObservedAt: now},
			wantConflict: true,
		},
		{
			name: "spoofed hostname and services while old device online",
			input: PassiveInput{SameIP: true, CanonicalHostname: "trusted-phone", ExistingHostname: "trusted-phone",
				Services: []string{"_airplay._tcp"}, ExistingServices: []string{"_airplay._tcp"},
				NewMAC: "02:de:ad:be:ef:01", ExistingMAC: "02:de:ad:be:ef:02",
				ExistingOnline: true, ExistingLastSeen: now.Add(-time.Second), ObservedAt: now},
			wantConflict: true,
		},
		{
			name: "unrelated rotating MAC without continuity",
			input: PassiveInput{NewMAC: "02:00:00:00:00:05", ExistingMAC: "02:00:00:00:00:06",
				ExistingLastSeen: now.Add(-time.Hour), ObservedAt: now},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			decision := ScorePassive(tc.input)
			if decision.AutoMerge {
				t.Fatal("passive matrix case authorized automatic merge")
			}
			if math.IsNaN(decision.Probability) || decision.Probability < 0 || decision.Probability > 1 {
				t.Fatalf("invalid probability: %v", decision.Probability)
			}
			if decision.Ambiguous != tc.wantCandidate {
				t.Fatalf("candidate mismatch: got=%v probability=%.6f", decision.Ambiguous, decision.Probability)
			}
			if decision.Conflict != tc.wantConflict {
				t.Fatalf("conflict mismatch: got=%v probability=%.6f", decision.Conflict, decision.Probability)
			}
		})
	}
}

func BenchmarkScorePassive(b *testing.B) {
	now := time.Now()
	input := PassiveInput{SameIP: true, CanonicalHostname: "phone", ExistingHostname: "phone",
		Services: []string{"_airplay._tcp", "_companion-link._tcp"}, ExistingServices: []string{"_airplay._tcp", "_companion-link._tcp"},
		NewMAC: "02:00:00:00:00:02", ExistingMAC: "02:00:00:00:00:01",
		ExistingLastSeen: now.Add(-30 * time.Second), ObservedAt: now}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = ScorePassive(input)
	}
}
