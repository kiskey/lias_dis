package api

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/user/lias-dis/shared/models"
)

func TestCapabilitiesV1GoldenContract(t *testing.T) {
	want, err := os.ReadFile("testdata/capabilities_v1.json")
	if err != nil {
		t.Fatal(err)
	}
	got, err := json.MarshalIndent(DISCapabilities(), "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	got = append(got, '\n')
	if !bytes.Equal(got, want) {
		t.Fatalf("v1 capabilities changed without an explicit schema decision:\nwant:\n%s\ngot:\n%s", want, got)
	}
}

func TestCurrentDeviceListDecodesWithLegacyV1Client(t *testing.T) {
	type legacyDeviceV1 struct {
		PDID       string   `json:"pdid"`
		CurrentMAC string   `json:"current_mac"`
		CurrentIP  string   `json:"current_ip"`
		Hostname   string   `json:"hostname"`
		Online     bool     `json:"online"`
		Tags       []string `json:"tags"`
	}
	type legacyListV1 struct {
		Devices []legacyDeviceV1 `json:"devices"`
		Total   int              `json:"total"`
	}

	current := DeviceListResponse{
		Devices: []models.Device{{
			DeviceID: "internal-immutable-id", PDID: "pdid_public",
			CurrentMAC: "02:00:00:00:00:01", CurrentIP: "192.168.1.20",
			Hostname: "phone", Online: true, Tags: []string{"kids"},
			IdentityAssurance:   models.IdentityVerified,
			IdentityProbability: 1, IdentityAmbiguous: false,
			FirstSeen: time.Unix(1_700_000_000, 0),
			LastSeen:  time.Unix(1_700_000_100, 0),
		}},
		Total: 1,
	}
	wire, err := json.Marshal(current)
	if err != nil {
		t.Fatal(err)
	}
	var legacy legacyListV1
	if err := json.Unmarshal(wire, &legacy); err != nil {
		t.Fatalf("legacy LIAS decoder rejected additive DIS fields: %v", err)
	}
	if legacy.Total != 1 || len(legacy.Devices) != 1 || legacy.Devices[0].PDID != "pdid_public" ||
		legacy.Devices[0].CurrentMAC != "02:00:00:00:00:01" || !legacy.Devices[0].Online {
		t.Fatalf("legacy contract values changed: %+v", legacy)
	}
}

func TestCurrentClientIgnoresFutureResponseFields(t *testing.T) {
	wire := []byte(`{
		"devices":[{
			"pdid":"pdid_future",
			"current_mac":"02:00:00:00:00:02",
			"online":true,
			"future_device_field":{"nested":true}
		}],
		"total":1,
		"future_top_level_field":"ignored"
	}`)
	var current DeviceListResponse
	if err := json.Unmarshal(wire, &current); err != nil {
		t.Fatalf("current LIAS decoder rejected future additive fields: %v", err)
	}
	if current.Total != 1 || len(current.Devices) != 1 || current.Devices[0].PDID != "pdid_future" {
		t.Fatalf("known fields were not preserved: %+v", current)
	}
}

func TestAndroidIdentityGoldenContractsRemainAdditive(t *testing.T) {
	candidateWire, err := os.ReadFile("testdata/identity_candidates_v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var candidates models.IdentityCandidateListResponse
	if err := json.Unmarshal(candidateWire, &candidates); err != nil || len(candidates.Candidates) != 1 {
		t.Fatalf("candidate fixture decode failed: candidates=%+v err=%v", candidates, err)
	}
	candidate := candidates.Candidates[0]
	if candidate.SourcePDID != "pdid_source" || candidate.TargetPDID != "pdid_target" || len(candidate.Conflicts) != 1 {
		t.Fatalf("candidate identity fields changed: %+v", candidate)
	}

	profileWire, err := os.ReadFile("testdata/identity_profile_v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var profile models.IdentityProfile
	if err := json.Unmarshal(profileWire, &profile); err != nil || profile.PDID != "pdid_target" || profile.Assurance != models.IdentityVerified {
		t.Fatalf("profile fixture decode failed: profile=%+v err=%v", profile, err)
	}

	// This deliberately mirrors an additive Android decoder: known identity
	// fields are retained and unknown server fields remain harmless.
	type androidDeviceContract struct {
		PDID                string                   `json:"pdid"`
		IdentityTier        models.IdentityTier      `json:"identity_tier"`
		IdentityAssurance   models.IdentityAssurance `json:"identity_assurance"`
		IdentityProbability float64                  `json:"identity_probability"`
		IdentityAmbiguous   bool                     `json:"identity_ambiguous"`
	}
	type androidDeviceListContract struct {
		Devices []androidDeviceContract `json:"devices"`
		Total   int                     `json:"total"`
	}
	deviceWire, err := os.ReadFile("testdata/device_identity_v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var devices androidDeviceListContract
	if err := json.Unmarshal(deviceWire, &devices); err != nil {
		t.Fatalf("Android-compatible identity decode rejected additive fields: %v", err)
	}
	if devices.Total != 1 || len(devices.Devices) != 1 || devices.Devices[0].PDID != "pdid_target" ||
		devices.Devices[0].IdentityTier != models.TierBIA || devices.Devices[0].IdentityAssurance != models.IdentityVerified ||
		devices.Devices[0].IdentityProbability != 1 || devices.Devices[0].IdentityAmbiguous {
		t.Fatalf("Android identity contract values changed: %+v", devices)
	}
}

func TestLIASSnapshotGoldenSupportsLowResourceClients(t *testing.T) {
	type snapshotContract struct {
		Revision                uint64                     `json:"revision"`
		Devices                 []models.Device            `json:"devices"`
		Users                   []models.User              `json:"users"`
		DeviceEffectiveStatuses map[string]json.RawMessage `json:"device_effective_statuses"`
		TagEffectiveStatuses    map[string]json.RawMessage `json:"tag_effective_statuses"`
	}
	wire, err := os.ReadFile("testdata/lias_snapshot_v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var snapshot snapshotContract
	if err := json.Unmarshal(wire, &snapshot); err != nil {
		t.Fatalf("snapshot fixture decode failed: %v", err)
	}
	if snapshot.Revision != 7 || snapshot.Devices == nil || snapshot.Users == nil ||
		snapshot.DeviceEffectiveStatuses == nil || snapshot.TagEffectiveStatuses == nil {
		t.Fatalf("snapshot synchronization fields changed: %+v", snapshot)
	}
}
