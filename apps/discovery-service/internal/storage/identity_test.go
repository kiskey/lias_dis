package storage

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/user/lias-dis/shared/models"
)

func TestLegacyPDIDAndDeviceIDRemainStableAcrossReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity.db")
	s, err := NewStorage(path)
	if err != nil {
		t.Fatal(err)
	}
	d := &models.Device{PDID: "legacy-public-key", CurrentMAC: "00:11:22:33:44:55", Hostname: "phone", FirstSeen: time.Now(), LastSeen: time.Now()}
	if err := s.SaveDevice(d); err != nil {
		t.Fatal(err)
	}
	deviceID := d.DeviceID
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = NewStorage(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	devices, err := s.LoadHydrate()
	if err != nil {
		t.Fatal(err)
	}
	if len(devices) != 1 || devices[0].PDID != "legacy-public-key" || devices[0].DeviceID != deviceID {
		t.Fatalf("identity changed across migration/reopen: %+v", devices)
	}
}

func TestVerifiedAliasCannotBelongToTwoDevices(t *testing.T) {
	s, err := NewStorage(filepath.Join(t.TempDir(), "aliases.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	now := time.Now()
	for _, d := range []*models.Device{{DeviceID: "dev_a", PDID: "pdid_a", FirstSeen: now, LastSeen: now}, {DeviceID: "dev_b", PDID: "pdid_b", FirstSeen: now, LastSeen: now}} {
		if err := s.SaveDevice(d); err != nil {
			t.Fatal(err)
		}
	}
	alias := models.IdentityAlias{DeviceID: "dev_a", Type: models.AliasMAC, ValueHash: "hash", Verified: true, FirstSeen: now, LastSeen: now}
	if _, err := s.UpsertIdentityAlias(alias); err != nil {
		t.Fatal(err)
	}
	alias.DeviceID = "dev_b"
	if _, err := s.UpsertIdentityAlias(alias); !errors.Is(err, ErrAliasConflict) {
		t.Fatalf("wanted conflict, got %v", err)
	}
}

func TestCandidateDecisionAndRedirect(t *testing.T) {
	s, err := NewStorage(filepath.Join(t.TempDir(), "candidate.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	id, err := s.UpsertIdentityCandidate(models.IdentityCandidateLink{SourcePDID: "a", TargetPDID: "b", Probability: .8})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.DecideIdentityCandidate(id, "rejected", "test"); err != nil {
		t.Fatal(err)
	}
	candidate, err := s.GetIdentityCandidate(id)
	if err != nil || candidate.Status != "rejected" {
		t.Fatalf("decision not persisted: %+v %v", candidate, err)
	}
}
