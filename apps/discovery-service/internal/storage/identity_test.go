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

func TestIdenticalAliasRefreshDoesNotWriteSQLite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "alias-refresh.db")
	s, err := NewStorage(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	now := time.Now().UTC().Truncate(time.Millisecond)
	if err := s.SaveDevice(&models.Device{DeviceID: "dev_a", PDID: "pdid_a", FirstSeen: now, LastSeen: now}); err != nil {
		t.Fatal(err)
	}
	alias := models.IdentityAlias{DeviceID: "dev_a", PDID: "pdid_a", Type: models.AliasMAC, ValueHash: "hash", Source: "openwrt_ap", Confidence: .9, FirstSeen: now, LastSeen: now}
	if _, err := s.UpsertIdentityAlias(alias); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec("PRAGMA wal_checkpoint(TRUNCATE)"); err != nil {
		t.Fatal(err)
	}
	before := sqliteTotalChanges(t, s)
	alias.LastSeen = now.Add(5 * time.Minute)
	if _, err := s.UpsertIdentityAlias(alias); err != nil {
		t.Fatal(err)
	}
	if after := sqliteTotalChanges(t, s); after != before {
		t.Fatalf("identical alias refresh changed SQLite: before=%d after=%d", before, after)
	}
	aliases, err := s.ListIdentityAliases("pdid_a")
	if err != nil || len(aliases) != 1 || !aliases[0].LastSeen.Equal(now) {
		t.Fatalf("durable alias activity changed: aliases=%+v err=%v", aliases, err)
	}

	alias.Confidence = .95
	if _, err := s.UpsertIdentityAlias(alias); err != nil {
		t.Fatal(err)
	}
	if after := sqliteTotalChanges(t, s); after <= before {
		t.Fatalf("material confidence increase did not write SQLite: before=%d after=%d", before, after)
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

func TestIdenticalCandidateEvidenceDoesNotWriteSQLite(t *testing.T) {
	s, err := NewStorage(filepath.Join(t.TempDir(), "candidate-noop.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	candidate := models.IdentityCandidateLink{SourcePDID: "source", TargetPDID: "target", Probability: .8,
		Ambiguous: true, Factors: []models.IdentityFactor{{Kind: "same_ip", Matched: true, LikelihoodRatio: 2}}}
	id, err := s.UpsertIdentityCandidate(candidate)
	if err != nil {
		t.Fatal(err)
	}
	before := sqliteTotalChanges(t, s)
	repeatedID, err := s.UpsertIdentityCandidate(candidate)
	if err != nil || repeatedID != id {
		t.Fatalf("repeated candidate id=%d err=%v", repeatedID, err)
	}
	if after := sqliteTotalChanges(t, s); after != before {
		t.Fatalf("identical candidate evidence wrote SQLite: before=%d after=%d", before, after)
	}
	candidate.Probability = .85
	if _, err := s.UpsertIdentityCandidate(candidate); err != nil {
		t.Fatal(err)
	}
	if after := sqliteTotalChanges(t, s); after <= before {
		t.Fatalf("material candidate score change did not write: before=%d after=%d", before, after)
	}
}
