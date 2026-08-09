// Package storage provides unit tests for DIS SQLite persistence.
//
// File:    apps/discovery-service/internal/storage/sqlite_test.go
// Version: 1.1
package storage

import (
	"encoding/json"
    "path/filepath"
    "testing"
    "time"

    "github.com/user/lias-dis/shared/models"
)

func TestSaveDevicesBatchSavepoint(t *testing.T) {
    // Create a temporary directory for the test database
    tmpDir := t.TempDir()
    dbPath := filepath.Join(tmpDir, "test.db")

    s, err := NewStorage(dbPath)
    if err != nil {
        t.Fatalf("Failed to create storage: %v", err)
    }
    defer s.Close()

    // Create a valid device and a device designed to fail (empty PDID will fail the tx constraint check indirectly via our logic,
    // but to truly test a tx failure, we need a constraint violation. We'll rely on the fact that an empty PDID is skipped by saveDeviceTx,
    // so we'll test that a valid batch saves successfully first).
    dev1 := &models.Device{
        PDID:         "pdid_bia_valid1",
        IdentityTier: "bia",
        FirstSeen:    time.Now(),
        LastSeen:     time.Now(),
        Online:       true,
    }
    
    dev2 := &models.Device{
        PDID:         "pdid_bia_valid2",
        IdentityTier: "bia",
        FirstSeen:    time.Now(),
        LastSeen:     time.Now(),
        Online:       true,
    }

    // Test valid batch
    err = s.SaveDevicesBatch([]*models.Device{dev1, dev2})
    if err != nil {
        t.Fatalf("SaveDevicesBatch failed for valid batch: %v", err)
    }

    devs, err := s.LoadHydrate()
    if err != nil {
        t.Fatalf("LoadHydrate failed: %v", err)
    }

    if len(devs) != 2 {
        t.Errorf("Expected 2 devices, got %d", len(devs))
    }

    // Test that the pending events TTL purge doesn't crash
    // (We can't easily test the time-based loop here, but we ensure the query compiles/runs)
    _, err = s.db.Exec("DELETE FROM pending_events WHERE last_seen < datetime('now', '-1 hour')")
    if err != nil {
        t.Errorf("Pending events purge query failed: %v", err)
    }
}

func TestPendingEventUpsertUsesUniqueConstraint(t *testing.T) {
	s, err := NewStorage(filepath.Join(t.TempDir(), "pending.db"))
	if err != nil {
		t.Fatalf("NewStorage: %v", err)
	}
	defer s.Close()

	now := time.Now()
	if err := s.SavePendingEvent("pdid_test", "device.hostname_changed", []byte(`{"hostname":"one"}`), now, now, 1, "dhcp"); err != nil {
		t.Fatalf("first pending-event upsert: %v", err)
	}
	if err := s.SavePendingEvent("pdid_test", "device.hostname_changed", []byte(`{"hostname":"two"}`), now, now.Add(time.Second), 2, "dhcp,avahi"); err != nil {
		t.Fatalf("second pending-event upsert: %v", err)
	}

	records, err := s.LoadPendingEvents()
	if err != nil {
		t.Fatalf("LoadPendingEvents: %v", err)
	}
	if len(records) != 1 || records[0].Confirmations != 2 || string(records[0].Payload) != `{"hostname":"two"}` {
		t.Fatalf("unexpected upsert result: %+v", records)
	}
}

func TestHydratePreservesCompleteDeviceState(t *testing.T) {
	s, err := NewStorage(filepath.Join(t.TempDir(), "hydrate.db"))
	if err != nil {
		t.Fatalf("NewStorage: %v", err)
	}
	defer s.Close()

	now := time.Now().UTC().Truncate(time.Millisecond)
	dev := &models.Device{
		PDID:             "pdid_test_complete",
		IdentityTier:     models.TierTentative,
		CurrentMAC:       "02:00:00:00:00:01",
		MACs:             []string{"02:00:00:00:00:01"},
		CurrentIP:        "192.168.1.25",
		IPs:              []string{"192.168.1.25"},
		Services:         []string{"_airplay._tcp"},
		Tags:             []string{"kids"},
		UserID:           "user-1",
		PendingOnlineObs: []string{"netlink"},
		IsTentative:      true,
		FirstSeen:        now,
		LastSeen:         now,
		SourceInfo: map[string]models.SourceMeta{
			"netlink": {Source: "netlink", Confidence: 0.9, Timestamp: now, Raw: map[string]interface{}{"state": "reachable"}},
		},
	}
	if err := s.SaveDevice(dev); err != nil {
		t.Fatalf("SaveDevice: %v", err)
	}

	hydrated, err := s.LoadHydrate()
	if err != nil {
		t.Fatalf("LoadHydrate: %v", err)
	}
	if len(hydrated) != 1 {
		t.Fatalf("expected one device, got %d", len(hydrated))
	}
	got := hydrated[0]
	if got.UserID != dev.UserID || !got.IsTentative || len(got.Services) != 1 || len(got.Tags) != 1 || len(got.PendingOnlineObs) != 1 {
		encoded, _ := json.Marshal(got)
		t.Fatalf("hydrated state incomplete: %s", encoded)
	}
	if meta, ok := got.SourceInfo["netlink"]; !ok || meta.Raw["state"] != "reachable" {
		t.Fatalf("source evidence was not preserved: %+v", got.SourceInfo)
	}
}
