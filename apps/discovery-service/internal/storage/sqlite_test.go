// Package storage provides unit tests for DIS SQLite persistence.
//
// File:    apps/discovery-service/internal/storage/sqlite_test.go
// Version: 1.1
package storage

import (
	"database/sql"
	"encoding/json"
	"errors"
	"os"
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
	if got.UserID != dev.UserID || !got.IsTentative || len(got.Services) != 1 || len(got.Tags) != 1 || got.Online || len(got.PendingOnlineObs) != 0 {
		encoded, _ := json.Marshal(got)
		t.Fatalf("hydrated state incomplete: %s", encoded)
	}
	if meta, ok := got.SourceInfo["netlink"]; !ok || meta.Raw["state"] != "reachable" {
		t.Fatalf("source evidence was not preserved: %+v", got.SourceInfo)
	}
}

func TestHydrateAlwaysStartsPresenceOffline(t *testing.T) {
	path := filepath.Join(t.TempDir(), "stale-online.db")
	s, err := NewStorage(path)
	if err != nil {
		t.Fatal(err)
	}
	stale := time.Now()
	dev := &models.Device{
		PDID: "pdid_stale_restart", DeviceID: "dev_stale_restart",
		CurrentMAC: "00:11:22:33:44:55", MACs: []string{"00:11:22:33:44:55"},
		FirstSeen: stale.Add(-time.Hour), LastSeen: stale, Online: true,
		PendingOnlineObs: []string{"netlink"},
	}
	if err := s.SaveDevice(dev); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := NewStorage(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	devices, err := reopened.LoadHydrate()
	if err != nil {
		t.Fatal(err)
	}
	if len(devices) != 1 || devices[0].Online || len(devices[0].PendingOnlineObs) != 0 {
		t.Fatalf("volatile presence survived restart: %+v", devices)
	}
}

func TestVolatileDeviceStateDoesNotWriteSQLite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "volatile-device.db")
	s, err := NewStorage(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	initialSeen := time.Now().UTC().Truncate(time.Millisecond)
	dev := &models.Device{
		PDID: "pdid_volatile", DeviceID: "dev_volatile", Hostname: "phone",
		FirstSeen: initialSeen.Add(-time.Hour), LastSeen: initialSeen, Online: true,
		CurrentMAC: "00:11:22:33:44:55", MACs: []string{"00:11:22:33:44:55"},
		SourceInfo: map[string]models.SourceMeta{
			"openwrt_ap": {Source: "openwrt_ap", Confidence: .9, Timestamp: initialSeen, Raw: map[string]interface{}{"state": "reachable", "lease_expires_at": "soon"}},
		},
	}
	if err := s.SaveDevice(dev); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec("PRAGMA wal_checkpoint(TRUNCATE)"); err != nil {
		t.Fatal(err)
	}
	before := sqliteTotalChanges(t, s)

	dev.LastSeen = initialSeen.Add(10 * time.Minute)
	dev.Online = false
	dev.PendingOnlineObs = []string{"netlink"}
	meta := dev.SourceInfo["openwrt_ap"]
	meta.Timestamp = dev.LastSeen
	meta.Raw["lease_expires_at"] = "later"
	dev.SourceInfo["openwrt_ap"] = meta
	if err := s.SaveDevicesBatch([]*models.Device{dev}); err != nil {
		t.Fatal(err)
	}
	if after := sqliteTotalChanges(t, s); after != before {
		t.Fatalf("volatile-only save changed SQLite: before=%d after=%d", before, after)
	}
	if info, err := os.Stat(path + "-wal"); err == nil && info.Size() != 0 {
		t.Fatalf("volatile-only save appended %d bytes to WAL", info.Size())
	}

	hydrated, err := s.LoadHydrate()
	if err != nil || len(hydrated) != 1 {
		t.Fatalf("hydrate: devices=%+v err=%v", hydrated, err)
	}
	got := hydrated[0]
	if !got.LastSeen.Equal(initialSeen) || got.Online || len(got.PendingOnlineObs) != 0 {
		t.Fatalf("volatile state was persisted: %+v", got)
	}

	dev.Hostname = "phone-renamed"
	if err := s.SaveDevicesBatch([]*models.Device{dev}); err != nil {
		t.Fatal(err)
	}
	if after := sqliteTotalChanges(t, s); after <= before {
		t.Fatalf("material hostname change did not write SQLite: before=%d after=%d", before, after)
	}
}

func TestMACOwnershipConflictDoesNotCreateDeviceOrWriteWAL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mac-owner.db")
	s, err := NewStorage(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	now := time.Now()
	owner := &models.Device{DeviceID: "dev_owner", PDID: "pdid_owner", CurrentMAC: "00:11:22:33:44:55",
		MACs: []string{"00:11:22:33:44:55"}, FirstSeen: now, LastSeen: now}
	if err := s.SaveDevice(owner); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec("PRAGMA wal_checkpoint(TRUNCATE)"); err != nil {
		t.Fatal(err)
	}
	before := sqliteTotalChanges(t, s)
	duplicate := &models.Device{DeviceID: "dev_duplicate", PDID: "pdid_duplicate", CurrentMAC: owner.CurrentMAC,
		FirstSeen: now, LastSeen: now}
	err = s.SaveDevice(duplicate)
	var conflict *MACOwnershipConflict
	if !errors.As(err, &conflict) || conflict.OwnerPDID != owner.PDID {
		t.Fatalf("expected ownership conflict, got %v", err)
	}
	if after := sqliteTotalChanges(t, s); after != before {
		t.Fatalf("MAC conflict changed SQLite: before=%d after=%d", before, after)
	}
	if info, err := os.Stat(path + "-wal"); err == nil && info.Size() != 0 {
		t.Fatalf("MAC conflict appended %d bytes to WAL", info.Size())
	}
	devices, err := s.LoadHydrate()
	if err != nil || len(devices) != 1 || devices[0].PDID != owner.PDID {
		t.Fatalf("ownership conflict left an orphan: devices=%+v err=%v", devices, err)
	}
}

func TestIPOwnershipTransfersOnceAndPreservesHistory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ip-owner.db")
	s, err := NewStorage(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	now := time.Now()
	first := &models.Device{DeviceID: "dev_first", PDID: "pdid_first", CurrentIP: "192.0.2.10",
		IPs: []string{"192.0.2.10"}, FirstSeen: now, LastSeen: now}
	second := &models.Device{DeviceID: "dev_second", PDID: "pdid_second", CurrentIP: "192.0.2.10",
		IPs: []string{"192.0.2.10"}, FirstSeen: now, LastSeen: now}
	if err := s.SaveDevice(first); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveDevice(second); err != nil {
		t.Fatal(err)
	}
	var owner string
	if err := s.db.QueryRow("SELECT pdid FROM device_ip_owners WHERE ip = ?", second.CurrentIP).Scan(&owner); err != nil || owner != second.PDID {
		t.Fatalf("IP owner=%q err=%v", owner, err)
	}
	var history int
	if err := s.db.QueryRow("SELECT COUNT(*) FROM device_ips WHERE ip = ?", second.CurrentIP).Scan(&history); err != nil || history != 2 {
		t.Fatalf("IP history count=%d err=%v", history, err)
	}
	if _, err := s.db.Exec("PRAGMA wal_checkpoint(TRUNCATE)"); err != nil {
		t.Fatal(err)
	}
	before := sqliteTotalChanges(t, s)
	if err := s.SaveDevice(second); err != nil {
		t.Fatal(err)
	}
	if after := sqliteTotalChanges(t, s); after != before {
		t.Fatalf("repeated IP ownership wrote SQLite: before=%d after=%d", before, after)
	}
	if info, err := os.Stat(path + "-wal"); err == nil && info.Size() != 0 {
		t.Fatalf("repeated IP ownership appended %d bytes to WAL", info.Size())
	}
}

func TestLegacyIPSchemaMigratesWithoutLosingAssociations(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy-ip.db")
	s, err := NewStorage(path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	device := &models.Device{DeviceID: "dev_legacy", PDID: "pdid_legacy", CurrentIP: "192.0.2.25",
		IPs: []string{"192.0.2.25"}, FirstSeen: now, LastSeen: now}
	if err := s.SaveDevice(device); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	statements := []string{
		"DROP INDEX IF EXISTS idx_ip_pdid",
		"DROP TABLE device_ip_owners",
		"ALTER TABLE device_ips RENAME TO device_ips_composite",
		"CREATE TABLE device_ips(pdid TEXT NOT NULL, ip TEXT PRIMARY KEY, FOREIGN KEY(pdid) REFERENCES devices(pdid) ON DELETE CASCADE)",
		"INSERT INTO device_ips(pdid, ip) SELECT pdid, ip FROM device_ips_composite",
		"DROP TABLE device_ips_composite",
	}
	for _, statement := range statements {
		if _, err := db.Exec(statement); err != nil {
			db.Close()
			t.Fatalf("legacy fixture %q: %v", statement, err)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	s, err = NewStorage(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var owner string
	if err := s.db.QueryRow("SELECT pdid FROM device_ip_owners WHERE ip = ?", device.CurrentIP).Scan(&owner); err != nil || owner != device.PDID {
		t.Fatalf("migrated owner=%q err=%v", owner, err)
	}
	var primaryKeyColumns int
	rows, err := s.db.Query("PRAGMA table_info(device_ips)")
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var cid, notNull, primaryKey int
		var name, columnType string
		var defaultValue interface{}
		if err := rows.Scan(&cid, &name, &columnType, &notNull, &defaultValue, &primaryKey); err != nil {
			t.Fatal(err)
		}
		if primaryKey > 0 {
			primaryKeyColumns++
		}
	}
	rows.Close()
	if primaryKeyColumns != 2 {
		t.Fatalf("device_ips primary key columns=%d", primaryKeyColumns)
	}
}

func sqliteTotalChanges(t *testing.T, s *Storage) int64 {
	t.Helper()
	var changes int64
	if err := s.db.QueryRow("SELECT total_changes()").Scan(&changes); err != nil {
		t.Fatal(err)
	}
	return changes
}

func TestReconcileZeroMACOrphanDuplicate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "reconcile-orphan.db")
	s, err := NewStorage(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	now := time.Now()
	owner := &models.Device{
		DeviceID: "dev_owner_reconcile", PDID: "pdid_owner_reconcile",
		CurrentMAC: "00:11:22:33:44:55", MACs: []string{"00:11:22:33:44:55"},
		Hostname: "owner", FirstSeen: now, LastSeen: now,
	}
	if err := s.SaveDevice(owner); err != nil {
		t.Fatal(err)
	}

	_, err = s.db.Exec(`
		INSERT INTO devices(device_id, pdid, current_mac, hostname, first_seen, last_seen)
		VALUES (?, ?, ?, ?, ?, ?)
	`, "dev_orphan_reconcile", "pdid_orphan_reconcile", owner.CurrentMAC, "orphan-host", now, now)
	if err != nil {
		t.Fatal(err)
	}

	repaired, err := s.ReconcileZeroMACOrphanDuplicates()
	if err != nil {
		t.Fatal(err)
	}
	if repaired != 1 {
		t.Fatalf("expected 1 repaired orphan, got %d", repaired)
	}

	var redirect string
	if err := s.db.QueryRow(`SELECT new_pdid FROM pdid_redirects WHERE old_pdid = ?`, "pdid_orphan_reconcile").Scan(&redirect); err != nil || redirect != owner.PDID {
		t.Fatalf("redirect=%q err=%v", redirect, err)
	}

	devices, err := s.LoadHydrate()
	if err != nil {
		t.Fatal(err)
	}
	if len(devices) != 1 || devices[0].PDID != owner.PDID {
		t.Fatalf("orphan still hydrated: %+v", devices)
	}
}

func TestReconcileDoesNotAutoMergeVerifiedAliasOrphan(t *testing.T) {
	path := filepath.Join(t.TempDir(), "reconcile-ambiguous.db")
	s, err := NewStorage(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	now := time.Now()
	owner := &models.Device{
		DeviceID: "dev_owner_ambiguous", PDID: "pdid_owner_ambiguous",
		CurrentMAC: "00:11:22:33:44:77", MACs: []string{"00:11:22:33:44:77"},
		FirstSeen: now, LastSeen: now,
	}
	if err := s.SaveDevice(owner); err != nil {
		t.Fatal(err)
	}

	_, err = s.db.Exec(`
		INSERT INTO devices(device_id, pdid, current_mac, hostname, first_seen, last_seen)
		VALUES (?, ?, ?, ?, ?, ?)
	`, "dev_orphan_ambiguous", "pdid_orphan_ambiguous", owner.CurrentMAC, "ambiguous-host", now, now)
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.db.Exec(`
		INSERT INTO identity_aliases(device_id, alias_type, value_hash, source, confidence, verified, first_seen, last_seen)
		VALUES (?, 'auth_alias', 'verified-different-device', 'test', 1.0, 1, ?, ?)
	`, "dev_orphan_ambiguous", now, now)
	if err != nil {
		t.Fatal(err)
	}

	repaired, err := s.ReconcileZeroMACOrphanDuplicates()
	if err != nil {
		t.Fatal(err)
	}
	if repaired != 0 {
		t.Fatalf("ambiguous orphan was auto-merged")
	}

	var count int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM devices WHERE pdid = ?`, "pdid_orphan_ambiguous").Scan(&count); err != nil || count != 1 {
		t.Fatalf("ambiguous orphan missing count=%d err=%v", count, err)
	}
}
