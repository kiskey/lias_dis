// Package storage provides CGO-free SQLite persistence for DIS device state.
//
// File:    apps/discovery-service/internal/storage/sqlite.go
// Version: 2.2
package storage

import (
	"database/sql"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/user/lias-dis/shared/models"
	_ "modernc.org/sqlite"
)

type Storage struct {
	mu     sync.Mutex
	dbPath string
	db     *sql.DB
}

func NewStorage(dbPath string) (*Storage, error) {
	if dbPath == "" {
		dbPath = "/var/lib/dis/state.db"
	}

	if err := os.MkdirAll(filepath.Dir(dbPath), 0755); err != nil {
		return nil, fmt.Errorf("failed to create database directory: %w", err)
	}

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open sqlite database: %w", err)
	}

	if _, err := db.Exec("PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;"); err != nil {
		slog.Warn("Failed to set PRAGMAs on DIS database", "error", err)
	}

	s := &Storage{
		dbPath: dbPath,
		db:     db,
	}

	if err := s.initSchema(); err != nil {
		db.Close()
		return nil, err
	}

	slog.Info("DIS SQLite storage engine initialized", "path", dbPath)
	return s, nil
}

func (s *Storage) initSchema() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	query := `
	CREATE TABLE IF NOT EXISTS devices (
		pdid TEXT PRIMARY KEY,
		identity_tier TEXT NOT NULL DEFAULT 'tentative',
		identity_anchor TEXT NOT NULL DEFAULT '',
		canonical_hostname TEXT NOT NULL DEFAULT '',
		current_mac TEXT NOT NULL DEFAULT '',
		current_ip TEXT NOT NULL DEFAULT '',
		hostname TEXT NOT NULL DEFAULT '',
		friendly_name TEXT NOT NULL DEFAULT '',
		manufacturer TEXT NOT NULL DEFAULT '',
		vendor TEXT NOT NULL DEFAULT '',
		model TEXT NOT NULL DEFAULT '',
		device_type TEXT NOT NULL DEFAULT '',
		confidence REAL NOT NULL DEFAULT 0.0,
		first_seen DATETIME NOT NULL,
		last_seen DATETIME NOT NULL,
		online INTEGER NOT NULL DEFAULT 1
	);

	CREATE TABLE IF NOT EXISTS device_macs (
		pdid TEXT NOT NULL,
		mac TEXT PRIMARY KEY,
		FOREIGN KEY(pdid) REFERENCES devices(pdid) ON DELETE CASCADE
	);

	CREATE TABLE IF NOT EXISTS device_ips (
		pdid TEXT NOT NULL,
		ip TEXT PRIMARY KEY,
		FOREIGN KEY(pdid) REFERENCES devices(pdid) ON DELETE CASCADE
	);

	CREATE TABLE IF NOT EXISTS hostname_owners (
		canonical_hostname TEXT PRIMARY KEY,
		pdid TEXT NOT NULL,
		acquired_at DATETIME NOT NULL,
		FOREIGN KEY(pdid) REFERENCES devices(pdid) ON DELETE CASCADE
	);

	CREATE TABLE IF NOT EXISTS pending_events (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		pdid TEXT NOT NULL,
		event_type TEXT NOT NULL,
		payload TEXT NOT NULL,
		first_seen DATETIME NOT NULL,
		last_seen DATETIME NOT NULL,
		confirmations INTEGER NOT NULL DEFAULT 1,
		sources TEXT NOT NULL DEFAULT ''
	);

	CREATE INDEX IF NOT EXISTS idx_mac_pdid ON device_macs(pdid);
	CREATE INDEX IF NOT EXISTS idx_ip_pdid ON device_ips(pdid);
	`

	_, err := s.db.Exec(query)
	if err != nil {
		return fmt.Errorf("failed to execute DIS schema initialization: %w", err)
	}

	// Migration column additions
	_, _ = s.db.Exec("ALTER TABLE devices ADD COLUMN identity_tier TEXT NOT NULL DEFAULT 'tentative'")
	_, _ = s.db.Exec("ALTER TABLE devices ADD COLUMN identity_anchor TEXT NOT NULL DEFAULT ''")
	_, _ = s.db.Exec("ALTER TABLE devices ADD COLUMN canonical_hostname TEXT NOT NULL DEFAULT ''")
	_, _ = s.db.Exec("ALTER TABLE devices ADD COLUMN current_mac TEXT NOT NULL DEFAULT ''")
	_, _ = s.db.Exec("ALTER TABLE devices ADD COLUMN current_ip TEXT NOT NULL DEFAULT ''")

	return nil
}

func (s *Storage) LoadHydrate() ([]models.Device, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	rows, err := s.db.Query(`
		SELECT pdid, identity_tier, identity_anchor, canonical_hostname, current_mac, current_ip, hostname, friendly_name, manufacturer, vendor, model, device_type, confidence, first_seen, last_seen, online
		FROM devices
	`)
	if err != nil {
		return nil, fmt.Errorf("failed to query devices from DB: %w", err)
	}
	defer rows.Close()

	deviceMap := make(map[string]*models.Device)

	for rows.Next() {
		var d models.Device
		var onlineInt int
		var firstSeen, lastSeen time.Time

		err := rows.Scan(
			&d.PDID, &d.IdentityTier, &d.IdentityAnchor, &d.CanonicalHostname,
			&d.CurrentMAC, &d.CurrentIP, &d.Hostname, &d.FriendlyName, &d.Manufacturer,
			&d.Vendor, &d.Model, &d.DeviceType, &d.Confidence, &firstSeen, &lastSeen, &onlineInt,
		)
		if err != nil {
			continue
		}

		d.FirstSeen = firstSeen
		d.LastSeen = lastSeen
		d.Online = onlineInt == 1
		d.MACs = []string{}
		d.IPs = []string{}
		d.SourceInfo = make(map[string]models.SourceMeta)

		devCopy := d
		deviceMap[d.PDID] = &devCopy
	}

	devices := make([]models.Device, 0, len(deviceMap))
	for _, dev := range deviceMap {
		devices = append(devices, *dev)
	}

	slog.Info("Successfully hydrated DIS device inventory from SQLite", "count", len(devices))
	return devices, nil
}

func (s *Storage) LoadHostnameOwners() (map[string]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	rows, err := s.db.Query("SELECT canonical_hostname, pdid FROM hostname_owners")
	if err != nil {
		return nil, fmt.Errorf("failed to query hostname owners from DB: %w", err)
	}
	defer rows.Close()

	owners := make(map[string]string)
	for rows.Next() {
		var host, pdid string
		if err := rows.Scan(&host, &pdid); err == nil && host != "" {
			owners[host] = pdid
		}
	}
	return owners, nil
}

func (s *Storage) SaveHostnameOwner(canonicalHost, pdid string) error {
	if canonicalHost == "" || pdid == "" {
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.Exec(`
		INSERT INTO hostname_owners (canonical_hostname, pdid, acquired_at)
		VALUES (?, ?, ?)
		ON CONFLICT(canonical_hostname) DO UPDATE SET
			pdid=excluded.pdid,
			acquired_at=excluded.acquired_at
	`, canonicalHost, pdid, time.Now())

	return err
}

func (s *Storage) DeleteHostnameOwner(canonicalHost string) error {
	if canonicalHost == "" {
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.Exec("DELETE FROM hostname_owners WHERE canonical_hostname = ?", canonicalHost)
	return err
}

func (s *Storage) SaveDevice(d *models.Device) error {
	if d == nil || d.PDID == "" {
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	onlineInt := 0
	if d.Online {
		onlineInt = 1
	}

	_, err = tx.Exec(`
		INSERT INTO devices (pdid, identity_tier, identity_anchor, canonical_hostname, current_mac, current_ip, hostname, friendly_name, manufacturer, vendor, model, device_type, confidence, first_seen, last_seen, online)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(pdid) DO UPDATE SET
			identity_tier=excluded.identity_tier,
			identity_anchor=excluded.identity_anchor,
			canonical_hostname=excluded.canonical_hostname,
			current_mac=excluded.current_mac,
			current_ip=excluded.current_ip,
			hostname=excluded.hostname,
			friendly_name=excluded.friendly_name,
			manufacturer=excluded.manufacturer,
			vendor=excluded.vendor,
			model=excluded.model,
			device_type=excluded.device_type,
			confidence=excluded.confidence,
			last_seen=excluded.last_seen,
			online=excluded.online
	`, d.PDID, string(d.IdentityTier), d.IdentityAnchor, d.CanonicalHostname, d.CurrentMAC, d.CurrentIP, d.Hostname, d.FriendlyName, d.Manufacturer, d.Vendor, d.Model, d.DeviceType, d.Confidence, d.FirstSeen, d.LastSeen, onlineInt)

	if err != nil {
		return fmt.Errorf("failed to upsert device %s: %w", d.PDID, err)
	}

	return tx.Commit()
}

func (s *Storage) DeleteDevice(pdid string) error {
	if pdid == "" {
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	_, _ = tx.Exec("DELETE FROM device_macs WHERE pdid = ?", pdid)
	_, _ = tx.Exec("DELETE FROM device_ips WHERE pdid = ?", pdid)
	_, _ = tx.Exec("DELETE FROM hostname_owners WHERE pdid = ?", pdid)
	_, _ = tx.Exec("DELETE FROM devices WHERE pdid = ?", pdid)

	return tx.Commit()
}

func (s *Storage) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}
