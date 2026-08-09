// Package storage provides CGO-free SQLite persistence for DIS device state.
//
// File:    apps/discovery-service/internal/storage/sqlite.go
// Version: 3.2 (Added Enrichment State Persistence)
package storage

import (
    "database/sql"
	"encoding/json"
    "fmt"
    "log/slog"
    "os"
    "path/filepath"
    "sync"
    "time"

    "github.com/user/lias-dis/apps/discovery-service/internal/inventory"
    "github.com/user/lias-dis/shared/models"
    _ "modernc.org/sqlite"
)

type PendingEventRecord struct {
    PDID          string
    EventType     string
    Payload       []byte
    FirstSeen     time.Time
    LastSeen      time.Time
    Confirmations int
    Sources       string
}

type Storage struct {
    mu     sync.Mutex
    dbPath string
    db     *sql.DB
	stopCh   chan struct{}
	stopOnce sync.Once
}

func NewStorage(dbPath string) (*Storage, error) {
    if dbPath == "" {
        dbPath = "/var/lib/dis/state.db"
    }

    if err := os.MkdirAll(filepath.Dir(dbPath), 0755); err != nil {
        return nil, fmt.Errorf("failed to create database directory: %w", err)
    }

	dsn := fmt.Sprintf("file:%s?_pragma=busy_timeout(5000)&_pragma=foreign_keys(ON)&_pragma=synchronous(NORMAL)&_pragma=journal_mode(WAL)", dbPath)
    db, err := sql.Open("sqlite", dsn)
    if err != nil {
        return nil, fmt.Errorf("failed to open sqlite database: %w", err)
    }

	// DIS is deliberately a low-write service. A single SQLite connection
	// prevents database/sql from creating competing writers and also makes
	// per-connection PRAGMA behavior deterministic.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to initialize sqlite database: %w", err)
	}

    s := &Storage{
        dbPath: dbPath,
        db:     db,
		stopCh: make(chan struct{}),
    }

    if err := s.initSchema(); err != nil {
        db.Close()
        return nil, err
    }

    if _, err := db.Exec("PRAGMA wal_checkpoint(TRUNCATE);"); err != nil {
        slog.Warn("Failed to truncate WAL on startup", "error", err)
    }

    if err := s.migrateV1PDIDs(); err != nil {
        slog.Warn("v1 to v2 PDID migration encountered an error", "error", err)
    }

    go s.pendingEventsRetentionLoop()

    slog.Info("DIS SQLite storage engine initialized", "path", dbPath)
    return s, nil
}

func (s *Storage) pendingEventsRetentionLoop() {
    ticker := time.NewTicker(1 * time.Hour)
    defer ticker.Stop()

    for {
		select {
		case <-s.stopCh:
			return
		case <-ticker.C:
        s.mu.Lock()
        _, err := s.db.Exec("DELETE FROM pending_events WHERE last_seen < datetime('now', '-1 hour')")
        s.mu.Unlock()
        if err != nil {
            slog.Warn("Failed to clean up old pending events", "error", err)
        }
		}
    }
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
        online INTEGER NOT NULL DEFAULT 1,
        last_enriched_at DATETIME,
        last_nmap_scan_at DATETIME,
        nmap_attempt_count INTEGER NOT NULL DEFAULT 0,
        is_fully_identified INTEGER NOT NULL DEFAULT 0,
        services_json TEXT NOT NULL DEFAULT '[]',
        tags_json TEXT NOT NULL DEFAULT '[]',
        user_id TEXT NOT NULL DEFAULT '',
        source_info_json TEXT NOT NULL DEFAULT '{}',
        pending_online_obs_json TEXT NOT NULL DEFAULT '[]',
        is_tentative INTEGER NOT NULL DEFAULT 0
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
    CREATE INDEX IF NOT EXISTS idx_pending_pdid ON pending_events(pdid, event_type);
    `

    _, err := s.db.Exec(query)
    if err != nil {
        return fmt.Errorf("failed to execute DIS schema initialization: %w", err)
    }

    _, _ = s.db.Exec("ALTER TABLE devices ADD COLUMN identity_tier TEXT NOT NULL DEFAULT 'tentative'")
    _, _ = s.db.Exec("ALTER TABLE devices ADD COLUMN identity_anchor TEXT NOT NULL DEFAULT ''")
    _, _ = s.db.Exec("ALTER TABLE devices ADD COLUMN canonical_hostname TEXT NOT NULL DEFAULT ''")
    _, _ = s.db.Exec("ALTER TABLE devices ADD COLUMN current_mac TEXT NOT NULL DEFAULT ''")
    _, _ = s.db.Exec("ALTER TABLE devices ADD COLUMN current_ip TEXT NOT NULL DEFAULT ''")
    
    // P1-FIX: Add enrichment tracking columns
    _, _ = s.db.Exec("ALTER TABLE devices ADD COLUMN last_enriched_at DATETIME")
    _, _ = s.db.Exec("ALTER TABLE devices ADD COLUMN last_nmap_scan_at DATETIME")
    _, _ = s.db.Exec("ALTER TABLE devices ADD COLUMN nmap_attempt_count INTEGER NOT NULL DEFAULT 0")
    _, _ = s.db.Exec("ALTER TABLE devices ADD COLUMN is_fully_identified INTEGER NOT NULL DEFAULT 0")

	_, _ = s.db.Exec("ALTER TABLE devices ADD COLUMN services_json TEXT NOT NULL DEFAULT '[]'")
	_, _ = s.db.Exec("ALTER TABLE devices ADD COLUMN tags_json TEXT NOT NULL DEFAULT '[]'")
	_, _ = s.db.Exec("ALTER TABLE devices ADD COLUMN user_id TEXT NOT NULL DEFAULT ''")
	_, _ = s.db.Exec("ALTER TABLE devices ADD COLUMN source_info_json TEXT NOT NULL DEFAULT '{}'")
	_, _ = s.db.Exec("ALTER TABLE devices ADD COLUMN pending_online_obs_json TEXT NOT NULL DEFAULT '[]'")
	_, _ = s.db.Exec("ALTER TABLE devices ADD COLUMN is_tentative INTEGER NOT NULL DEFAULT 0")

	// Older releases created only a non-unique index while SavePendingEvent
	// used ON CONFLICT(pdid,event_type). Collapse legacy duplicates first,
	// then install the unique constraint required by that upsert.
	if _, err := s.db.Exec(`
        DELETE FROM pending_events
        WHERE id NOT IN (
            SELECT MAX(id) FROM pending_events GROUP BY pdid, event_type
        )
    `); err != nil {
		return fmt.Errorf("failed to deduplicate pending events: %w", err)
	}
	if _, err := s.db.Exec(`
        CREATE UNIQUE INDEX IF NOT EXISTS uq_pending_pdid_event_type
        ON pending_events(pdid, event_type)
    `); err != nil {
		return fmt.Errorf("failed to create pending-event uniqueness constraint: %w", err)
	}

    return nil
}

func (s *Storage) migrateV1PDIDs() error {
    s.mu.Lock()
    defer s.mu.Unlock()

    var needsMigration int
    err := s.db.QueryRow(
        "SELECT COUNT(*) FROM devices WHERE pdid NOT LIKE 'pdid_bia_%' AND pdid NOT LIKE 'pdid_l7_%' AND pdid NOT LIKE 'pdid_tent_%'",
    ).Scan(&needsMigration)
    if err != nil || needsMigration == 0 {
        return nil
    }

    slog.Info("Starting v1→v2 PDID migration", "v1_devices", needsMigration)

    rows, err := s.db.Query("SELECT pdid, current_mac, hostname, vendor FROM devices WHERE pdid NOT LIKE 'pdid_bia_%' AND pdid NOT LIKE 'pdid_l7_%' AND pdid NOT LIKE 'pdid_tent_%'")
    if err != nil {
        return err
    }
    type migrationEntry struct {
        OldPDID, NewPDID, Tier, Anchor, CanonicalHost string
    }
    var migrations []migrationEntry

    for rows.Next() {
        var oldPDID, mac, hostname, vendor string
        if err := rows.Scan(&oldPDID, &mac, &hostname, &vendor); err != nil {
            continue
        }

        canonicalHost := inventory.CanonicalizeHostname(hostname)
        tier, anchor := inventory.DeriveTierAndAnchor(mac, canonicalHost, vendor)
        newPDID := inventory.GeneratePDID(tier, anchor)

        migrations = append(migrations, migrationEntry{
            OldPDID: oldPDID, NewPDID: newPDID,
            Tier: string(tier), Anchor: anchor, CanonicalHost: canonicalHost,
        })
    }
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}

    for _, m := range migrations {
        tx, _ := s.db.Begin()
        _, _ = tx.Exec(`INSERT INTO devices (pdid, identity_tier, identity_anchor, canonical_hostname, current_mac, current_ip, hostname, friendly_name, manufacturer, vendor, model, device_type, confidence, first_seen, last_seen, online)
                        SELECT ?, ?, ?, ?, current_mac, current_ip, hostname, friendly_name, manufacturer, vendor, model, device_type, confidence, first_seen, last_seen, online FROM devices WHERE pdid = ?`,
            m.NewPDID, m.Tier, m.Anchor, m.CanonicalHost, m.OldPDID)
        _, _ = tx.Exec("UPDATE device_macs SET pdid = ? WHERE pdid = ?", m.NewPDID, m.OldPDID)
        _, _ = tx.Exec("UPDATE device_ips SET pdid = ? WHERE pdid = ?", m.NewPDID, m.OldPDID)
        _, _ = tx.Exec("DELETE FROM devices WHERE pdid = ?", m.OldPDID)
        _ = tx.Commit()
    }

    _, _ = s.db.Exec("DELETE FROM hostname_owners")
	ownerRows, err := s.db.Query("SELECT canonical_hostname, pdid FROM devices WHERE canonical_hostname != ''")
	if err != nil {
		return err
	}
	type hostnameOwner struct{ host, pdid string }
	var rebuiltOwners []hostnameOwner
    for ownerRows.Next() {
        var host, pdid string
        if err := ownerRows.Scan(&host, &pdid); err == nil && host != "" {
			rebuiltOwners = append(rebuiltOwners, hostnameOwner{host: host, pdid: pdid})
		}
	}
	if err := ownerRows.Err(); err != nil {
		ownerRows.Close()
		return err
	}
	if err := ownerRows.Close(); err != nil {
		return err
	}
	for _, owner := range rebuiltOwners {
		if _, err := s.db.Exec("INSERT OR REPLACE INTO hostname_owners (canonical_hostname, pdid, acquired_at) VALUES (?, ?, ?)", owner.host, owner.pdid, time.Now()); err != nil {
			return err
        }
    }

    slog.Info("v1→v2 PDID migration complete", "migrated", len(migrations))
    return nil
}

func (s *Storage) LoadHydrate() ([]models.Device, error) {
    s.mu.Lock()
    defer s.mu.Unlock()

    rows, err := s.db.Query(`
        SELECT pdid, identity_tier, identity_anchor, canonical_hostname, 
               current_mac, current_ip, hostname, friendly_name, manufacturer, 
               vendor, model, device_type, confidence, first_seen, last_seen, online,
               last_enriched_at, last_nmap_scan_at, nmap_attempt_count, is_fully_identified,
               services_json, tags_json, user_id, source_info_json,
               pending_online_obs_json, is_tentative
        FROM devices
    `)
    if err != nil {
        return nil, fmt.Errorf("failed to query devices from DB: %w", err)
    }
    deviceMap := make(map[string]*models.Device)

    for rows.Next() {
        var d models.Device
        var onlineInt int
        var firstSeen, lastSeen time.Time
        var lastEnrichedAt, lastNmapScanAt sql.NullTime
		var nmapAttemptCount, isFullyIdentified, isTentative int
		var servicesJSON, tagsJSON, sourceInfoJSON, pendingOnlineJSON string

        err := rows.Scan(
            &d.PDID, &d.IdentityTier, &d.IdentityAnchor, &d.CanonicalHostname,
            &d.CurrentMAC, &d.CurrentIP, &d.Hostname, &d.FriendlyName, &d.Manufacturer,
            &d.Vendor, &d.Model, &d.DeviceType, &d.Confidence, &firstSeen, &lastSeen, &onlineInt,
            &lastEnrichedAt, &lastNmapScanAt, &nmapAttemptCount, &isFullyIdentified,
			&servicesJSON, &tagsJSON, &d.UserID, &sourceInfoJSON,
			&pendingOnlineJSON, &isTentative,
        )
        if err != nil {
            continue
        }

        d.FirstSeen = firstSeen
        d.LastSeen = lastSeen
        d.Online = onlineInt == 1
        if lastEnrichedAt.Valid {
            d.LastEnrichedAt = lastEnrichedAt.Time
        }
        if lastNmapScanAt.Valid {
            d.LastNmapScanAt = lastNmapScanAt.Time
        }
        d.NmapAttemptCount = nmapAttemptCount
        d.IsFullyIdentified = isFullyIdentified == 1
		d.IsTentative = isTentative == 1
        
        d.MACs = []string{}
        d.IPs = []string{}
        d.SourceInfo = make(map[string]models.SourceMeta)
		_ = json.Unmarshal([]byte(servicesJSON), &d.Services)
		_ = json.Unmarshal([]byte(tagsJSON), &d.Tags)
		_ = json.Unmarshal([]byte(sourceInfoJSON), &d.SourceInfo)
		_ = json.Unmarshal([]byte(pendingOnlineJSON), &d.PendingOnlineObs)

        devCopy := d
        deviceMap[d.PDID] = &devCopy
    }
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, fmt.Errorf("failed while reading devices from DB: %w", err)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}

    macRows, err := s.db.Query("SELECT pdid, mac FROM device_macs")
    if err == nil {
        for macRows.Next() {
            var pdid, mac string
            if macRows.Scan(&pdid, &mac) == nil {
                if dev, ok := deviceMap[pdid]; ok {
                    dev.MACs = append(dev.MACs, mac)
                }
            }
        }
		macRows.Close()
    }

    ipRows, err := s.db.Query("SELECT pdid, ip FROM device_ips")
    if err == nil {
        for ipRows.Next() {
            var pdid, ip string
            if ipRows.Scan(&pdid, &ip) == nil {
                if dev, ok := deviceMap[pdid]; ok {
                    dev.IPs = append(dev.IPs, ip)
                }
            }
        }
		ipRows.Close()
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
    s.mu.Lock()
    defer s.mu.Unlock()

    tx, err := s.db.Begin()
    if err != nil {
        return err
    }
    defer func() { _ = tx.Rollback() }()

    if err := s.saveDeviceTx(tx, d); err != nil {
        return err
    }

    return tx.Commit()
}

func (s *Storage) SaveDevicesBatch(devs []*models.Device) error {
    s.mu.Lock()
    defer s.mu.Unlock()

    tx, err := s.db.Begin()
    if err != nil {
        return err
    }
    defer func() { _ = tx.Rollback() }()

	for _, d := range devs {
        if err := s.saveDeviceTx(tx, d); err != nil {
			return err
        }
    }

    return tx.Commit()
}

func (s *Storage) saveDeviceTx(tx *sql.Tx, d *models.Device) error {
    if d == nil || d.PDID == "" {
        return nil
    }

    onlineInt := 0
    if d.Online {
        onlineInt = 1
    }

    isFullyIdentifiedInt := 0
    if d.IsFullyIdentified {
        isFullyIdentifiedInt = 1
    }

	isTentativeInt := 0
	if d.IsTentative {
		isTentativeInt = 1
	}

	servicesJSON, err := json.Marshal(d.Services)
	if err != nil {
		return fmt.Errorf("failed to encode services for %s: %w", d.PDID, err)
	}
	tagsJSON, err := json.Marshal(d.Tags)
	if err != nil {
		return fmt.Errorf("failed to encode tags for %s: %w", d.PDID, err)
	}
	sourceInfoJSON, err := json.Marshal(d.SourceInfo)
	if err != nil {
		return fmt.Errorf("failed to encode source metadata for %s: %w", d.PDID, err)
	}
	pendingOnlineJSON, err := json.Marshal(d.PendingOnlineObs)
	if err != nil {
		return fmt.Errorf("failed to encode pending observations for %s: %w", d.PDID, err)
	}

	_, err = tx.Exec(`
        INSERT INTO devices (pdid, identity_tier, identity_anchor, canonical_hostname, 
            current_mac, current_ip, hostname, friendly_name, manufacturer, vendor, 
            model, device_type, confidence, first_seen, last_seen, online,
            last_enriched_at, last_nmap_scan_at, nmap_attempt_count, is_fully_identified,
            services_json, tags_json, user_id, source_info_json,
            pending_online_obs_json, is_tentative)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
            online=excluded.online,
            last_enriched_at=excluded.last_enriched_at,
            last_nmap_scan_at=excluded.last_nmap_scan_at,
            nmap_attempt_count=excluded.nmap_attempt_count,
            is_fully_identified=excluded.is_fully_identified,
            services_json=excluded.services_json,
            tags_json=excluded.tags_json,
            user_id=excluded.user_id,
            source_info_json=excluded.source_info_json,
            pending_online_obs_json=excluded.pending_online_obs_json,
            is_tentative=excluded.is_tentative
    `, d.PDID, string(d.IdentityTier), d.IdentityAnchor, d.CanonicalHostname, d.CurrentMAC, d.CurrentIP, d.Hostname, d.FriendlyName, d.Manufacturer, d.Vendor, d.Model, d.DeviceType, d.Confidence, d.FirstSeen, d.LastSeen, onlineInt, d.LastEnrichedAt, d.LastNmapScanAt, d.NmapAttemptCount, isFullyIdentifiedInt, string(servicesJSON), string(tagsJSON), d.UserID, string(sourceInfoJSON), string(pendingOnlineJSON), isTentativeInt)

    if err != nil {
        return fmt.Errorf("failed to upsert device %s: %w", d.PDID, err)
    }

    existingMACs := make(map[string]bool)
    macRows, err := tx.Query("SELECT mac FROM device_macs WHERE pdid = ?", d.PDID)
    if err == nil {
        for macRows.Next() {
            var mac string
            macRows.Scan(&mac)
            existingMACs[mac] = true
        }
        macRows.Close()
    }

    desiredMACs := make(map[string]bool)
    for _, mac := range d.MACs {
        if mac != "" {
            desiredMACs[mac] = true
        }
    }

    for mac := range desiredMACs {
        if !existingMACs[mac] {
            _, _ = tx.Exec("INSERT OR IGNORE INTO device_macs (pdid, mac) VALUES (?, ?)", d.PDID, mac)
        }
    }
    for mac := range existingMACs {
        if !desiredMACs[mac] {
            _, _ = tx.Exec("DELETE FROM device_macs WHERE pdid = ? AND mac = ?", d.PDID, mac)
        }
    }

    existingIPs := make(map[string]bool)
    ipRows, err := tx.Query("SELECT ip FROM device_ips WHERE pdid = ?", d.PDID)
    if err == nil {
        for ipRows.Next() {
            var ip string
            ipRows.Scan(&ip)
            existingIPs[ip] = true
        }
        ipRows.Close()
    }

    desiredIPs := make(map[string]bool)
    for _, ip := range d.IPs {
        if ip != "" {
            desiredIPs[ip] = true
        }
    }

    for ip := range desiredIPs {
        if !existingIPs[ip] {
            _, _ = tx.Exec("INSERT OR IGNORE INTO device_ips (pdid, ip) VALUES (?, ?)", d.PDID, ip)
        }
    }
    for ip := range existingIPs {
        if !desiredIPs[ip] {
            _, _ = tx.Exec("DELETE FROM device_ips WHERE pdid = ? AND ip = ?", d.PDID, ip)
        }
    }

    return nil
}

func (s *Storage) ReplaceDevicePDID(oldPDID, newPDID string, d *models.Device) error {
    s.mu.Lock()
    defer s.mu.Unlock()

    tx, err := s.db.Begin()
    if err != nil {
        return err
    }
    defer func() { _ = tx.Rollback() }()

    if err := s.saveDeviceTx(tx, d); err != nil {
        return err
    }

    _, _ = tx.Exec("UPDATE device_macs SET pdid = ? WHERE pdid = ?", newPDID, oldPDID)
    _, _ = tx.Exec("UPDATE device_ips SET pdid = ? WHERE pdid = ?", newPDID, oldPDID)
    _, _ = tx.Exec("UPDATE hostname_owners SET pdid = ? WHERE pdid = ?", newPDID, oldPDID)
    _, _ = tx.Exec("UPDATE pending_events SET pdid = ? WHERE pdid = ?", newPDID, oldPDID)
    
    _, err = tx.Exec("DELETE FROM devices WHERE pdid = ?", oldPDID)
    if err != nil {
        return err
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

func (s *Storage) SavePendingEvent(pdid, eventType string, payload []byte, firstSeen, lastSeen time.Time, confirmations int, sources string) error {
    s.mu.Lock()
    defer s.mu.Unlock()

    payloadStr := string(payload)
    _, err := s.db.Exec(`
        INSERT INTO pending_events (pdid, event_type, payload, first_seen, last_seen, confirmations, sources)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(pdid, event_type) DO UPDATE SET
            payload=excluded.payload,
            last_seen=excluded.last_seen,
            confirmations=excluded.confirmations,
            sources=excluded.sources
    `, pdid, eventType, payloadStr, firstSeen, lastSeen, confirmations, sources)

    return err
}

func (s *Storage) DeletePendingEventsBatch(records []PendingEventRecord) error {
    s.mu.Lock()
    defer s.mu.Unlock()

    tx, err := s.db.Begin()
    if err != nil {
        return err
    }
    defer func() { _ = tx.Rollback() }()

    for _, r := range records {
        if _, err := tx.Exec("DELETE FROM pending_events WHERE pdid = ? AND event_type = ?", r.PDID, r.EventType); err != nil {
            return err
        }
    }

    return tx.Commit()
}

func (s *Storage) DeletePendingEvent(pdid, eventType string) error {
    s.mu.Lock()
    defer s.mu.Unlock()

    _, err := s.db.Exec("DELETE FROM pending_events WHERE pdid = ? AND event_type = ?", pdid, eventType)
    return err
}

func (s *Storage) LoadPendingEvents() ([]PendingEventRecord, error) {
    s.mu.Lock()
    defer s.mu.Unlock()

    rows, err := s.db.Query("SELECT pdid, event_type, payload, first_seen, last_seen, confirmations, sources FROM pending_events")
    if err != nil {
        return nil, err
    }
    defer rows.Close()

    var records []PendingEventRecord
    for rows.Next() {
        var r PendingEventRecord
        if err := rows.Scan(&r.PDID, &r.EventType, &r.Payload, &r.FirstSeen, &r.LastSeen, &r.Confirmations, &r.Sources); err == nil {
            records = append(records, r)
        }
    }
    return records, nil
}

func (s *Storage) Close() error {
	s.stopOnce.Do(func() { close(s.stopCh) })
    s.mu.Lock()
    defer s.mu.Unlock()
    if s.db != nil {
        return s.db.Close()
    }
    return nil
}
