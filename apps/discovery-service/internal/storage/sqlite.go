// Package storage provides CGO-free SQLite persistence for DIS device state.
//
// File:    apps/discovery-service/internal/storage/sqlite.go
// Version: 3.0 (Added Pending Events TTL Purge)
package storage

import (
    "database/sql"
    "fmt"
    "log/slog"
    "os"
    "path/filepath"
    "strings"
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
}

func NewStorage(dbPath string) (*Storage, error) {
    if dbPath == "" {
        dbPath = "/var/lib/dis/state.db"
    }

    if err := os.MkdirAll(filepath.Dir(dbPath), 0755); err != nil {
        return nil, fmt.Errorf("failed to create database directory: %w", err)
    }

    dsn := fmt.Sprintf("file:%s?_pragma=busy_timeout(5000)&_pragma=synchronous(NORMAL)&_pragma=journal_mode(WAL)", dbPath)
    db, err := sql.Open("sqlite", dsn)
    if err != nil {
        return nil, fmt.Errorf("failed to open sqlite database: %w", err)
    }

    s := &Storage{
        dbPath: dbPath,
        db:     db,
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

    // Technical Debt Fix: Start pending events retention loop
    go s.pendingEventsRetentionLoop()

    slog.Info("DIS SQLite storage engine initialized", "path", dbPath)
    return s, nil
}

func (s *Storage) pendingEventsRetentionLoop() {
    ticker := time.NewTicker(1 * time.Hour)
    defer ticker.Stop()

    for {
        s.mu.Lock()
        _, err := s.db.Exec("DELETE FROM pending_events WHERE last_seen < datetime('now', '-1 hour')")
        s.mu.Unlock()

        if err != nil {
            slog.Warn("Failed to clean up old pending events", "error", err)
        }

        <-ticker.C
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
    defer rows.Close()

    type migrationEntry struct {
        OldPDID, NewPDID, Tier, Anchor, CanonicalHost string
    }
    var migrations []migrationEntry

    for rows.Next() {
        var oldPDID, mac, hostname, vendor string
        if err := rows.Scan(&oldPDID, &mac, &hostname, &vendor); err != nil {
            continue
        }

        canonicalHost := canonicalizeHostnameLocal(hostname)
        tier, anchor := inventory.DeriveTierAndAnchor(mac, canonicalHost, vendor)
        newPDID := inventory.GeneratePDID(tier, anchor)

        migrations = append(migrations, migrationEntry{
            OldPDID: oldPDID, NewPDID: newPDID,
            Tier: string(tier), Anchor: anchor, CanonicalHost: canonicalHost,
        })
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
    ownerRows, _ := s.db.Query("SELECT canonical_hostname, pdid FROM devices WHERE canonical_hostname != ''")
    defer ownerRows.Close()
    for ownerRows.Next() {
        var host, pdid string
        if err := ownerRows.Scan(&host, &pdid); err == nil && host != "" {
            _, _ = s.db.Exec("INSERT OR REPLACE INTO hostname_owners (canonical_hostname, pdid, acquired_at) VALUES (?, ?, ?)", host, pdid, time.Now())
        }
    }

    slog.Info("v1→v2 PDID migration complete", "migrated", len(migrations))
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

    macRows, err := s.db.Query("SELECT pdid, mac FROM device_macs")
    if err == nil {
        defer macRows.Close()
        for macRows.Next() {
            var pdid, mac string
            if macRows.Scan(&pdid, &mac) == nil {
                if dev, ok := deviceMap[pdid]; ok {
                    dev.MACs = append(dev.MACs, mac)
                }
            }
        }
    }

    ipRows, err := s.db.Query("SELECT pdid, ip FROM device_ips")
    if err == nil {
        defer ipRows.Close()
        for ipRows.Next() {
            var pdid, ip string
            if ipRows.Scan(&pdid, &ip) == nil {
                if dev, ok := deviceMap[pdid]; ok {
                    dev.IPs = append(dev.IPs, ip)
                }
            }
        }
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

    for i, d := range devs {
        // Critical 1 Fix: Use SAVEPOINT to allow individual failures without aborting the batch
        spName := fmt.Sprintf("sp_%d", i)
        if _, err := tx.Exec("SAVEPOINT " + spName); err != nil {
            slog.Error("Failed to create savepoint, aborting batch", "error", err)
            return err
        }

        if err := s.saveDeviceTx(tx, d); err != nil {
            slog.Error("Failed to save device in batch, rolling back savepoint", "pdid", d.PDID, "error", err)
            _, _ = tx.Exec("ROLLBACK TO " + spName)
            _, _ = tx.Exec("RELEASE " + spName)
            continue
        }
        _, _ = tx.Exec("RELEASE " + spName)
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

    _, err := tx.Exec(`
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
    s.mu.Lock()
    defer s.mu.Unlock()
    if s.db != nil {
        return s.db.Close()
    }
    return nil
}

func canonicalizeHostnameLocal(raw string) string {
    h := strings.ToLower(strings.TrimSpace(raw))
    h = strings.TrimSuffix(h, ".")
    if h == "" {
        return ""
    }

    var canonicalSuffixes = []string{
        ".home.arpa", ".localdomain", ".internal", ".local", ".lan", ".home", ".corp", ".priv", ".intranet",
    }

    changed := true
    for changed {
        changed = false
        for _, suf := range canonicalSuffixes {
            if strings.HasSuffix(h, suf) {
                h = strings.TrimSuffix(h, suf)
                changed = true
                break
            }
        }
    }

    for strings.Contains(h, "..") {
        h = strings.ReplaceAll(h, "..", ".")
    }

    return strings.Trim(h, ".")
}
