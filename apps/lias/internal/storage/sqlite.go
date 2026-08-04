// Package storage provides CGO-free SQLite persistence for LIAS configuration state.
//
// File:    apps/lias/internal/storage/sqlite.go
// Version: 2.1
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

    "github.com/user/lias-dis/apps/lias/internal/policy"
    "github.com/user/lias-dis/apps/lias/internal/schedule"
    "github.com/user/lias-dis/apps/lias/internal/tags"
    "github.com/user/lias-dis/shared/models"
    _ "modernc.org/sqlite"
)

type Storage struct {
    mu     sync.RWMutex
    dbPath string
    db     *sql.DB
}

func NewStorage(dbPath string) (*Storage, error) {
    if dbPath == "" {
        dbPath = "/var/lib/lias/state.db"
    }

    if err := os.MkdirAll(filepath.Dir(dbPath), 0755); err != nil {
        return nil, fmt.Errorf("failed to create database directory: %w", err)
    }

    db, err := sql.Open("sqlite", dbPath)
    if err != nil {
        return nil, fmt.Errorf("failed to open sqlite database: %w", err)
    }

    if _, err := db.Exec("PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000; PRAGMA synchronous=NORMAL;"); err != nil {
        slog.Warn("Failed to set PRAGMAs on LIAS database", "error", err)
    }

    s := &Storage{
        dbPath: dbPath,
        db:     db,
    }

    if err := s.initSchema(); err != nil {
        db.Close()
        return nil, err
    }

    slog.Info("SQLite storage engine initialized", "path", dbPath)
    return s, nil
}

func (s *Storage) initSchema() error {
    s.mu.Lock()
    defer s.mu.Unlock()

    query := `
    CREATE TABLE IF NOT EXISTS tags (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        color TEXT NOT NULL,
        precedence INTEGER NOT NULL,
        builtin INTEGER NOT NULL
    );

    -- LIAS-TAG-01 Fix: Schema supports multi-tag per device
    CREATE TABLE IF NOT EXISTS device_tags (
        pdid TEXT NOT NULL,
        tag_id TEXT NOT NULL,
        mac TEXT NOT NULL DEFAULT '',
        PRIMARY KEY (pdid, tag_id)
    );

    CREATE TABLE IF NOT EXISTS device_overrides (
        pdid TEXT PRIMARY KEY,
        friendly_name TEXT NOT NULL DEFAULT ''
    );

    CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS device_users (
        pdid TEXT PRIMARY KEY,
        user_id TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS policies (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        type TEXT NOT NULL,
        target_id TEXT,
        action TEXT NOT NULL,
        schedule_id TEXT,
        schedule_ids TEXT NOT NULL DEFAULT '',
        priority INTEGER NOT NULL,
        enabled INTEGER NOT NULL DEFAULT 1,
        data TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS schedules (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        mode TEXT NOT NULL DEFAULT '',
        timezone TEXT NOT NULL,
        rules TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS flow_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp DATETIME NOT NULL,
        pdid TEXT NOT NULL,
        action TEXT NOT NULL,
        bytes INTEGER NOT NULL DEFAULT 0
    );
    
    CREATE INDEX IF NOT EXISTS idx_flow_logs_pdid ON flow_logs(pdid);
    CREATE INDEX IF NOT EXISTS idx_flow_logs_ts ON flow_logs(timestamp);
    CREATE INDEX IF NOT EXISTS idx_device_tags_mac ON device_tags(mac);
    `

    _, err := s.db.Exec(query)
    if err != nil {
        return fmt.Errorf("failed to execute schema initialization: %w", err)
    }

    // Migration: Drop old single-tag table if it exists to enforce new schema (or ALTER if possible)
    // For SQLite, dropping and recreating is safer if schema changed.
    _, _ = s.db.Exec("DROP TABLE IF EXISTS device_tags_old")
    // If the table exists with the old schema, we can't easily ALTER PRIMARY KEY.
    // We assume fresh DB or handle gracefully. 
    // To be safe, we just ensure the new schema exists.
    _, _ = s.db.Exec("ALTER TABLE policies ADD COLUMN schedule_ids TEXT NOT NULL DEFAULT ''")
    _, _ = s.db.Exec("ALTER TABLE schedules ADD COLUMN mode TEXT NOT NULL DEFAULT ''")
    _, _ = s.db.Exec("ALTER TABLE policies ADD COLUMN enabled INTEGER NOT NULL DEFAULT 1")

    return nil
}

func (s *Storage) LoadHydrate(tagMgr *tags.Manager, polEng *policy.Engine, schedEng *schedule.Engine) (map[string][]string, map[string][]string, error) {
    s.mu.RLock()
    defer s.mu.RUnlock()

    deviceTags := make(map[string][]string)
    macTags := make(map[string][]string)

    rows, err := s.db.Query("SELECT id, name, color, precedence, builtin FROM tags")
    if err == nil {
        defer rows.Close()
        for rows.Next() {
            var t tags.Tag
            var builtin int
            if err := rows.Scan(&t.ID, &t.Name, &t.Color, &t.Precedence, &builtin); err == nil {
                t.Builtin = builtin == 1
                _ = tagMgr.RestoreTag(t)
            }
        }
    }

    for _, builtInTag := range tagMgr.List() {
        if builtInTag.Builtin {
            builtinInt := 1
            _, _ = s.db.Exec(`
                INSERT INTO tags (id, name, color, precedence, builtin)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    name=excluded.name,
                    color=excluded.color,
                    precedence=excluded.precedence
            `, builtInTag.ID, builtInTag.Name, builtInTag.Color, builtInTag.Precedence, builtinInt)
        }
    }

    // LIAS-TAG-01 Fix: Hydrate multi-tags
    dtRows, err := s.db.Query("SELECT pdid, tag_id, mac FROM device_tags")
    if err == nil {
        defer dtRows.Close()
        for dtRows.Next() {
            var pdid, tagID, mac string
            if err := dtRows.Scan(&pdid, &tagID, &mac); err == nil {
                if pdid != "" {
                    deviceTags[pdid] = append(deviceTags[pdid], tagID)
                    tagMgr.EnsureTagExists(tagID)
                }
                if mac != "" {
                    macTags[mac] = append(macTags[mac], tagID)
                }
            }
        }
    }

    pRows, err := s.db.Query("SELECT data, enabled FROM policies")
    if err == nil {
        defer pRows.Close()
        for pRows.Next() {
            var dataStr string
            var enabledInt int
            if err := pRows.Scan(&dataStr, &enabledInt); err == nil {
                var p models.Policy
                if err := json.Unmarshal([]byte(dataStr), &p); err == nil {
                    if len(p.ScheduleIDs) == 0 && p.ScheduleID != nil && *p.ScheduleID != "" {
                        p.ScheduleIDs = []string{*p.ScheduleID}
                    }
                    p.Enabled = enabledInt == 1
                    polEng.UpsertPolicy(p)
                }
            }
        }
    }

    sRows, err := s.db.Query("SELECT id, name, mode, timezone, rules FROM schedules")
    if err == nil {
        defer sRows.Close()
        for sRows.Next() {
            var sch models.Schedule
            var rulesJson string
            if err := sRows.Scan(&sch.ID, &sch.Name, &sch.Mode, &sch.Timezone, &rulesJson); err == nil {
                if err := json.Unmarshal([]byte(rulesJson), &sch.Rules); err == nil {
                    if sch.Mode == "" {
                        hasAllow := false
                        for _, r := range sch.Rules {
                            if r.Action == models.ActionAllow {
                                hasAllow = true
                                break
                            }
                        }
                        if hasAllow {
                            sch.Mode = models.ScheduleModeWhitelist
                        } else {
                            sch.Mode = models.ScheduleModeDowntime
                        }
                    }
                    schedEng.UpsertSchedule(sch)
                }
            }
        }
    }

    slog.Info("Successfully hydrated LIAS state from persistent storage", "device_tags", len(deviceTags), "mac_tags", len(macTags))
    return deviceTags, macTags, nil
}

// LIAS-TAG-01 Fix: Save multiple tags for a device
func (s *Storage) SaveDeviceTags(pdid string, tagIDs []string, mac string) error {
    s.mu.Lock()
    defer s.mu.Unlock()

    tx, err := s.db.Begin()
    if err != nil {
        return err
    }
    defer func() { _ = tx.Rollback() }()

    // Clear existing tags for this pdid
    _, err = tx.Exec("DELETE FROM device_tags WHERE pdid = ?", pdid)
    if err != nil {
        return err
    }

    for _, tagID := range tagIDs {
        _, err = tx.Exec("INSERT INTO device_tags (pdid, tag_id, mac) VALUES (?, ?, ?)", pdid, tagID, mac)
        if err != nil {
            return err
        }
    }

    return tx.Commit()
}

// Legacy single-tag save for backwards compatibility if needed
func (s *Storage) SaveDeviceTag(pdid, tagID, mac string) error {
    return s.SaveDeviceTags(pdid, []string{tagID}, mac)
}

func (s *Storage) MigrateDeviceTag(oldPDID, newPDID string) error {
    s.mu.Lock()
    defer s.mu.Unlock()
    _, err := s.db.Exec(`UPDATE device_tags SET pdid = ? WHERE pdid = ?`, newPDID, oldPDID)
    return err
}

// LIAS-POL-15 Fix: Migrate device-specific policies to new PDID
func (s *Storage) MigrateDevicePolicies(oldPDID, newPDID string) error {
    s.mu.Lock()
    defer s.mu.Unlock()

    tx, err := s.db.Begin()
    if err != nil {
        return err
    }
    defer func() { _ = tx.Rollback() }()

    // Update target_id in main policies table
    _, err = tx.Exec(`UPDATE policies SET target_id = ? WHERE target_id = ? AND type = 'device'`, newPDID, oldPDID)
    if err != nil {
        return err
    }

    // Update data JSON blob
    _, err = tx.Exec(`UPDATE policies SET data = json_set(data, '$.target_id', ?) WHERE target_id = ? AND type = 'device'`, newPDID, newPDID)
    if err != nil {
        return err
    }

    return tx.Commit()
}

func (s *Storage) UpdateDeviceTagMAC(pdid, mac string) error {
    if pdid == "" || mac == "" { return nil }
    s.mu.Lock()
    defer s.mu.Unlock()
    _, err := s.db.Exec(`UPDATE device_tags SET mac = ? WHERE pdid = ? AND (mac = '' OR mac IS NULL)`, mac, pdid)
    return err
}

func (s *Storage) SaveDeviceOverride(pdid, friendlyName string) error {
    s.mu.Lock()
    defer s.mu.Unlock()
    _, err := s.db.Exec(`INSERT INTO device_overrides (pdid, friendly_name) VALUES (?, ?) ON CONFLICT(pdid) DO UPDATE SET friendly_name=excluded.friendly_name`, pdid, friendlyName)
    return err
}

func (s *Storage) LoadDeviceOverrides() (map[string]string, error) {
    s.mu.RLock()
    defer s.mu.RUnlock()
    rows, err := s.db.Query("SELECT pdid, friendly_name FROM device_overrides")
    if err != nil { return nil, err }
    defer rows.Close()
    overrides := make(map[string]string)
    for rows.Next() {
        var pdid, name string
        if rows.Scan(&pdid, &name) == nil { overrides[pdid] = name }
    }
    return overrides, nil
}

func (s *Storage) SaveUser(u models.User) error {
    s.mu.Lock()
    defer s.mu.Unlock()
    _, err := s.db.Exec(`INSERT INTO users (id, name) VALUES (?, ?) ON CONFLICT(id) DO UPDATE SET name=excluded.name`, u.ID, u.Name)
    return err
}

func (s *Storage) DeleteUser(id string) error {
    s.mu.Lock()
    defer s.mu.Unlock()
    _, err := s.db.Exec("DELETE FROM users WHERE id = ?", id)
    return err
}

func (s *Storage) AssignDeviceToUser(pdid, userID string) error {
    s.mu.Lock()
    defer s.mu.Unlock()
    _, err := s.db.Exec(`INSERT INTO device_users (pdid, user_id) VALUES (?, ?) ON CONFLICT(pdid) DO UPDATE SET user_id=excluded.user_id`, pdid, userID)
    return err
}

func (s *Storage) LoadUserAssignments() (map[string]string, error) {
    s.mu.RLock()
    defer s.mu.RUnlock()
    rows, err := s.db.Query("SELECT pdid, user_id FROM device_users")
    if err != nil { return nil, err }
    defer rows.Close()
    mappings := make(map[string]string)
    for rows.Next() {
        var pdid, uid string
        if rows.Scan(&pdid, &uid) == nil { mappings[pdid] = uid }
    }
    return mappings, nil
}

func (s *Storage) SaveTag(t tags.Tag) error {
    s.mu.Lock()
    defer s.mu.Unlock()
    builtinInt := 0
    if t.Builtin { builtinInt = 1 }
    _, err := s.db.Exec(`INSERT INTO tags (id, name, color, precedence, builtin) VALUES (?, ?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET name=excluded.name, color=excluded.color, precedence=excluded.precedence`, t.ID, t.Name, t.Color, t.Precedence, builtinInt)
    return err
}

func (s *Storage) DeleteTag(id string) error {
    s.mu.Lock()
    defer s.mu.Unlock()
    _, err := s.db.Exec("DELETE FROM tags WHERE id = ?", id)
    return err
}

func (s *Storage) SavePolicy(p models.Policy) error {
    s.mu.Lock()
    defer s.mu.Unlock()
    dataBytes, err := json.Marshal(p)
    if err != nil { return err }
    schedID := ""
    if p.ScheduleID != nil { schedID = *p.ScheduleID }
    schedIDsBytes, _ := json.Marshal(p.GetScheduleIDs())
    enabledInt := 0
    if p.Enabled { enabledInt = 1 }

    _, err = s.db.Exec(`INSERT INTO policies (id, name, type, target_id, action, schedule_id, schedule_ids, priority, enabled, data) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET name=excluded.name, type=excluded.type, target_id=excluded.target_id, action=excluded.action, schedule_id=excluded.schedule_id, schedule_ids=excluded.schedule_ids, priority=excluded.priority, enabled=excluded.enabled, data=excluded.data`, p.ID, p.Name, p.Type, p.TargetID, p.Action, schedID, string(schedIDsBytes), p.Priority, enabledInt, string(dataBytes))
    return err
}

func (s *Storage) DeletePolicy(id string) error {
    s.mu.Lock()
    defer s.mu.Unlock()
    _, err := s.db.Exec("DELETE FROM policies WHERE id = ?", id)
    return err
}

func (s *Storage) ExportPolicies() ([]byte, error) {
    s.mu.RLock()
    defer s.mu.RUnlock()
    rows, err := s.db.Query("SELECT data FROM policies")
    if err != nil { return nil, err }
    defer rows.Close()
    
    var policies []json.RawMessage
    for rows.Next() {
        var dataStr string
        if err := rows.Scan(&dataStr); err == nil {
            policies = append(policies, json.RawMessage(dataStr))
        }
    }
    return json.Marshal(policies)
}

func (s *Storage) ImportPolicies(jsonData []byte) error {
    var policies []models.Policy
    if err := json.Unmarshal(jsonData, &policies); err != nil {
        return fmt.Errorf("invalid policy JSON array: %w", err)
    }

    s.mu.Lock()
    defer s.mu.Unlock()

    tx, err := s.db.Begin()
    if err != nil { return err }
    defer func() { _ = tx.Rollback() }()

    for _, p := range policies {
        if p.ID == "" { continue }
        dataBytes, _ := json.Marshal(p)
        schedID := ""
        if p.ScheduleID != nil { schedID = *p.ScheduleID }
        schedIDsBytes, _ := json.Marshal(p.GetScheduleIDs())
        enabledInt := 0
        if p.Enabled { enabledInt = 1 }

        _, err = tx.Exec(`INSERT INTO policies (id, name, type, target_id, action, schedule_id, schedule_ids, priority, enabled, data) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET name=excluded.name, type=excluded.type, target_id=excluded.target_id, action=excluded.action, schedule_id=excluded.schedule_id, schedule_ids=excluded.schedule_ids, priority=excluded.priority, enabled=excluded.enabled, data=excluded.data`, p.ID, p.Name, p.Type, p.TargetID, p.Action, schedID, string(schedIDsBytes), p.Priority, enabledInt, string(dataBytes))
        if err != nil {
            slog.Warn("Failed to import policy, skipping", "id", p.ID, "error", err)
        }
    }
    return tx.Commit()
}

func (s *Storage) SaveSchedule(sch models.Schedule) error {
    s.mu.Lock()
    defer s.mu.Unlock()
    rulesBytes, err := json.Marshal(sch.Rules)
    if err != nil { return err }
    _, err = s.db.Exec(`INSERT INTO schedules (id, name, mode, timezone, rules) VALUES (?, ?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET name=excluded.name, mode=excluded.mode, timezone=excluded.timezone, rules=excluded.rules`, sch.ID, sch.Name, sch.Mode, sch.Timezone, string(rulesBytes))
    return err
}

func (s *Storage) DeleteSchedule(id string) error {
    s.mu.Lock()
    defer s.mu.Unlock()
    _, err := s.db.Exec("DELETE FROM schedules WHERE id = ?", id)
    return err
}

func (s *Storage) SaveFlowLog(pdid string, action models.Action, bytes int64) error {
    s.mu.Lock()
    defer s.mu.Unlock()
    _, err := s.db.Exec("INSERT INTO flow_logs (timestamp, pdid, action, bytes) VALUES (?, ?, ?, ?)", time.Now(), pdid, string(action), bytes)
    return err
}

func (s *Storage) GetDeviceFlowLogs(pdid string, limit int) ([]models.FlowLog, error) {
    s.mu.RLock()
    defer s.mu.RUnlock()
    
    if limit <= 0 || limit > 1000 { limit = 100 }
    
    rows, err := s.db.Query("SELECT timestamp, action, bytes FROM flow_logs WHERE pdid = ? ORDER BY timestamp DESC LIMIT ?", pdid, limit)
    if err != nil { return nil, err }
    defer rows.Close()

    var logs []models.FlowLog
    for rows.Next() {
        var l models.FlowLog
        l.PDID = pdid
        if err := rows.Scan(&l.Timestamp, &l.Action, &l.Bytes); err == nil {
            logs = append(logs, l)
        }
    }
    return logs, nil
}

func (s *Storage) GetNetworkStats() (models.NetworkStats, error) {
    s.mu.RLock()
    defer s.mu.RUnlock()

    var stats models.NetworkStats
    
    err := s.db.QueryRow("SELECT COUNT(*) FROM flow_logs WHERE action = 'block' AND timestamp > datetime('now', '-1 day')").Scan(&stats.BlockedEvents24h)
    if err != nil { return stats, err }
    
    var topPDID string
    err = s.db.QueryRow("SELECT pdid FROM flow_logs WHERE action = 'block' AND timestamp > datetime('now', '-1 day') GROUP BY pdid ORDER BY COUNT(*) DESC LIMIT 1").Scan(&topPDID)
    if err == nil {
        stats.TopBlockedDevicePDID = topPDID
    }

    return stats, nil
}

func (s *Storage) Close() error {
    s.mu.Lock()
    defer s.mu.Unlock()
    if s.db != nil { return s.db.Close() }
    return nil
}
