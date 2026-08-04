// Package storage provides CGO-free SQLite persistence for LIAS configuration state.
//
// File:    apps/lias/internal/storage/sqlite.go
// Version: 1.9
package storage

import (
    "database/sql"
    "encoding/json"
    "fmt"
    "log/slog"
    "os"
    "path/filepath"
    "sync"

    "github.com/user/lias-dis/apps/lias/internal/policy"
    "github.com/user/lias-dis/apps/lias/internal/schedule"
    "github.com/user/lias-dis/apps/lias/internal/tags"
    "github.com/user/lias-dis/shared/models"
    _ "modernc.org/sqlite"
)

type Storage struct {
    mu     sync.RWMutex // LIAS-STOR-09 Fix: RWMutex allows concurrent reads
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

    CREATE TABLE IF NOT EXISTS device_tags (
        pdid TEXT PRIMARY KEY,
        tag_id TEXT NOT NULL,
        mac TEXT NOT NULL DEFAULT ''
    );

    -- UI-FN-12 Fix: Manual device overrides
    CREATE TABLE IF NOT EXISTS device_overrides (
        pdid TEXT PRIMARY KEY,
        friendly_name TEXT NOT NULL DEFAULT ''
    );

    -- SYS-FEAT-03 Fix: Per-User identity mapping
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
        enabled INTEGER NOT NULL DEFAULT 1, -- LIAS-POL-01 Fix
        data TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS schedules (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        mode TEXT NOT NULL DEFAULT '',
        timezone TEXT NOT NULL,
        rules TEXT NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_device_tags_mac ON device_tags(mac);
    `

    _, err := s.db.Exec(query)
    if err != nil {
        return fmt.Errorf("failed to execute schema initialization: %w", err)
    }

    // Additive migrations for existing databases
    _, _ = s.db.Exec("ALTER TABLE policies ADD COLUMN schedule_ids TEXT NOT NULL DEFAULT ''")
    _, _ = s.db.Exec("ALTER TABLE schedules ADD COLUMN mode TEXT NOT NULL DEFAULT ''")
    _, _ = s.db.Exec("ALTER TABLE policies ADD COLUMN enabled INTEGER NOT NULL DEFAULT 1") // LIAS-POL-01

    return nil
}

func (s *Storage) LoadHydrate(tagMgr *tags.Manager, polEng *policy.Engine, schedEng *schedule.Engine) (map[string]string, map[string]string, error) {
    s.mu.RLock()
    defer s.mu.RUnlock()

    deviceTags := make(map[string]string)
    macTags := make(map[string]string)

    // 1. Hydrate Tags
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

    // 2. Hydrate Device Tags
    dtRows, err := s.db.Query("SELECT pdid, tag_id, mac FROM device_tags")
    if err == nil {
        defer dtRows.Close()
        for dtRows.Next() {
            var pdid, tagID, mac string
            if err := dtRows.Scan(&pdid, &tagID, &mac); err == nil {
                if pdid != "" {
                    deviceTags[pdid] = tagID
                    tagMgr.EnsureTagExists(tagID)
                }
                if mac != "" {
                    macTags[mac] = tagID
                }
            }
        }
    }

    // 3. Hydrate Policies
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
                    p.Enabled = enabledInt == 1 // LIAS-POL-01
                    polEng.UpsertPolicy(p)
                }
            }
        }
    }

    // 4. Hydrate Schedules
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

func (s *Storage) SaveDeviceTag(pdid, tagID, mac string) error {
    s.mu.Lock()
    defer s.mu.Unlock()

    _, err := s.db.Exec(`
        INSERT INTO device_tags (pdid, tag_id, mac)
        VALUES (?, ?, ?)
        ON CONFLICT(pdid) DO UPDATE SET tag_id=excluded.tag_id, mac=CASE WHEN excluded.mac != '' THEN excluded.mac ELSE device_tags.mac END
    `, pdid, tagID, mac)

    return err
}

func (s *Storage) MigrateDeviceTag(oldPDID, newPDID string) error {
    s.mu.Lock()
    defer s.mu.Unlock()

    _, err := s.db.Exec(`
        UPDATE device_tags
        SET pdid = ?
        WHERE pdid = ?
    `, newPDID, oldPDID)

    return err
}

func (s *Storage) UpdateDeviceTagMAC(pdid, mac string) error {
    if pdid == "" || mac == "" {
        return nil
    }

    s.mu.Lock()
    defer s.mu.Unlock()

    _, err := s.db.Exec(`
        UPDATE device_tags
        SET mac = ?
        WHERE pdid = ? AND (mac = '' OR mac IS NULL)
    `, mac, pdid)

    return err
}

// UI-FN-12 Fix: Save manual device rename
func (s *Storage) SaveDeviceOverride(pdid, friendlyName string) error {
    s.mu.Lock()
    defer s.mu.Unlock()

    _, err := s.db.Exec(`
        INSERT INTO device_overrides (pdid, friendly_name)
        VALUES (?, ?)
        ON CONFLICT(pdid) DO UPDATE SET friendly_name=excluded.friendly_name
    `, pdid, friendlyName)

    return err
}

func (s *Storage) LoadDeviceOverrides() (map[string]string, error) {
    s.mu.RLock()
    defer s.mu.RUnlock()

    rows, err := s.db.Query("SELECT pdid, friendly_name FROM device_overrides")
    if err != nil {
        return nil, err
    }
    defer rows.Close()

    overrides := make(map[string]string)
    for rows.Next() {
        var pdid, name string
        if rows.Scan(&pdid, &name) == nil {
            overrides[pdid] = name
        }
    }
    return overrides, nil
}

// SYS-FEAT-03 Fix: Per-User identity mapping
func (s *Storage) SaveUser(u models.User) error {
    s.mu.Lock()
    defer s.mu.Unlock()

    _, err := s.db.Exec(`
        INSERT INTO users (id, name)
        VALUES (?, ?)
        ON CONFLICT(id) DO UPDATE SET name=excluded.name
    `, u.ID, u.Name)

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

    _, err := s.db.Exec(`
        INSERT INTO device_users (pdid, user_id)
        VALUES (?, ?)
        ON CONFLICT(pdid) DO UPDATE SET user_id=excluded.user_id
    `, pdid, userID)

    return err
}

func (s *Storage) LoadUserAssignments() (map[string]string, error) {
    s.mu.RLock()
    defer s.mu.RUnlock()

    rows, err := s.db.Query("SELECT pdid, user_id FROM device_users")
    if err != nil {
        return nil, err
    }
    defer rows.Close()

    mappings := make(map[string]string)
    for rows.Next() {
        var pdid, uid string
        if rows.Scan(&pdid, &uid) == nil {
            mappings[pdid] = uid
        }
    }
    return mappings, nil
}

func (s *Storage) SaveTag(t tags.Tag) error {
    s.mu.Lock()
    defer s.mu.Unlock()

    builtinInt := 0
    if t.Builtin {
        builtinInt = 1
    }

    _, err := s.db.Exec(`
        INSERT INTO tags (id, name, color, precedence, builtin)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
            name=excluded.name,
            color=excluded.color,
            precedence=excluded.precedence
    `, t.ID, t.Name, t.Color, t.Precedence, builtinInt)

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
    if err != nil {
        return err
    }

    schedID := ""
    if p.ScheduleID != nil {
        schedID = *p.ScheduleID
    }

    schedIDsBytes, _ := json.Marshal(p.GetScheduleIDs())
    
    enabledInt := 0
    if p.Enabled { // LIAS-POL-01
        enabledInt = 1
    }

    _, err = s.db.Exec(`
        INSERT INTO policies (id, name, type, target_id, action, schedule_id, schedule_ids, priority, enabled, data)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
            name=excluded.name,
            type=excluded.type,
            target_id=excluded.target_id,
            action=excluded.action,
            schedule_id=excluded.schedule_id,
            schedule_ids=excluded.schedule_ids,
            priority=excluded.priority,
            enabled=excluded.enabled,
            data=excluded.data
    `, p.ID, p.Name, p.Type, p.TargetID, p.Action, schedID, string(schedIDsBytes), p.Priority, enabledInt, string(dataBytes))

    return err
}

func (s *Storage) DeletePolicy(id string) error {
    s.mu.Lock()
    defer s.mu.Unlock()
    _, err := s.db.Exec("DELETE FROM policies WHERE id = ?", id)
    return err
}

func (s *Storage) SaveSchedule(sch models.Schedule) error {
    s.mu.Lock()
    defer s.mu.Unlock()

    rulesBytes, err := json.Marshal(sch.Rules)
    if err != nil {
        return err
    }

    _, err = s.db.Exec(`
        INSERT INTO schedules (id, name, mode, timezone, rules)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
            name=excluded.name,
            mode=excluded.mode,
            timezone=excluded.timezone,
            rules=excluded.rules
    `, sch.ID, sch.Name, sch.Mode, sch.Timezone, string(rulesBytes))

    return err
}

func (s *Storage) DeleteSchedule(id string) error {
    s.mu.Lock()
    defer s.mu.Unlock()
    _, err := s.db.Exec("DELETE FROM schedules WHERE id = ?", id)
    return err
}

func (s *Storage) Close() error {
    s.mu.Lock()
    defer s.mu.Unlock()
    if s.db != nil {
        return s.db.Close()
    }
    return nil
}
