// Package storage provides CGO-free SQLite persistence for LIAS configuration state.
//
// File:    apps/lias/internal/storage/sqlite.go
// Version: 1.1
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
	mu     sync.Mutex
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
		tag_id TEXT NOT NULL
	);

	CREATE TABLE IF NOT EXISTS policies (
		id TEXT PRIMARY KEY,
		name TEXT NOT NULL,
		type TEXT NOT NULL,
		target_id TEXT,
		action TEXT NOT NULL,
		schedule_id TEXT,
		priority INTEGER NOT NULL,
		data TEXT NOT NULL
	);

	CREATE TABLE IF NOT EXISTS schedules (
		id TEXT PRIMARY KEY,
		name TEXT NOT NULL,
		timezone TEXT NOT NULL,
		rules TEXT NOT NULL
	);
	`

	_, err := s.db.Exec(query)
	if err != nil {
		return fmt.Errorf("failed to execute schema initialization: %w", err)
	}
	return nil
}

func (s *Storage) LoadHydrate(tagMgr *tags.Manager, polEng *policy.Engine, schedEng *schedule.Engine) (map[string]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	deviceTags := make(map[string]string)

	// 1. Hydrate Tags
	rows, err := s.db.Query("SELECT id, name, color, precedence, builtin FROM tags")
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var t tags.Tag
			var builtin int
			if err := rows.Scan(&t.ID, &t.Name, &t.Color, &t.Precedence, &builtin); err == nil {
				t.Builtin = builtin == 1
				_, _ = tagMgr.Create(t.Name, t.Color)
			}
		}
	}

	// 2. Hydrate Device Tags (Sticky Assignments)
	dtRows, err := s.db.Query("SELECT pdid, tag_id FROM device_tags")
	if err == nil {
		defer dtRows.Close()
		for dtRows.Next() {
			var pdid, tagID string
			if err := dtRows.Scan(&pdid, &tagID); err == nil {
				deviceTags[pdid] = tagID
			}
		}
	}

	// 3. Hydrate Policies
	pRows, err := s.db.Query("SELECT data FROM policies")
	if err == nil {
		defer pRows.Close()
		for pRows.Next() {
			var dataStr string
			if err := pRows.Scan(&dataStr); err == nil {
				var p models.Policy
				if err := json.Unmarshal([]byte(dataStr), &p); err == nil {
					polEng.UpsertPolicy(p)
				}
			}
		}
	}

	// 4. Hydrate Schedules
	sRows, err := s.db.Query("SELECT id, name, timezone, rules FROM schedules")
	if err == nil {
		defer sRows.Close()
		for sRows.Next() {
			var sch models.Schedule
			var rulesJson string
			if err := sRows.Scan(&sch.ID, &sch.Name, &sch.Timezone, &rulesJson); err == nil {
				if err := json.Unmarshal([]byte(rulesJson), &sch.Rules); err == nil {
					schedEng.UpsertSchedule(sch)
				}
			}
		}
	}

	slog.Info("Successfully hydrated LIAS state from persistent storage", "loaded_device_tags", len(deviceTags))
	return deviceTags, nil
}

func (s *Storage) SaveDeviceTag(pdid, tagID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.Exec(`
		INSERT INTO device_tags (pdid, tag_id)
		VALUES (?, ?)
		ON CONFLICT(pdid) DO UPDATE SET tag_id=excluded.tag_id
	`, pdid, tagID)

	return err
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

	_, err = s.db.Exec(`
		INSERT INTO policies (id, name, type, target_id, action, schedule_id, priority, data)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			name=excluded.name,
			type=excluded.type,
			target_id=excluded.target_id,
			action=excluded.action,
			schedule_id=excluded.schedule_id,
			priority=excluded.priority,
			data=excluded.data
	`, p.ID, p.Name, p.Type, p.TargetID, p.Action, schedID, p.Priority, string(dataBytes))

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
		INSERT INTO schedules (id, name, timezone, rules)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			name=excluded.name,
			timezone=excluded.timezone,
			rules=excluded.rules
	`, sch.ID, sch.Name, sch.Timezone, string(rulesBytes))

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
