package storage

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/user/lias-dis/shared/models"
)

type IdentityMigrationConflict struct {
	ObjectType string `json:"object_type"`
	WinnerID   string `json:"winner_id"`
	LoserID    string `json:"loser_id"`
	Details    string `json:"details"`
}

type IdentityMigrationResult struct {
	OldPDID      string
	NewPDID      string
	Tags         []string
	FriendlyName string
	UserID       string
	Policies     []models.Policy
	Conflicts    []IdentityMigrationConflict
	Replayed     bool
}

// MigrateIdentityState moves every LIAS-owned reference in one idempotent
// transaction. Target metadata wins when explicit; source fills empty values.
func (s *Storage) MigrateIdentityState(oldPDID, newPDID string) (IdentityMigrationResult, error) {
	result := IdentityMigrationResult{OldPDID: oldPDID, NewPDID: newPDID, Tags: []string{}, Policies: []models.Policy{}, Conflicts: []IdentityMigrationConflict{}}
	if oldPDID == "" || newPDID == "" || oldPDID == newPDID {
		return result, fmt.Errorf("invalid identity migration")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return result, err
	}
	defer func() { _ = tx.Rollback() }()

	var recordedTarget string
	err = tx.QueryRow("SELECT new_pdid FROM identity_migrations WHERE old_pdid = ?", oldPDID).Scan(&recordedTarget)
	if err == nil {
		if recordedTarget != newPDID {
			return result, fmt.Errorf("identity migration target conflict")
		}
		result.Replayed = true
		if err := loadIdentityMigrationStateTx(tx, &result); err != nil {
			return result, err
		}
		return result, tx.Commit()
	}
	if err != nil && err != sql.ErrNoRows {
		return result, err
	}

	if _, err := tx.Exec(`INSERT OR IGNORE INTO device_tags (pdid, tag_id, mac)
		SELECT ?, tag_id, mac FROM device_tags WHERE pdid = ?`, newPDID, oldPDID); err != nil {
		return result, err
	}
	if _, err := tx.Exec("DELETE FROM device_tags WHERE pdid = ?", oldPDID); err != nil {
		return result, err
	}
	if _, err := tx.Exec(`INSERT INTO device_overrides (pdid, friendly_name)
		SELECT ?, friendly_name FROM device_overrides WHERE pdid = ?
		ON CONFLICT(pdid) DO UPDATE SET friendly_name = CASE
			WHEN device_overrides.friendly_name != '' THEN device_overrides.friendly_name
			ELSE excluded.friendly_name END`, newPDID, oldPDID); err != nil {
		return result, err
	}
	if _, err := tx.Exec("DELETE FROM device_overrides WHERE pdid = ?", oldPDID); err != nil {
		return result, err
	}
	if _, err := tx.Exec(`INSERT INTO device_users (pdid, user_id)
		SELECT ?, user_id FROM device_users WHERE pdid = ?
		ON CONFLICT(pdid) DO UPDATE SET user_id = CASE
			WHEN device_users.user_id != '' THEN device_users.user_id
			ELSE excluded.user_id END`, newPDID, oldPDID); err != nil {
		return result, err
	}
	if _, err := tx.Exec("DELETE FROM device_users WHERE pdid = ?", oldPDID); err != nil {
		return result, err
	}

	if err := migrateIdentityPoliciesTx(tx, oldPDID, newPDID, &result); err != nil {
		return result, err
	}
	if _, err := tx.Exec("UPDATE flow_logs SET pdid = ? WHERE pdid = ?", newPDID, oldPDID); err != nil {
		return result, err
	}
	// Compress prior redirects so late queued writes always land on the newest
	// surviving identity even after multiple reidentifications.
	if _, err := tx.Exec("UPDATE identity_pdid_redirects SET new_pdid = ? WHERE new_pdid = ?", newPDID, oldPDID); err != nil {
		return result, err
	}
	if _, err := tx.Exec(`INSERT INTO identity_pdid_redirects (old_pdid, new_pdid) VALUES (?, ?)
		ON CONFLICT(old_pdid) DO UPDATE SET new_pdid = excluded.new_pdid`, oldPDID, newPDID); err != nil {
		return result, err
	}
	if _, err := tx.Exec("INSERT INTO identity_migrations (old_pdid, new_pdid, migrated_at) VALUES (?, ?, ?)", oldPDID, newPDID, time.Now()); err != nil {
		return result, err
	}
	for _, conflict := range result.Conflicts {
		if _, err := tx.Exec(`INSERT INTO identity_migration_conflicts
			(old_pdid, new_pdid, object_type, winner_id, loser_id, details, created_at)
			VALUES (?, ?, ?, ?, ?, ?, ?)`, oldPDID, newPDID, conflict.ObjectType,
			conflict.WinnerID, conflict.LoserID, conflict.Details, time.Now()); err != nil {
			return result, err
		}
	}
	if err := loadIdentityMigrationStateTx(tx, &result); err != nil {
		return result, err
	}
	return result, tx.Commit()
}

func migrateIdentityPoliciesTx(tx *sql.Tx, oldPDID, newPDID string, result *IdentityMigrationResult) error {
	rows, err := tx.Query("SELECT data FROM policies WHERE type = 'device' AND (target_id = ? OR target_id = ?)", oldPDID, newPDID)
	if err != nil {
		return err
	}
	var sourcePolicies, targetPolicies []models.Policy
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			rows.Close()
			return err
		}
		var policy models.Policy
		if err := json.Unmarshal([]byte(raw), &policy); err != nil {
			rows.Close()
			return fmt.Errorf("decode policy during identity migration: %w", err)
		}
		if policy.TargetID == oldPDID {
			sourcePolicies = append(sourcePolicies, policy)
		} else {
			targetPolicies = append(targetPolicies, policy)
		}
	}
	if err := rows.Close(); err != nil {
		return err
	}
	targetByID := make(map[string]models.Policy, len(targetPolicies))
	for _, policy := range targetPolicies {
		targetByID[policy.ID] = policy
	}
	for _, source := range sourcePolicies {
		oldID := source.ID
		source.TargetID = newPDID
		source.ID = retargetTemporaryPolicyID(source.ID, oldPDID, newPDID)
		source.UpdatedAt = time.Now()
		if target, collision := targetByID[source.ID]; collision {
			winner, loser := target, source
			if source.Priority > target.Priority {
				winner, loser = source, target
			}
			details, _ := json.Marshal(map[string]any{"winner": winner, "loser": loser})
			result.Conflicts = append(result.Conflicts, IdentityMigrationConflict{
				ObjectType: "policy", WinnerID: winner.ID, LoserID: loser.ID, Details: string(details),
			})
			if _, err := tx.Exec("DELETE FROM policies WHERE id IN (?, ?)", oldID, target.ID); err != nil {
				return err
			}
			if err := savePolicyTx(tx, winner); err != nil {
				return err
			}
			targetByID[winner.ID] = winner
			continue
		}
		if _, err := tx.Exec("DELETE FROM policies WHERE id = ?", oldID); err != nil {
			return err
		}
		if err := savePolicyTx(tx, source); err != nil {
			return err
		}
		targetByID[source.ID] = source
	}
	// Distinct policies are intentionally retained. Record which policy wins
	// enforcement when their enabled actions are mutually exclusive.
	var active []models.Policy
	for _, policy := range targetByID {
		if policy.Enabled {
			active = append(active, policy)
		}
	}
	sort.Slice(active, func(i, j int) bool {
		if active[i].Priority == active[j].Priority {
			return active[i].ID < active[j].ID
		}
		return active[i].Priority > active[j].Priority
	})
	if len(active) > 1 {
		winner := active[0]
		for _, loser := range active[1:] {
			if loser.Action == winner.Action {
				continue
			}
			details, _ := json.Marshal(map[string]any{"winner": winner, "lower_priority_policy": loser, "both_retained": true})
			result.Conflicts = append(result.Conflicts, IdentityMigrationConflict{
				ObjectType: "policy_precedence", WinnerID: winner.ID, LoserID: loser.ID, Details: string(details),
			})
		}
	}
	return nil
}

func retargetTemporaryPolicyID(id, oldPDID, newPDID string) string {
	for _, prefix := range []string{"pol_pause_", "pol_extend_device_"} {
		if id == prefix+oldPDID {
			return prefix + newPDID
		}
	}
	return id
}

func savePolicyTx(tx *sql.Tx, policy models.Policy) error {
	data, err := json.Marshal(policy)
	if err != nil {
		return err
	}
	scheduleID := ""
	if policy.ScheduleID != nil {
		scheduleID = *policy.ScheduleID
	}
	scheduleIDs, _ := json.Marshal(policy.GetScheduleIDs())
	enabled := 0
	if policy.Enabled {
		enabled = 1
	}
	_, err = tx.Exec(`INSERT INTO policies
		(id, name, type, target_id, action, schedule_id, schedule_ids, priority, enabled, data)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, policy.ID, policy.Name, policy.Type,
		policy.TargetID, policy.Action, scheduleID, string(scheduleIDs), policy.Priority, enabled, string(data))
	return err
}

func loadIdentityMigrationStateTx(tx *sql.Tx, result *IdentityMigrationResult) error {
	result.Tags = result.Tags[:0]
	rows, err := tx.Query("SELECT tag_id FROM device_tags WHERE pdid = ? ORDER BY tag_id", result.NewPDID)
	if err != nil {
		return err
	}
	for rows.Next() {
		var tag string
		if err := rows.Scan(&tag); err != nil {
			rows.Close()
			return err
		}
		result.Tags = append(result.Tags, tag)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	_ = tx.QueryRow("SELECT friendly_name FROM device_overrides WHERE pdid = ?", result.NewPDID).Scan(&result.FriendlyName)
	_ = tx.QueryRow("SELECT user_id FROM device_users WHERE pdid = ?", result.NewPDID).Scan(&result.UserID)
	result.Policies = result.Policies[:0]
	policyRows, err := tx.Query("SELECT data FROM policies WHERE type = 'device' AND target_id = ?", result.NewPDID)
	if err != nil {
		return err
	}
	for policyRows.Next() {
		var raw string
		if err := policyRows.Scan(&raw); err != nil {
			policyRows.Close()
			return err
		}
		var policy models.Policy
		if err := json.Unmarshal([]byte(raw), &policy); err != nil {
			policyRows.Close()
			return err
		}
		result.Policies = append(result.Policies, policy)
	}
	if err := policyRows.Close(); err != nil {
		return err
	}
	sort.Slice(result.Policies, func(i, j int) bool {
		if result.Policies[i].Priority == result.Policies[j].Priority {
			return strings.Compare(result.Policies[i].ID, result.Policies[j].ID) < 0
		}
		return result.Policies[i].Priority > result.Policies[j].Priority
	})
	if result.Replayed {
		result.Conflicts = result.Conflicts[:0]
		conflictRows, err := tx.Query(`SELECT object_type, winner_id, loser_id, details
			FROM identity_migration_conflicts WHERE old_pdid = ? AND new_pdid = ? ORDER BY id`, result.OldPDID, result.NewPDID)
		if err != nil {
			return err
		}
		for conflictRows.Next() {
			var conflict IdentityMigrationConflict
			if err := conflictRows.Scan(&conflict.ObjectType, &conflict.WinnerID, &conflict.LoserID, &conflict.Details); err != nil {
				conflictRows.Close()
				return err
			}
			result.Conflicts = append(result.Conflicts, conflict)
		}
		if err := conflictRows.Close(); err != nil {
			return err
		}
	}
	return nil
}
