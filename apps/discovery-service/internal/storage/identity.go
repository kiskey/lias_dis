package storage

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/user/lias-dis/shared/models"
)

var (
	ErrAliasConflict    = errors.New("verified identity alias belongs to another device")
	ErrIdentityNotFound = errors.New("identity record not found")
	ErrCandidateChanged = errors.New("identity candidate changed or was already decided")
)

func (s *Storage) UpsertIdentityAlias(alias models.IdentityAlias) (int64, error) {
	if alias.DeviceID == "" || alias.Type == "" || alias.ValueHash == "" {
		return 0, fmt.Errorf("invalid identity alias")
	}
	if alias.FirstSeen.IsZero() {
		alias.FirstSeen = time.Now()
	}
	if alias.LastSeen.IsZero() {
		alias.LastSeen = alias.FirstSeen
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()

	if alias.Verified {
		var owner string
		err := tx.QueryRow(`
            SELECT device_id FROM identity_aliases
            WHERE alias_type = ? AND value_hash = ? AND verified = 1
              AND revoked_at IS NULL AND device_id != ?
            LIMIT 1
        `, string(alias.Type), alias.ValueHash, alias.DeviceID).Scan(&owner)
		if err == nil {
			return 0, ErrAliasConflict
		}
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return 0, err
		}
	}

	verified := 0
	if alias.Verified {
		verified = 1
	}
	var id int64
	var existingSource string
	var existingConfidence float64
	var existingVerified int
	var revoked sql.NullTime
	err = tx.QueryRow(`SELECT id, source, confidence, verified, revoked_at
        FROM identity_aliases WHERE device_id = ? AND alias_type = ? AND value_hash = ?`,
		alias.DeviceID, string(alias.Type), alias.ValueHash).Scan(
		&id, &existingSource, &existingConfidence, &existingVerified, &revoked)
	if err == nil {
		// last_seen is volatile activity. Identical observations return the
		// existing ID without modifying a page or appending a WAL frame.
		if existingSource == alias.Source && existingConfidence >= alias.Confidence &&
			existingVerified >= verified && !revoked.Valid {
			return id, nil
		}
		_, err = tx.Exec(`UPDATE identity_aliases SET source = ?, confidence = MAX(confidence, ?),
            verified = MAX(verified, ?), revoked_at = NULL WHERE id = ?`,
			alias.Source, alias.Confidence, verified, id)
		if err != nil {
			return 0, err
		}
		return id, tx.Commit()
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return 0, err
	}
	result, err := tx.Exec(`INSERT INTO identity_aliases (
        device_id, alias_type, value_hash, source, confidence,
        verified, first_seen, last_seen, revoked_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL)`, alias.DeviceID, string(alias.Type), alias.ValueHash,
		alias.Source, alias.Confidence, verified, alias.FirstSeen, alias.LastSeen)
	if err != nil {
		return 0, err
	}
	id, err = result.LastInsertId()
	if err != nil {
		return 0, err
	}
	return id, tx.Commit()
}

// LoadIdentityAliases hydrates the material alias index used to suppress
// repeat writes while live observation times remain in memory.
func (s *Storage) LoadIdentityAliases() ([]models.IdentityAlias, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.db.Query(`SELECT id, device_id, alias_type, value_hash, source,
        confidence, verified, first_seen, last_seen, revoked_at FROM identity_aliases`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	aliases := make([]models.IdentityAlias, 0)
	for rows.Next() {
		var alias models.IdentityAlias
		var verified int
		var revoked sql.NullTime
		if err := rows.Scan(&alias.ID, &alias.DeviceID, &alias.Type, &alias.ValueHash, &alias.Source,
			&alias.Confidence, &verified, &alias.FirstSeen, &alias.LastSeen, &revoked); err != nil {
			return nil, err
		}
		alias.Verified = verified == 1
		if revoked.Valid {
			value := revoked.Time
			alias.RevokedAt = &value
		}
		aliases = append(aliases, alias)
	}
	return aliases, rows.Err()
}

func (s *Storage) FindVerifiedAliasPDIDs(aliasType models.IdentityAliasType, valueHash string) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	rows, err := s.db.Query(`
        SELECT DISTINCT d.pdid
        FROM identity_aliases a
        JOIN devices d ON d.device_id = a.device_id
        WHERE a.alias_type = ? AND a.value_hash = ?
          AND a.verified = 1 AND a.revoked_at IS NULL
        ORDER BY d.pdid
    `, string(aliasType), valueHash)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var pdids []string
	for rows.Next() {
		var pdid string
		if err := rows.Scan(&pdid); err != nil {
			return nil, err
		}
		pdids = append(pdids, pdid)
	}
	return pdids, rows.Err()
}

func (s *Storage) ListIdentityAliases(pdid string) ([]models.IdentityAlias, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	rows, err := s.db.Query(`
        SELECT a.id, a.device_id, d.pdid, a.alias_type, a.value_hash,
               a.source, a.confidence, a.verified, a.first_seen,
               a.last_seen, a.revoked_at
        FROM identity_aliases a
        JOIN devices d ON d.device_id = a.device_id
        WHERE d.pdid = ?
        ORDER BY a.verified DESC, a.last_seen DESC, a.id DESC
    `, pdid)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var aliases []models.IdentityAlias
	for rows.Next() {
		var alias models.IdentityAlias
		var verified int
		var revoked sql.NullTime
		if err := rows.Scan(&alias.ID, &alias.DeviceID, &alias.PDID, &alias.Type,
			&alias.ValueHash, &alias.Source, &alias.Confidence, &verified,
			&alias.FirstSeen, &alias.LastSeen, &revoked); err != nil {
			return nil, err
		}
		alias.Verified = verified == 1
		if revoked.Valid {
			value := revoked.Time
			alias.RevokedAt = &value
		}
		aliases = append(aliases, alias)
	}
	return aliases, rows.Err()
}

func (s *Storage) RevokeIdentityAlias(pdid string, aliasID int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	result, err := s.db.Exec(`
        UPDATE identity_aliases
        SET revoked_at = ?
        WHERE id = ? AND device_id = (SELECT device_id FROM devices WHERE pdid = ?)
    `, time.Now(), aliasID, pdid)
	if err != nil {
		return err
	}
	changed, _ := result.RowsAffected()
	if changed == 0 {
		return ErrIdentityNotFound
	}
	return nil
}

func (s *Storage) SaveIdentityEvidence(evidence models.IdentityEvidence) error {
	if evidence.DeviceID == "" || evidence.Kind == "" {
		return nil
	}
	if evidence.ObservedAt.IsZero() {
		evidence.ObservedAt = time.Now()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`
        INSERT INTO identity_evidence (
            device_id, candidate_device_id, kind, value_hash, source,
            log_likelihood, observed_at, expires_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `, evidence.DeviceID, evidence.CandidateDeviceID, evidence.Kind,
		evidence.ValueHash, evidence.Source, evidence.LogLikelihood,
		evidence.ObservedAt, evidence.ExpiresAt)
	return err
}

func (s *Storage) ListIdentityEvidence(pdid string, limit int) ([]models.IdentityEvidence, error) {
	if limit <= 0 || limit > 200 {
		limit = 100
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.db.Query(`
        SELECT e.id, e.device_id, e.candidate_device_id, e.kind,
               e.value_hash, e.source, e.log_likelihood,
               e.observed_at, e.expires_at
        FROM identity_evidence e
        JOIN devices d ON d.device_id = e.device_id
        WHERE d.pdid = ?
        ORDER BY e.observed_at DESC, e.id DESC
        LIMIT ?
    `, pdid, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var evidence []models.IdentityEvidence
	for rows.Next() {
		var item models.IdentityEvidence
		var expires sql.NullTime
		if err := rows.Scan(&item.ID, &item.DeviceID, &item.CandidateDeviceID,
			&item.Kind, &item.ValueHash, &item.Source, &item.LogLikelihood,
			&item.ObservedAt, &expires); err != nil {
			return nil, err
		}
		if expires.Valid {
			value := expires.Time
			item.ExpiresAt = &value
		}
		evidence = append(evidence, item)
	}
	return evidence, rows.Err()
}

func (s *Storage) UpsertIdentityCandidate(candidate models.IdentityCandidateLink) (int64, error) {
	if candidate.SourcePDID == "" || candidate.TargetPDID == "" || candidate.SourcePDID == candidate.TargetPDID {
		return 0, fmt.Errorf("invalid identity candidate")
	}
	now := time.Now()
	if candidate.CreatedAt.IsZero() {
		candidate.CreatedAt = now
	}
	candidate.UpdatedAt = now
	if candidate.Status == "" {
		candidate.Status = "pending"
	}
	factorsJSON, err := json.Marshal(candidate.Factors)
	if err != nil {
		return 0, err
	}
	ambiguous := 0
	if candidate.Ambiguous {
		ambiguous = 1
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	var id int64
	err = s.db.QueryRow(`
        INSERT INTO identity_candidates (
            source_pdid, target_pdid, probability, ambiguous, status,
            factors_json, created_at, updated_at, decision_source, decision_note
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(source_pdid, target_pdid) DO UPDATE SET
            probability = excluded.probability,
            ambiguous = excluded.ambiguous,
            factors_json = excluded.factors_json,
            updated_at = excluded.updated_at
        RETURNING id
	`, candidate.SourcePDID, candidate.TargetPDID, candidate.Probability,
		ambiguous, candidate.Status, string(factorsJSON), candidate.CreatedAt,
		candidate.UpdatedAt, candidate.DecisionSource, candidate.DecisionNote).Scan(&id)
	return id, err
}

func (s *Storage) ListIdentityCandidates(pdid string) ([]models.IdentityCandidateLink, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.db.Query(`
        SELECT id, source_pdid, target_pdid, probability, ambiguous,
               status, factors_json, created_at, updated_at, decision_source, decision_note
        FROM identity_candidates
        WHERE source_pdid = ? OR target_pdid = ?
        ORDER BY status = 'pending' DESC, probability DESC, updated_at DESC
    `, pdid, pdid)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var candidates []models.IdentityCandidateLink
	for rows.Next() {
		candidate, err := scanIdentityCandidate(rows)
		if err != nil {
			return nil, err
		}
		candidates = append(candidates, candidate)
	}
	return candidates, rows.Err()
}

// ListIdentityCandidatesPage returns a stable newest-first page. The cursor is
// the last row's (updated_at,id) tuple from the preceding page.
func (s *Storage) ListIdentityCandidatesPage(status string, limit int, before time.Time, beforeID int64) ([]models.IdentityCandidateLink, error) {
	// One extra row is allowed internally so callers can determine whether a
	// next-page cursor is needed while keeping the public limit capped at 100.
	if limit < 1 || limit > 101 {
		return nil, fmt.Errorf("invalid candidate page limit")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	query := `
        SELECT id, source_pdid, target_pdid, probability, ambiguous,
               status, factors_json, created_at, updated_at, decision_source, decision_note
        FROM identity_candidates
        WHERE (? = '' OR status = ?)
          AND (? = 0 OR updated_at < ? OR (updated_at = ? AND id < ?))
        ORDER BY updated_at DESC, id DESC
        LIMIT ?
    `
	hasCursor := 0
	if !before.IsZero() {
		hasCursor = 1
	}
	rows, err := s.db.Query(query, status, status, hasCursor, before, before, beforeID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	candidates := make([]models.IdentityCandidateLink, 0, limit)
	for rows.Next() {
		candidate, err := scanIdentityCandidate(rows)
		if err != nil {
			return nil, err
		}
		candidates = append(candidates, candidate)
	}
	return candidates, rows.Err()
}

func (s *Storage) GetIdentityCandidate(id int64) (models.IdentityCandidateLink, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	row := s.db.QueryRow(`
        SELECT id, source_pdid, target_pdid, probability, ambiguous,
               status, factors_json, created_at, updated_at, decision_source, decision_note
        FROM identity_candidates WHERE id = ?
    `, id)
	candidate, err := scanIdentityCandidate(row)
	if errors.Is(err, sql.ErrNoRows) {
		return candidate, ErrIdentityNotFound
	}
	return candidate, err
}

type identityCandidateScanner interface {
	Scan(dest ...interface{}) error
}

func scanIdentityCandidate(scanner identityCandidateScanner) (models.IdentityCandidateLink, error) {
	var candidate models.IdentityCandidateLink
	var ambiguous int
	var factorsJSON string
	err := scanner.Scan(&candidate.ID, &candidate.SourcePDID, &candidate.TargetPDID,
		&candidate.Probability, &ambiguous, &candidate.Status, &factorsJSON,
		&candidate.CreatedAt, &candidate.UpdatedAt, &candidate.DecisionSource, &candidate.DecisionNote)
	if err != nil {
		return candidate, err
	}
	candidate.Ambiguous = ambiguous == 1
	_ = json.Unmarshal([]byte(factorsJSON), &candidate.Factors)
	return candidate, nil
}

func (s *Storage) DecideIdentityCandidate(id int64, status, source string, note ...string) error {
	if status != "confirmed" && status != "rejected" {
		return fmt.Errorf("invalid candidate decision")
	}
	decisionNote := ""
	if len(note) > 0 {
		decisionNote = strings.TrimSpace(note[0])
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	result, err := s.db.Exec(`
        UPDATE identity_candidates
        SET status = ?, decision_source = ?, decision_note = ?, ambiguous = 0, updated_at = ?
        WHERE id = ? AND status = 'pending'
    `, status, source, decisionNote, time.Now(), id)
	if err != nil {
		return err
	}
	changed, _ := result.RowsAffected()
	if changed == 0 {
		return ErrIdentityNotFound
	}
	return nil
}

func (s *Storage) ReopenIdentityCandidate(id int64, source, note string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	result, err := s.db.Exec(`
        UPDATE identity_candidates
        SET status = 'pending', decision_source = ?, decision_note = ?, ambiguous = 1, updated_at = ?
        WHERE id = ? AND status = 'rejected'
    `, source, strings.TrimSpace(note), time.Now(), id)
	if err != nil {
		return err
	}
	changed, _ := result.RowsAffected()
	if changed == 0 {
		return ErrCandidateChanged
	}
	return nil
}

func (s *Storage) ResolvePDID(pdid string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	current := pdid
	seen := map[string]struct{}{current: {}}
	for i := 0; i < 8; i++ {
		var next string
		err := s.db.QueryRow("SELECT new_pdid FROM pdid_redirects WHERE old_pdid = ?", current).Scan(&next)
		if errors.Is(err, sql.ErrNoRows) {
			return current, nil
		}
		if err != nil {
			return "", err
		}
		if _, cycle := seen[next]; cycle {
			return "", fmt.Errorf("pdid redirect cycle")
		}
		seen[next] = struct{}{}
		current = next
	}
	return "", fmt.Errorf("pdid redirect depth exceeded")
}

func (s *Storage) MergeDevices(source, target *models.Device, reason string) error {
	if source == nil || target == nil || source.PDID == "" || target.PDID == "" || source.PDID == target.PDID {
		return fmt.Errorf("invalid device merge")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if err := s.mergeDevicesTx(tx, source, target, reason); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Storage) mergeDevicesTx(tx *sql.Tx, source, target *models.Device, reason string) error {
	if _, err := tx.Exec("DELETE FROM device_macs WHERE pdid = ?", source.PDID); err != nil {
		return err
	}
	if _, err := tx.Exec("DELETE FROM device_ips WHERE pdid = ?", source.PDID); err != nil {
		return err
	}
	if err := s.saveDeviceTx(tx, target); err != nil {
		return err
	}
	if _, err := tx.Exec(`
        UPDATE identity_aliases AS target_alias SET
            confidence = MAX(target_alias.confidence, (SELECT source_alias.confidence FROM identity_aliases source_alias
                WHERE source_alias.device_id = ? AND source_alias.alias_type = target_alias.alias_type AND source_alias.value_hash = target_alias.value_hash)),
            verified = MAX(target_alias.verified, (SELECT source_alias.verified FROM identity_aliases source_alias
                WHERE source_alias.device_id = ? AND source_alias.alias_type = target_alias.alias_type AND source_alias.value_hash = target_alias.value_hash)),
            last_seen = MAX(target_alias.last_seen, (SELECT source_alias.last_seen FROM identity_aliases source_alias
                WHERE source_alias.device_id = ? AND source_alias.alias_type = target_alias.alias_type AND source_alias.value_hash = target_alias.value_hash))
        WHERE target_alias.device_id = ? AND EXISTS (
            SELECT 1 FROM identity_aliases source_alias WHERE source_alias.device_id = ?
              AND source_alias.alias_type = target_alias.alias_type AND source_alias.value_hash = target_alias.value_hash
        )
    `, source.DeviceID, source.DeviceID, source.DeviceID, target.DeviceID, source.DeviceID); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM identity_aliases AS source_alias WHERE source_alias.device_id = ? AND EXISTS (
        SELECT 1 FROM identity_aliases target_alias WHERE target_alias.device_id = ?
          AND target_alias.alias_type = source_alias.alias_type AND target_alias.value_hash = source_alias.value_hash
    )`, source.DeviceID, target.DeviceID); err != nil {
		return err
	}
	if _, err := tx.Exec("UPDATE identity_aliases SET device_id = ? WHERE device_id = ?", target.DeviceID, source.DeviceID); err != nil {
		return err
	}
	if _, err := tx.Exec("UPDATE identity_evidence SET device_id = ? WHERE device_id = ?", target.DeviceID, source.DeviceID); err != nil {
		return err
	}
	if _, err := tx.Exec("DELETE FROM hostname_owners WHERE pdid = ?", source.PDID); err != nil {
		return err
	}
	if _, err := tx.Exec("DELETE FROM pending_events WHERE pdid = ?", source.PDID); err != nil {
		return err
	}
	if _, err := tx.Exec(`
        INSERT INTO pdid_redirects (old_pdid, new_pdid, reason, created_at)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(old_pdid) DO UPDATE SET
            new_pdid = excluded.new_pdid,
            reason = excluded.reason,
            created_at = excluded.created_at
    `, source.PDID, target.PDID, reason, time.Now()); err != nil {
		return err
	}
	if _, err := tx.Exec("DELETE FROM devices WHERE pdid = ?", source.PDID); err != nil {
		return err
	}
	return nil
}

// ConfirmIdentityCandidateMerge commits the candidate decision, device merge,
// redirect, aliases, and evidence as one SQLite transaction.
func (s *Storage) ConfirmIdentityCandidateMerge(id int64, source, target *models.Device, reason, note string) (models.IdentityCandidateLink, error) {
	if source == nil || target == nil || source.PDID == target.PDID {
		return models.IdentityCandidateLink{}, fmt.Errorf("invalid device merge")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return models.IdentityCandidateLink{}, err
	}
	defer func() { _ = tx.Rollback() }()
	candidate, err := scanIdentityCandidate(tx.QueryRow(`
        SELECT id, source_pdid, target_pdid, probability, ambiguous,
               status, factors_json, created_at, updated_at, decision_source, decision_note
        FROM identity_candidates WHERE id = ?
    `, id))
	if errors.Is(err, sql.ErrNoRows) {
		return candidate, ErrIdentityNotFound
	}
	if err != nil {
		return candidate, err
	}
	if candidate.Status != "pending" || candidate.SourcePDID != source.PDID || candidate.TargetPDID != target.PDID {
		return candidate, ErrCandidateChanged
	}
	now := time.Now()
	result, err := tx.Exec(`
        UPDATE identity_candidates
        SET status = 'confirmed', decision_source = 'manual_admin', decision_note = ?, ambiguous = 0, updated_at = ?
        WHERE id = ? AND status = 'pending'
    `, strings.TrimSpace(note), now, id)
	if err != nil {
		return candidate, err
	}
	changed, _ := result.RowsAffected()
	if changed != 1 {
		return candidate, ErrCandidateChanged
	}
	if err := s.mergeDevicesTx(tx, source, target, reason); err != nil {
		return candidate, err
	}
	if err := tx.Commit(); err != nil {
		return candidate, err
	}
	candidate.Status = "confirmed"
	candidate.Ambiguous = false
	candidate.DecisionSource = "manual_admin"
	candidate.DecisionNote = strings.TrimSpace(note)
	candidate.UpdatedAt = now
	return candidate, nil
}

func (s *Storage) SplitDevice(original, split *models.Device, macHash string) error {
	if original == nil || split == nil || original.PDID == split.PDID {
		return fmt.Errorf("invalid device split")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if err := s.saveDeviceTx(tx, original); err != nil {
		return err
	}
	if err := s.saveDeviceTx(tx, split); err != nil {
		return err
	}
	if macHash != "" {
		if _, err := tx.Exec(`
            UPDATE identity_aliases SET device_id = ?, source = 'manual_split',
                verified = 1, revoked_at = NULL, last_seen = ?
            WHERE device_id = ? AND alias_type = 'mac' AND value_hash = ?
        `, split.DeviceID, time.Now(), original.DeviceID, macHash); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Storage) IdentityProfile(pdid string) (*models.IdentityProfile, error) {
	resolved, err := s.ResolvePDID(pdid)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	var profile models.IdentityProfile
	var ambiguous int
	err = s.db.QueryRow(`
        SELECT device_id, pdid, identity_assurance,
               identity_probability, identity_ambiguous
        FROM devices WHERE pdid = ?
    `, resolved).Scan(&profile.DeviceID, &profile.PDID, &profile.Assurance,
		&profile.Probability, &ambiguous)
	s.mu.Unlock()
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrIdentityNotFound
	}
	if err != nil {
		return nil, err
	}
	profile.Ambiguous = ambiguous == 1
	if profile.Aliases, err = s.ListIdentityAliases(resolved); err != nil {
		return nil, err
	}
	if profile.Candidates, err = s.ListIdentityCandidates(resolved); err != nil {
		return nil, err
	}
	if profile.Evidence, err = s.ListIdentityEvidence(resolved, 100); err != nil {
		return nil, err
	}
	return &profile, nil
}

func IsIdentityNotFound(err error) bool {
	return errors.Is(err, ErrIdentityNotFound) || strings.Contains(strings.ToLower(err.Error()), "not found")
}
