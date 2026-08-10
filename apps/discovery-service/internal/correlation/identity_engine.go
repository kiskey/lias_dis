package correlation

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"sort"
	"strings"
	"time"

	identitycore "github.com/user/lias-dis/apps/discovery-service/internal/identity"
	"github.com/user/lias-dis/apps/discovery-service/internal/inventory"
	"github.com/user/lias-dis/apps/discovery-service/internal/storage"
	"github.com/user/lias-dis/shared/models"
)

var (
	ErrCandidateStaleOrConflicting = models.ErrCandidateStaleOrConflicting
	ErrCandidateNotFound           = models.ErrCandidateNotFound
)

type identityCandidateCursor struct {
	UpdatedAt time.Time `json:"updated_at"`
	ID        int64     `json:"id"`
}

type identityAliasKey struct {
	DeviceID string
	Type     models.IdentityAliasType
	Hash     string
}

type identityAliasActivity struct {
	ID                int64
	FirstSeen         time.Time
	LastSeen          time.Time
	LatestSource      string
	LatestConfidence  float64
	DurableSource     string
	DurableConfidence float64
	DurableVerified   bool
	Revoked           bool
}

func (e *Engine) loadIdentityAliasActivity(store *storage.Storage) {
	aliases, err := store.LoadIdentityAliases()
	if err != nil {
		return
	}
	e.aliasMu.Lock()
	defer e.aliasMu.Unlock()
	e.aliases = make(map[identityAliasKey]identityAliasActivity, len(aliases))
	for _, alias := range aliases {
		key := identityAliasKey{DeviceID: alias.DeviceID, Type: alias.Type, Hash: alias.ValueHash}
		e.aliases[key] = identityAliasActivity{
			ID: alias.ID, FirstSeen: alias.FirstSeen, LastSeen: alias.LastSeen,
			LatestSource: alias.Source, LatestConfidence: alias.Confidence,
			DurableSource: alias.Source, DurableConfidence: alias.Confidence,
			DurableVerified: alias.Verified, Revoked: alias.RevokedAt != nil,
		}
	}
}

// ReconcileOrphanMACDuplicates repairs the exact corruption shape produced by
// the former cache-purge/INSERT-OR-IGNORE interaction. Only a device with zero
// authoritative MAC memberships and no independent verified alias is merged.
func (e *Engine) ReconcileOrphanMACDuplicates() (int, error) {
	if e.store == nil {
		return 0, nil
	}
	devices := e.cache.List()
	owners := make(map[string]*models.Device)
	for i := range devices {
		d := &devices[i]
		for _, mac := range d.MACs {
			if normalized := inventory.NormalizeMAC(mac); normalized != "" {
				owners[normalized] = d
			}
		}
	}
	repaired := 0
	for i := range devices {
		source := &devices[i]
		if len(source.MACs) != 0 {
			continue
		}
		mac := inventory.NormalizeMAC(source.CurrentMAC)
		target := owners[mac]
		if mac == "" || target == nil || target.PDID == source.PDID {
			continue
		}
		conflicting, err := e.store.HasIndependentVerifiedAliases(source.DeviceID, target.DeviceID)
		if err != nil {
			return repaired, err
		}
		if conflicting {
			slog.Warn("Duplicate-MAC orphan requires identity review", "source_pdid", source.PDID,
				"owner_pdid", target.PDID, "mac", mac)
			continue
		}
		merged := mergeOrphanDeviceData(source, target)
		if err := e.store.MergeDevices(source, merged, "exact_mac_orphan_repair"); err != nil {
			return repaired, err
		}
		e.cache.Delete(source.PDID)
		e.cache.Upsert(merged)
		if merged.CanonicalHostname != "" {
			_ = e.cache.AcquireHostname(merged.CanonicalHostname, merged.PDID)
		}
		owners[mac] = merged
		migratedMACs := append([]string(nil), source.MACs...)
		if len(migratedMACs) == 0 {
			migratedMACs = []string{mac}
		}
		e.broker.Broadcast(models.NewEvent(models.EventDeviceReidentified, merged.PDID, models.DeviceReidentifiedPayload{
			PDID: merged.PDID, OldPDID: source.PDID, NewPDID: merged.PDID,
			Reason: "exact_mac_orphan_repair", MigratedMACs: migratedMACs, Timestamp: time.Now(),
		}))
		repaired++
	}
	if repaired > 0 {
		e.loadIdentityAliasActivity(e.store)
	}
	return repaired, nil
}

func mergeOrphanDeviceData(source, target *models.Device) *models.Device {
	merged := mergeDeviceData(source, target)
	// Repairing a storage artifact is not an administrator verification.
	merged.IdentityAssurance = target.IdentityAssurance
	merged.IdentityProbability = target.IdentityProbability
	merged.IdentityAmbiguous = target.IdentityAmbiguous
	if merged.Hostname == "" {
		merged.Hostname = source.Hostname
		merged.CanonicalHostname = source.CanonicalHostname
	}
	if merged.FriendlyName == "" {
		merged.FriendlyName = source.FriendlyName
	}
	if merged.Manufacturer == "" {
		merged.Manufacturer = source.Manufacturer
	}
	if merged.Vendor == "" {
		merged.Vendor = source.Vendor
	}
	if merged.Model == "" {
		merged.Model = source.Model
	}
	if merged.DeviceType == "" {
		merged.DeviceType = source.DeviceType
	}
	if target.CurrentIP != "" {
		merged.CurrentIP = target.CurrentIP
	} else if source.CurrentIP != "" {
		merged.CurrentIP = source.CurrentIP
	}
	if merged.SourceInfo == nil {
		merged.SourceInfo = make(map[string]models.SourceMeta)
	}
	for key, meta := range source.SourceInfo {
		if _, exists := merged.SourceInfo[key]; !exists {
			merged.SourceInfo[key] = meta
		}
	}
	return merged
}

func (e *Engine) resolveVerifiedObservation(signals []identitycore.Signal) *models.Device {
	if e.store == nil {
		return nil
	}
	owners := make(map[string]struct{})
	for _, signal := range signals {
		// Passive MAC observations may match a MAC alias that an administrator
		// previously verified. Stable credentials must arrive authenticated.
		if signal.Type != models.AliasMAC && !signal.Verified {
			continue
		}
		hash, err := identitycore.HashAlias(signal.Type, signal.Value)
		if err != nil {
			continue
		}
		pdids, err := e.store.FindVerifiedAliasPDIDs(signal.Type, hash)
		if err != nil {
			continue
		}
		for _, pdid := range pdids {
			owners[pdid] = struct{}{}
		}
	}
	if len(owners) != 1 {
		return nil
	}
	for pdid := range owners {
		return e.cache.Get(pdid)
	}
	return nil
}

func (e *Engine) recordIdentitySignals(d *models.Device, signals []identitycore.Signal, candidate *models.Device, decision identitycore.Decision, observedAt time.Time) {
	if e.store == nil || d == nil || d.DeviceID == "" {
		return
	}

	for _, signal := range signals {
		hash, err := identitycore.HashAlias(signal.Type, signal.Value)
		if err != nil {
			continue
		}
		key := identityAliasKey{DeviceID: d.DeviceID, Type: signal.Type, Hash: hash}
		e.aliasMu.Lock()
		activity, known := e.aliases[key]
		if activity.FirstSeen.IsZero() {
			activity.FirstSeen = observedAt
		}
		if observedAt.After(activity.LastSeen) {
			activity.LastSeen = observedAt
		}
		activity.LatestSource = signal.Source
		if signal.Confidence > activity.LatestConfidence {
			activity.LatestConfidence = signal.Confidence
		}
		materialChanged := !known || (!activity.Revoked &&
			((signal.Verified && !activity.DurableVerified) || signal.Confidence > activity.DurableConfidence))
		e.aliases[key] = activity
		e.aliasMu.Unlock()
		if !materialChanged {
			continue
		}
		id, persistErr := e.store.UpsertIdentityAlias(models.IdentityAlias{
			DeviceID: d.DeviceID, PDID: d.PDID, Type: signal.Type,
			ValueHash: hash, Source: signal.Source, Confidence: signal.Confidence,
			Verified: signal.Verified, FirstSeen: activity.FirstSeen, LastSeen: observedAt,
		})
		if persistErr == nil {
			e.aliasMu.Lock()
			activity = e.aliases[key]
			activity.ID = id
			activity.DurableSource = signal.Source
			if signal.Confidence > activity.DurableConfidence {
				activity.DurableConfidence = signal.Confidence
			}
			activity.DurableVerified = activity.DurableVerified || signal.Verified
			activity.Revoked = false
			e.aliases[key] = activity
			e.aliasMu.Unlock()
		}
	}
	if candidate == nil || decision.Probability < identitycore.PassiveCandidateThreshold {
		return
	}
	id, err := e.store.UpsertIdentityCandidate(models.IdentityCandidateLink{
		SourcePDID: d.PDID, TargetPDID: candidate.PDID,
		Probability: decision.Probability, Ambiguous: true, Status: "pending",
		Factors: decision.Factors, CreatedAt: observedAt,
	})
	if err == nil {
		e.broker.Broadcast(models.NewEvent(models.EventIdentityCandidateChanged, d.PDID, models.IdentityCandidateEventPayload{
			CandidateID: id, SourcePDID: d.PDID, TargetPDID: candidate.PDID,
			Status: "pending", Timestamp: time.Now(),
		}))
	}
	for _, factor := range decision.Factors {
		if !factor.Matched {
			continue
		}
		_ = e.store.SaveIdentityEvidence(models.IdentityEvidence{
			DeviceID: d.DeviceID, CandidateDeviceID: candidate.DeviceID,
			Kind: factor.Kind, Source: "passive_correlation",
			LogLikelihood: math.Log(factor.LikelihoodRatio), ObservedAt: observedAt,
		})
	}
}

func (e *Engine) ResolvePDID(pdid string) string {
	if e.store == nil {
		return pdid
	}
	resolved, err := e.store.ResolvePDID(pdid)
	if err != nil {
		return pdid
	}
	return resolved
}

func (e *Engine) GetIdentityProfile(pdid string) (*models.IdentityProfile, error) {
	if e.store == nil {
		return nil, errors.New("identity persistence unavailable")
	}
	profile, err := e.store.IdentityProfile(e.ResolvePDID(pdid))
	if err != nil {
		return nil, err
	}
	e.aliasMu.RLock()
	for i := range profile.Aliases {
		alias := &profile.Aliases[i]
		activity, ok := e.aliases[identityAliasKey{DeviceID: alias.DeviceID, Type: alias.Type, Hash: alias.ValueHash}]
		if !ok {
			continue
		}
		if activity.LastSeen.After(alias.LastSeen) {
			alias.LastSeen = activity.LastSeen
		}
		if activity.LatestSource != "" {
			alias.Source = activity.LatestSource
		}
		if activity.LatestConfidence > alias.Confidence {
			alias.Confidence = activity.LatestConfidence
		}
	}
	e.aliasMu.RUnlock()
	// Preserve the route's established activity ordering even though the
	// freshest timestamps are now overlaid from memory rather than SQLite.
	sort.SliceStable(profile.Aliases, func(i, j int) bool {
		if profile.Aliases[i].Verified != profile.Aliases[j].Verified {
			return profile.Aliases[i].Verified
		}
		if !profile.Aliases[i].LastSeen.Equal(profile.Aliases[j].LastSeen) {
			return profile.Aliases[i].LastSeen.After(profile.Aliases[j].LastSeen)
		}
		return profile.Aliases[i].ID > profile.Aliases[j].ID
	})
	return profile, nil
}

func (e *Engine) BindIdentityAlias(pdid string, req models.IdentityBindingRequest) (models.IdentityAlias, error) {
	if e.store == nil {
		return models.IdentityAlias{}, errors.New("identity persistence unavailable")
	}
	pdid = e.ResolvePDID(pdid)
	d := e.cache.Get(pdid)
	if d == nil {
		return models.IdentityAlias{}, storageIdentityNotFound()
	}
	hash, err := identitycore.HashAlias(req.Type, req.Value)
	if err != nil {
		return models.IdentityAlias{}, fmt.Errorf("invalid alias value")
	}
	now := time.Now()
	source := strings.TrimSpace(req.Source)
	if source == "" {
		source = "manual_admin"
	}
	alias := models.IdentityAlias{DeviceID: d.DeviceID, PDID: d.PDID, Type: req.Type,
		ValueHash: hash, Source: source, Confidence: 1, Verified: true,
		FirstSeen: now, LastSeen: now}
	id, err := e.store.UpsertIdentityAlias(alias)
	alias.ID = id
	if err == nil {
		key := identityAliasKey{DeviceID: d.DeviceID, Type: alias.Type, Hash: alias.ValueHash}
		e.aliasMu.Lock()
		e.aliases[key] = identityAliasActivity{
			ID: id, FirstSeen: alias.FirstSeen, LastSeen: alias.LastSeen,
			LatestSource: alias.Source, LatestConfidence: alias.Confidence,
			DurableSource: alias.Source, DurableConfidence: alias.Confidence, DurableVerified: true,
		}
		e.aliasMu.Unlock()
		d.IdentityAssurance = models.IdentityVerified
		d.IdentityProbability = 1
		d.IdentityAmbiguous = false
		e.cache.Upsert(d)
		e.markDirty(d.PDID)
		e.broker.Broadcast(models.NewEvent(models.EventIdentityBindingChanged, d.PDID, models.IdentityBindingEventPayload{
			PDID: d.PDID, AliasID: alias.ID, AliasType: alias.Type, Action: "bound", Timestamp: time.Now(),
		}))
	}
	return alias, err
}

func storageIdentityNotFound() error { return errors.New("identity not found") }

func (e *Engine) RevokeIdentityAlias(pdid string, aliasID int64) error {
	if e.store == nil {
		return errors.New("identity persistence unavailable")
	}
	pdid = e.ResolvePDID(pdid)
	err := e.store.RevokeIdentityAlias(pdid, aliasID)
	if err == nil {
		e.aliasMu.Lock()
		for key, activity := range e.aliases {
			if activity.ID == aliasID {
				activity.Revoked = true
				e.aliases[key] = activity
				break
			}
		}
		e.aliasMu.Unlock()
		e.broker.Broadcast(models.NewEvent(models.EventIdentityBindingChanged, pdid, models.IdentityBindingEventPayload{
			PDID: pdid, AliasID: aliasID, Action: "revoked", Timestamp: time.Now(),
		}))
	}
	return err
}

func (e *Engine) ListIdentityCandidates(status string, limit int, cursor string) (models.IdentityCandidateListResponse, error) {
	if e.store == nil {
		return models.IdentityCandidateListResponse{}, errors.New("identity persistence unavailable")
	}
	var after identityCandidateCursor
	if cursor != "" {
		data, err := base64.RawURLEncoding.DecodeString(cursor)
		if err != nil || json.Unmarshal(data, &after) != nil || after.ID < 1 || after.UpdatedAt.IsZero() {
			return models.IdentityCandidateListResponse{}, fmt.Errorf("invalid cursor")
		}
	}
	links, err := e.store.ListIdentityCandidatesPage(status, limit+1, after.UpdatedAt, after.ID)
	if err != nil {
		return models.IdentityCandidateListResponse{}, err
	}
	response := models.IdentityCandidateListResponse{Candidates: make([]models.IdentityCandidateDetail, 0, min(limit, len(links)))}
	for _, link := range links[:min(limit, len(links))] {
		response.Candidates = append(response.Candidates, e.decorateIdentityCandidate(link))
	}
	if len(links) > limit {
		last := links[limit-1]
		data, _ := json.Marshal(identityCandidateCursor{UpdatedAt: last.UpdatedAt, ID: last.ID})
		response.NextCursor = base64.RawURLEncoding.EncodeToString(data)
	}
	return response, nil
}

func (e *Engine) GetIdentityCandidate(id int64) (*models.IdentityCandidateDetail, error) {
	if e.store == nil {
		return nil, errors.New("identity persistence unavailable")
	}
	candidate, err := e.store.GetIdentityCandidate(id)
	if err != nil {
		if storage.IsIdentityNotFound(err) {
			return nil, ErrCandidateNotFound
		}
		return nil, err
	}
	decorated := e.decorateIdentityCandidate(candidate)
	return &decorated, nil
}

func (e *Engine) decorateIdentityCandidate(link models.IdentityCandidateLink) models.IdentityCandidateDetail {
	item := models.IdentityCandidateDetail{ID: link.ID, SourcePDID: link.SourcePDID, TargetPDID: link.TargetPDID,
		Probability: link.Probability, Ambiguous: link.Ambiguous, Status: link.Status,
		Factors: []models.IdentityFactor{}, Conflicts: []models.IdentityFactor{}, CreatedAt: link.CreatedAt,
		UpdatedAt: link.UpdatedAt, DecisionSource: link.DecisionSource, DecisionNote: link.DecisionNote}
	for _, factor := range link.Factors {
		if factor.Matched {
			item.Factors = append(item.Factors, factor)
		} else {
			item.Conflicts = append(item.Conflicts, factor)
		}
	}
	// Do not resolve the source through a post-merge redirect: after a confirmed
	// merge the source record genuinely no longer exists and must not be shown
	// as a duplicate copy of the surviving target.
	item.SourceDevice = identityCandidateDevice(e.cache.Get(link.SourcePDID))
	item.TargetDevice = identityCandidateDevice(e.cache.Get(link.TargetPDID))
	return item
}

func identityCandidateDevice(device *models.Device) *models.IdentityCandidateDevice {
	if device == nil {
		return nil
	}
	return &models.IdentityCandidateDevice{PDID: device.PDID, DisplayName: device.DisplayName(),
		CurrentMAC: device.CurrentMAC, Online: device.Online, LastSeen: device.LastSeen}
}

func validateCandidateDecision(candidate models.IdentityCandidateLink, req models.IdentityCandidateDecisionRequest) error {
	if req.ExpectedSourcePDID != "" && req.ExpectedSourcePDID != candidate.SourcePDID {
		return ErrCandidateStaleOrConflicting
	}
	if req.ExpectedTargetPDID != "" && req.ExpectedTargetPDID != candidate.TargetPDID {
		return ErrCandidateStaleOrConflicting
	}
	if req.ExpectedUpdatedAt != nil && !req.ExpectedUpdatedAt.Equal(candidate.UpdatedAt) {
		return ErrCandidateStaleOrConflicting
	}
	return nil
}

func (e *Engine) RejectIdentityCandidate(id int64, req models.IdentityCandidateDecisionRequest) (*models.IdentityCandidateDetail, error) {
	e.identityMu.Lock()
	defer e.identityMu.Unlock()
	candidate, err := e.store.GetIdentityCandidate(id)
	if err != nil {
		return nil, ErrCandidateNotFound
	}
	if candidate.Status == "rejected" {
		decorated := e.decorateIdentityCandidate(candidate)
		return &decorated, nil
	}
	if candidate.Status != "pending" || validateCandidateDecision(candidate, req) != nil {
		return nil, ErrCandidateStaleOrConflicting
	}
	if err := e.store.DecideIdentityCandidate(id, "rejected", "manual_admin", req.DecisionNote); err != nil {
		return nil, ErrCandidateStaleOrConflicting
	}
	candidate, _ = e.store.GetIdentityCandidate(id)
	e.broadcastCandidateDecision(candidate)
	decorated := e.decorateIdentityCandidate(candidate)
	return &decorated, nil
}

func (e *Engine) ReopenIdentityCandidate(id int64, req models.IdentityCandidateDecisionRequest) (*models.IdentityCandidateDetail, error) {
	e.identityMu.Lock()
	defer e.identityMu.Unlock()
	candidate, err := e.store.GetIdentityCandidate(id)
	if err != nil {
		return nil, ErrCandidateNotFound
	}
	if candidate.Status == "confirmed" || validateCandidateDecision(candidate, req) != nil {
		return nil, ErrCandidateStaleOrConflicting
	}
	if candidate.Status == "pending" {
		decorated := e.decorateIdentityCandidate(candidate)
		return &decorated, nil
	}
	if err := e.store.ReopenIdentityCandidate(id, "manual_admin", req.DecisionNote); err != nil {
		return nil, ErrCandidateStaleOrConflicting
	}
	candidate, _ = e.store.GetIdentityCandidate(id)
	e.broker.Broadcast(models.NewEvent(models.EventIdentityCandidateChanged, candidate.SourcePDID, models.IdentityCandidateEventPayload{
		CandidateID: id, SourcePDID: candidate.SourcePDID, TargetPDID: candidate.TargetPDID,
		Status: candidate.Status, Timestamp: time.Now(),
	}))
	decorated := e.decorateIdentityCandidate(candidate)
	return &decorated, nil
}

func (e *Engine) ConfirmIdentityCandidate(id int64, req models.IdentityCandidateDecisionRequest) (*models.Device, error) {
	e.identityMu.Lock()
	defer e.identityMu.Unlock()
	if e.store == nil {
		return nil, errors.New("identity persistence unavailable")
	}
	candidate, err := e.store.GetIdentityCandidate(id)
	if err != nil {
		return nil, ErrCandidateNotFound
	}
	if candidate.Status == "confirmed" {
		device := e.cache.Get(e.ResolvePDID(candidate.TargetPDID))
		if device == nil {
			return nil, ErrCandidateStaleOrConflicting
		}
		return device, nil
	}
	if candidate.Status != "pending" || validateCandidateDecision(candidate, req) != nil {
		return nil, ErrCandidateStaleOrConflicting
	}
	source := e.cache.Get(candidate.SourcePDID)
	target := e.cache.Get(candidate.TargetPDID)
	if source == nil || target == nil {
		return nil, ErrCandidateStaleOrConflicting
	}
	if source.Online && target.Online {
		return nil, ErrCandidateStaleOrConflicting
	}
	merged := mergeDeviceData(source, target)
	decided, err := e.store.ConfirmIdentityCandidateMerge(id, source, merged, "manual_candidate_confirmation", req.DecisionNote)
	if err != nil {
		return nil, err
	}
	e.cache.Delete(source.PDID)
	e.cache.Upsert(merged)
	e.broadcastCandidateDecision(decided)
	e.broker.Broadcast(models.NewEvent(models.EventDeviceReidentified, merged.PDID, models.DeviceReidentifiedPayload{
		PDID: merged.PDID, OldPDID: source.PDID, NewPDID: merged.PDID, Reason: "manual_candidate_confirmation",
		MigratedMACs: source.MACs, Timestamp: time.Now(),
	}))
	return merged, nil
}

func (e *Engine) broadcastCandidateDecision(candidate models.IdentityCandidateLink) {
	e.broker.Broadcast(models.NewEvent(models.EventIdentityCandidateDecided, candidate.SourcePDID, models.IdentityCandidateEventPayload{
		CandidateID: candidate.ID, SourcePDID: candidate.SourcePDID, TargetPDID: candidate.TargetPDID,
		Status: candidate.Status, Timestamp: time.Now(),
	}))
}

func mergeDeviceData(source, target *models.Device) *models.Device {
	merged := target.Clone()
	for _, mac := range source.MACs {
		merged.AddMAC(mac)
	}
	for _, ip := range source.IPs {
		merged.AddIP(ip)
	}
	for _, service := range source.Services {
		merged.AddService(service)
	}
	for _, tag := range source.Tags {
		if !containsString(merged.Tags, tag) {
			merged.Tags = append(merged.Tags, tag)
		}
	}
	if source.LastSeen.After(merged.LastSeen) {
		merged.LastSeen = source.LastSeen
	}
	if merged.FirstSeen.IsZero() || (!source.FirstSeen.IsZero() && source.FirstSeen.Before(merged.FirstSeen)) {
		merged.FirstSeen = source.FirstSeen
	}
	merged.IdentityAssurance = models.IdentityVerified
	merged.IdentityProbability = 1
	merged.IdentityAmbiguous = false
	return merged
}

func (e *Engine) SplitIdentity(pdid string, req models.IdentitySplitRequest) (*models.Device, error) {
	if e.store == nil {
		return nil, errors.New("identity persistence unavailable")
	}
	pdid = e.ResolvePDID(pdid)
	original := e.cache.Get(pdid)
	mac, normalizeErr := identitycore.NormalizeAlias(models.AliasMAC, req.MAC)
	if original == nil || normalizeErr != nil || !original.HasMAC(mac) || len(original.MACs) < 2 {
		return nil, fmt.Errorf("split requires one MAC from a multi-MAC device")
	}
	deviceID, newPDID, err := inventory.NewPermanentIdentity()
	if err != nil {
		return nil, err
	}
	original.MACs = removeString(original.MACs, mac)
	if original.CurrentMAC == mac {
		original.CurrentMAC = firstString(original.MACs)
	}
	split := &models.Device{DeviceID: deviceID, PDID: newPDID, CurrentMAC: mac, MACs: []string{mac},
		IdentityTier: models.TierTentative, IdentityAnchor: mac, IdentityAssurance: models.IdentityVerified,
		IdentityProbability: 1, Vendor: original.Vendor, Model: original.Model, DeviceType: original.DeviceType,
		FirstSeen: time.Now(), LastSeen: time.Now(), SourceInfo: map[string]models.SourceMeta{}}
	for _, ip := range req.MoveIPs {
		ip = strings.TrimSpace(ip)
		if ip != "" {
			original.IPs = removeString(original.IPs, ip)
			split.AddIP(ip)
		}
	}
	hash, _ := identitycore.HashAlias(models.AliasMAC, mac)
	if err := e.store.SplitDevice(original, split, hash); err != nil {
		return nil, err
	}
	e.cache.Upsert(original)
	e.cache.Upsert(split)
	return split, nil
}

func removeString(values []string, remove string) []string {
	out := values[:0]
	for _, value := range values {
		if value != remove {
			out = append(out, value)
		}
	}
	return out
}
func firstString(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return values[0]
}
func containsString(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
