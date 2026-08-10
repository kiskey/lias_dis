// Package policy implements the rule evaluation engine for LIAS.
//
// File:    apps/lias/internal/policy/engine.go
// Version: 2.6 (Added SweepExpired for Extend Access temporary policy lifecycle)
package policy

import (
	"strings"
	"sync"
	"time"

	liasSync "github.com/user/lias-dis/apps/lias/internal/sync"
	"github.com/user/lias-dis/shared/models"
)

type PolicyEvaluator interface {
	EvaluateAction(d *liasSync.LocalDevice, sched ScheduleEvaluator) models.Action
}

type ScheduleEvaluator interface {
	EvaluateNow(schedID string) models.Action
	EvaluateBundle(schedIDs []string) models.Action
}

type Engine struct {
	mu       sync.RWMutex
	policies map[string]models.Policy
}

func NewEngine() *Engine {
	return &Engine{
		policies: map[string]models.Policy{
			"global_default": {
				ID:       "global_default",
				Name:     "Global Access Switch",
				Type:     models.PolicyTypeGlobal,
				Action:   models.ActionSchedule,
				Priority: 0,
				Enabled:  true,
			},
		},
	}
}

func (e *Engine) UpsertPolicy(p models.Policy) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.policies[p.ID] = p
}

func (e *Engine) DeletePolicy(id string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	delete(e.policies, id)
}

func (e *Engine) GetPolicy(id string) (models.Policy, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	p, exists := e.policies[id]
	return p, exists
}

func (e *Engine) ListPolicies() []models.Policy {
	e.mu.RLock()
	defer e.mu.RUnlock()

	list := make([]models.Policy, 0, len(e.policies))
	for _, p := range e.policies {
		list = append(list, p)
	}
	return list
}

// ReconcileDeviceIdentity replaces all live policies targeting either side of
// a completed migration with the transaction's authoritative target set.
func (e *Engine) ReconcileDeviceIdentity(oldPDID, newPDID string, policies []models.Policy) {
	e.mu.Lock()
	defer e.mu.Unlock()
	for id, policy := range e.policies {
		if policy.Type == models.PolicyTypeDevice && (policy.TargetID == oldPDID || policy.TargetID == newPDID) {
			delete(e.policies, id)
		}
	}
	for _, policy := range policies {
		e.policies[policy.ID] = policy
	}
}

func policyActionRank(action models.Action) int {
	switch action {
	case models.ActionBlock:
		return 3
	case models.ActionSchedule:
		return 2
	case models.ActionAllow:
		return 1
	default:
		return 0
	}
}

func preferPolicy(candidate models.Policy, best *models.Policy) bool {
	if best == nil {
		return true
	}
	if candidate.Priority != best.Priority {
		return candidate.Priority > best.Priority
	}
	if policyActionRank(candidate.Action) != policyActionRank(best.Action) {
		return policyActionRank(candidate.Action) > policyActionRank(best.Action)
	}
	if !candidate.UpdatedAt.Equal(best.UpdatedAt) {
		return candidate.UpdatedAt.After(best.UpdatedAt)
	}
	return candidate.ID < best.ID
}

func (e *Engine) bestPolicyForTargetLocked(pt models.PolicyType, target string) *models.Policy {
	var best *models.Policy
	for _, p := range e.policies {
		if !p.Enabled || p.Type != pt || p.TargetID != target {
			continue
		}
		if preferPolicy(p, best) {
			x := p
			best = &x
		}
	}
	return best
}

func (e *Engine) GetEffectiveTagPolicy(tagID string) (models.Policy, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	best := e.bestPolicyForTargetLocked(models.PolicyTypeTag, tagID)
	if best == nil {
		return models.Policy{}, false
	}
	return *best, true
}

func (e *Engine) tagOutcomeLocked(tags []string) (hasBlock, hasAllow bool, scheduleIDs []string) {
	for _, tag := range tags {
		best := e.bestPolicyForTargetLocked(models.PolicyTypeTag, tag)
		if best == nil {
			continue
		}
		switch best.Action {
		case models.ActionBlock:
			hasBlock = true
		case models.ActionAllow:
			hasAllow = true
		case models.ActionSchedule:
			ids := best.GetScheduleIDs()
			if len(ids) == 0 {
				hasBlock = true
			} else {
				scheduleIDs = append(scheduleIDs, ids...)
			}
		default:
			hasBlock = true
		}
	}
	return
}

func (e *Engine) GetEffectivePolicy(d *liasSync.LocalDevice) models.Policy {
	if d == nil {
		return models.Policy{ID: "fallback", Action: models.ActionAllow}
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	if d.HasTag("infrastructure") {
		return models.Policy{ID: "infrastructure_override", Type: models.PolicyTypeTag, Action: models.ActionAllow}
	}
	gp, has := e.policies["global_default"]
	if has && gp.Enabled && gp.Action == models.ActionBlock {
		return models.Policy{ID: "global_killswitch", Type: models.PolicyTypeGlobal, Action: models.ActionBlock}
	}
	if has && gp.Enabled && gp.Action == models.ActionAllow {
		return models.Policy{ID: "global_allow_override", Type: models.PolicyTypeGlobal, Action: models.ActionAllow}
	}
	if best := e.bestPolicyForTargetLocked(models.PolicyTypeDevice, d.PDID); best != nil {
		return *best
	}
	block, allow, ids := e.tagOutcomeLocked(d.Tags)
	if block {
		return models.Policy{ID: "tag_block_override", Type: models.PolicyTypeTag, Action: models.ActionBlock}
	}
	if allow {
		return models.Policy{ID: "tag_allow_override", Type: models.PolicyTypeTag, Action: models.ActionAllow}
	}
	if len(ids) > 0 {
		return models.Policy{ID: "tag_schedule_bundle", Type: models.PolicyTypeTag, Action: models.ActionSchedule, ScheduleIDs: ids}
	}
	if has {
		return gp
	}
	return models.Policy{ID: "fallback", Type: models.PolicyTypeGlobal, Action: models.ActionAllow}
}

// EvaluateAction resolves final action for a device record using strict
// precedence hierarchy.
func (e *Engine) EvaluateAction(d *liasSync.LocalDevice, sched ScheduleEvaluator) models.Action {
	if d == nil {
		return models.ActionAllow
	}
	if d.HasTag("infrastructure") {
		return models.ActionAllow
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	if gp, ok := e.policies["global_default"]; ok && gp.Enabled {
		if gp.Action == models.ActionBlock {
			return models.ActionBlock
		}
		if gp.Action == models.ActionAllow {
			return models.ActionAllow
		}
	}
	if best := e.bestPolicyForTargetLocked(models.PolicyTypeDevice, d.PDID); best != nil {
		if best.Action == models.ActionSchedule {
			ids := best.GetScheduleIDs()
			if len(ids) == 0 || sched == nil {
				return models.ActionBlock
			}
			return sched.EvaluateBundle(ids)
		}
		if best.Action != models.ActionAllow && best.Action != models.ActionBlock {
			return models.ActionBlock
		}
		return best.Action
	}
	block, allow, ids := e.tagOutcomeLocked(d.Tags)
	if block {
		return models.ActionBlock
	}
	if allow {
		return models.ActionAllow
	}
	if len(ids) > 0 {
		if sched == nil {
			return models.ActionBlock
		}
		return sched.EvaluateBundle(ids)
	}
	if gp, ok := e.policies["global_default"]; ok && gp.Enabled {
		if gp.Action == models.ActionSchedule {
			ids := gp.GetScheduleIDs()
			if len(ids) == 0 {
				return models.ActionAllow
			}
			if sched == nil {
				return models.ActionBlock
			}
			return sched.EvaluateBundle(ids)
		}
		if gp.Action != models.ActionAllow && gp.Action != models.ActionBlock {
			return models.ActionBlock
		}
		return gp.Action
	}
	return models.ActionAllow
}

// SweepExpired removes any policy whose ExpiresAt has passed, and returns
// the IDs of any schedules that were privately owned by those policies
// (so the caller can also delete them via schedEng). A schedule is
// considered "privately owned" if its ID has the sched_pause_ or
// sched_extend_ prefix — i.e. it was synthesized for exactly one
// temporary policy and nothing else references it.
//
// This method is the single authoritative expiry code path for both
// Pause Internet and Extend Access temporary policies. It must be called
// on a periodic ticker (e.g. every 15 seconds) from the server main loop.
func (e *Engine) SweepExpired(now time.Time) (expiredPolicyIDs []string, ownedScheduleIDs []string) {
	e.mu.Lock()
	defer e.mu.Unlock()

	for id, p := range e.policies {
		if p.ExpiresAt != nil && now.After(*p.ExpiresAt) {
			expiredPolicyIDs = append(expiredPolicyIDs, id)
			for _, sid := range p.GetScheduleIDs() {
				if strings.HasPrefix(sid, "sched_pause_") || strings.HasPrefix(sid, "sched_extend_") {
					ownedScheduleIDs = append(ownedScheduleIDs, sid)
				}
			}
			delete(e.policies, id)
		}
	}
	return
}
