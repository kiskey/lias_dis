// Package policy implements the rule evaluation engine for LIAS.
//
// File:    apps/lias/internal/policy/engine.go
// Version: 1.6
package policy

import (
	"sync"

	liasSync "github.com/user/lias-dis/apps/lias/internal/sync"
	"github.com/user/lias-dis/shared/models"
)

type PolicyEvaluator interface {
	EvaluateAction(d *liasSync.LocalDevice, sched ScheduleEvaluator) models.Action
}

type ScheduleEvaluator interface {
	EvaluateNow(schedID string) models.Action
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
				Action:   models.ActionAllow,
				Priority: 0,
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

func (e *Engine) ListPolicies() []models.Policy {
	e.mu.RLock()
	defer e.mu.RUnlock()

	list := make([]models.Policy, 0, len(e.policies))
	for _, p := range e.policies {
		list = append(list, p)
	}
	return list
}

func (e *Engine) GetEffectivePolicy(d *liasSync.LocalDevice) models.Policy {
	if d == nil {
		return models.Policy{ID: "fallback", Action: models.ActionAllow}
	}

	e.mu.RLock()
	defer e.mu.RUnlock()

	// 1. INFRASTRUCTURE IMMUNITY CHECK
	for _, t := range d.Tags {
		if t == "infrastructure" {
			return models.Policy{
				ID:     "infrastructure_override",
				Name:   "Infrastructure Immunity",
				Type:   models.PolicyTypeTag,
				Action: models.ActionAllow,
			}
		}
	}

	// 2. GLOBAL KILL-SWITCH CHECK
	globalPol, hasGlobal := e.policies["global_default"]
	if hasGlobal && globalPol.Action == models.ActionBlock {
		return models.Policy{
			ID:     "global_killswitch",
			Name:   "Global Access Switch (Block All)",
			Type:   models.PolicyTypeGlobal,
			Action: models.ActionBlock,
		}
	}

	// 3. DEVICE-SPECIFIC POLICY
	var bestDevPolicy *models.Policy
	for _, p := range e.policies {
		if p.Type == models.PolicyTypeDevice && p.TargetID == d.PDID {
			if bestDevPolicy == nil || p.Priority > bestDevPolicy.Priority {
				pCopy := p
				bestDevPolicy = &pCopy
			}
		}
	}
	if bestDevPolicy != nil {
		return *bestDevPolicy
	}

	// 4. TAG-GROUP POLICIES (Supports multiple policies/schedules per tag group)
	var tagPolicies []models.Policy
	for _, tagID := range d.Tags {
		for _, p := range e.policies {
			if p.Type == models.PolicyTypeTag && p.TargetID == tagID {
				tagPolicies = append(tagPolicies, p)
			}
		}
	}

	if len(tagPolicies) > 0 {
		bestTagPol := tagPolicies[0]
		for _, p := range tagPolicies {
			if p.Priority > bestTagPol.Priority {
				bestTagPol = p
			}
		}
		return bestTagPol
	}

	// 5. GLOBAL POLICY FALLBACK
	if hasGlobal {
		return globalPol
	}

	return models.Policy{
		ID:     "fallback",
		Name:   "Fallback Allow",
		Type:   models.PolicyTypeGlobal,
		Action: models.ActionAllow,
	}
}

// EvaluateAction resolves final action, evaluating ALL policies attached to the device's tag group.
func (e *Engine) EvaluateAction(d *liasSync.LocalDevice, schedEval ScheduleEvaluator) models.Action {
	if d == nil {
		return models.ActionAllow
	}

	// Infrastructure immunity
	if d.HasTag("infrastructure") {
		return models.ActionAllow
	}

	e.mu.RLock()
	defer e.mu.RUnlock()

	// Global kill-switch check
	if globalPol, ok := e.policies["global_default"]; ok && globalPol.Action == models.ActionBlock {
		return models.ActionBlock
	}

	// Evaluate device policies
	for _, p := range e.policies {
		if p.Type == models.PolicyTypeDevice && p.TargetID == d.PDID {
			if p.Action == models.ActionSchedule && p.ScheduleID != nil && schedEval != nil {
				return schedEval.EvaluateNow(*p.ScheduleID)
			}
			return p.Action
		}
	}

	// Evaluate ALL policies attached to device's Tag Groups
	var tagActions []models.Action
	for _, tagID := range d.Tags {
		for _, p := range e.policies {
			if p.Type == models.PolicyTypeTag && p.TargetID == tagID {
				act := p.Action
				if act == models.ActionSchedule && p.ScheduleID != nil && schedEval != nil {
					act = schedEval.EvaluateNow(*p.ScheduleID)
				}
				tagActions = append(tagActions, act)
			}
		}
	}

	// Fail-Closed Rule for multiple tag policies: If ANY attached policy/schedule resolves to BLOCK, drop traffic.
	if len(tagActions) > 0 {
		for _, act := range tagActions {
			if act == models.ActionBlock {
				return models.ActionBlock
			}
		}
		return models.ActionAllow
	}

	// Fallback to global policy action
	if globalPol, ok := e.policies["global_default"]; ok {
		if globalPol.Action == models.ActionSchedule && globalPol.ScheduleID != nil && schedEval != nil {
			return schedEval.EvaluateNow(*globalPol.ScheduleID)
		}
		return globalPol.Action
	}

	return models.ActionAllow
}
