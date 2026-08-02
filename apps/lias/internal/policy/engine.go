// Package policy implements the rule evaluation engine for LIAS.
//
// File:    apps/lias/internal/policy/engine.go
// Version: 1.3
package policy

import (
	"sync"

	liasSync "github.com/user/lias-dis/apps/lias/internal/sync"
	"github.com/user/lias-dis/shared/models"
)

// PolicyEvaluator resolves the active firewall action for a target device.
type PolicyEvaluator interface {
	EvaluateAction(d *liasSync.LocalDevice, sched ScheduleEvaluator) models.Action
}

// ScheduleEvaluator resolves time-based schedule rules.
type ScheduleEvaluator interface {
	EvaluateNow(schedID string) models.Action
}

// Engine manages configured policies and evaluates precedence rules.
type Engine struct {
	mu       sync.RWMutex
	policies map[string]models.Policy
}

// NewEngine initializes the policy engine with the global default allow policy.
func NewEngine() *Engine {
	return &Engine{
		policies: map[string]models.Policy{
			"global_default": {
				ID:       "global_default",
				Name:     "Global Default Allow",
				Type:     models.PolicyTypeGlobal,
				Action:   models.ActionAllow,
				Priority: 0,
			},
		},
	}
}

// UpsertPolicy adds or updates a policy record.
func (e *Engine) UpsertPolicy(p models.Policy) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.policies[p.ID] = p
}

// DeletePolicy removes a policy by ID.
func (e *Engine) DeletePolicy(id string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	delete(e.policies, id)
}

// ListPolicies returns a list of all configured policies.
func (e *Engine) ListPolicies() []models.Policy {
	e.mu.RLock()
	defer e.mu.RUnlock()

	list := make([]models.Policy, 0, len(e.policies))
	for _, p := range e.policies {
		list = append(list, p)
	}
	return list
}

// GetEffectivePolicy determines the active policy for a device based on precedence:
// 1. Infrastructure Override (Always Allow)
// 2. Device-Specific Policy (TargetID == PDID)
// 3. Tag-Based Policy (TargetID in device.Tags)
// 4. Global Default Policy
// 5. Hardcoded Fallback Allow
func (e *Engine) GetEffectivePolicy(d *liasSync.LocalDevice) models.Policy {
	if d == nil {
		return models.Policy{ID: "fallback", Action: models.ActionAllow}
	}

	e.mu.RLock()
	defer e.mu.RUnlock()

	// 1. Infrastructure short-circuit override (Never block routers, switches, gateways)
	for _, t := range d.Tags {
		if t == "infrastructure" {
			return models.Policy{
				ID:     "infrastructure_override",
				Name:   "Infrastructure Override",
				Type:   models.PolicyTypeTag,
				Action: models.ActionAllow,
			}
		}
	}

	// 2. Device-Specific Policy
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

	// 3. Tag-Based Policy
	var bestTagPolicy *models.Policy
	for _, tagID := range d.Tags {
		for _, p := range e.policies {
			if p.Type == models.PolicyTypeTag && p.TargetID == tagID {
				if bestTagPolicy == nil || p.Priority > bestTagPolicy.Priority {
					pCopy := p
					bestTagPolicy = &pCopy
				}
			}
		}
	}
	if bestTagPolicy != nil {
		return *bestTagPolicy
	}

	// 4. Global Default Policy
	var bestGlobalPolicy *models.Policy
	for _, p := range e.policies {
		if p.Type == models.PolicyTypeGlobal {
			if bestGlobalPolicy == nil || p.Priority > bestGlobalPolicy.Priority {
				pCopy := p
				bestGlobalPolicy = &pCopy
			}
		}
	}
	if bestGlobalPolicy != nil {
		return *bestGlobalPolicy
	}

	// 5. Fail-safe fallback
	return models.Policy{
		ID:     "fallback",
		Name:   "Fallback Allow",
		Type:   models.PolicyTypeGlobal,
		Action: models.ActionAllow,
	}
}

// EvaluateAction resolves the final firewall action (allow or block) for a device.
func (e *Engine) EvaluateAction(d *liasSync.LocalDevice, schedEval ScheduleEvaluator) models.Action {
	p := e.GetEffectivePolicy(d)

	if p.Action == models.ActionSchedule {
		if p.ScheduleID == nil || *p.ScheduleID == "" || schedEval == nil {
			return models.ActionBlock // Fail-closed per §6.4 if schedule ID is invalid
		}
		return schedEval.EvaluateNow(*p.ScheduleID)
	}

	return p.Action
}
