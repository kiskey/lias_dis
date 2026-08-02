// Package policy implements the rule evaluation engine for LIAS.
//
// File:    apps/lias/internal/policy/engine.go
// Version: 1.4
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

// NewEngine initializes the policy engine with default global policy settings.
func NewEngine() *Engine {
	return &Engine{
		policies: map[string]models.Policy{
			"global_default": {
				ID:       "global_default",
				Name:     "Global Access Switch",
				Type:     models.PolicyTypeGlobal,
				Action:   models.ActionAllow, // Default: Always Allow
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

// GetEffectivePolicy determines the active policy based on strict precedence rules:
//
// RULE 1: Infrastructure Immunity (Infrastructure tagged devices are ALWAYS allowed and immune to global switches)
// RULE 2: Global Kill-Switch Override (If Global Default is set to 'block', non-infrastructure devices are blocked)
// RULE 3: Device-Specific Policy (TargetID == PDID)
// RULE 4: Tag-Group Policy (TargetID in device.Tags)
// RULE 5: Global Default Policy
func (e *Engine) GetEffectivePolicy(d *liasSync.LocalDevice) models.Policy {
	if d == nil {
		return models.Policy{ID: "fallback", Action: models.ActionAllow}
	}

	e.mu.RLock()
	defer e.mu.RUnlock()

	// 1. INFRASTRUCTURE IMMUNITY CHECK
	// Devices tagged as 'infrastructure' are completely immune to global blocks and device rules.
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
	// If Global Policy is explicitly set to 'block' (Global Downtime Switch), it overrides all regular devices.
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

	// 4. TAG-GROUP POLICY (Schedule or Block assigned to entire Tag Group e.g. 'kids')
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

// EvaluateAction resolves the final firewall action (allow or block) for a device.
func (e *Engine) EvaluateAction(d *liasSync.LocalDevice, schedEval ScheduleEvaluator) models.Action {
	p := e.GetEffectivePolicy(d)

	if p.Action == models.ActionSchedule {
		if p.ScheduleID == nil || *p.ScheduleID == "" || schedEval == nil {
			return models.ActionBlock // Fail-closed if schedule reference is broken
		}
		return schedEval.EvaluateNow(*p.ScheduleID)
	}

	return p.Action
}
