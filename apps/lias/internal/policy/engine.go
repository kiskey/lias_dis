// Package policy implements the evaluation engine for LIAS.
// It determines the effective action for a device based on tag, global,
// and device-specific rules.
//
// File:    apps/lias/internal/policy/engine.go
// Version: 1.2
package policy

import (
    stdsync "sync"

    liasSync "github.com/user/lias-dis/apps/lias/internal/sync"
    "github.com/user/lias-dis/shared/models"
)

// PolicyEvaluator is the interface for evaluating the final action of a device.
// Exported so the nftables builder can consume it without cyclic dependencies.
type PolicyEvaluator interface {
    EvaluateAction(d *liasSync.LocalDevice, sched ScheduleEvaluator) models.Action
}

// ScheduleEvaluator is implemented by the schedule engine to resolve
// scheduled actions in real-time.
type ScheduleEvaluator interface {
    EvaluateNow(schedID string) models.Action
}

// Engine manages the collection of policies and evaluates them for devices.
type Engine struct {
    mu       stdsync.RWMutex
    policies map[string]models.Policy
}

// NewEngine initializes the policy engine with a default global allow policy.
func NewEngine() *Engine {
    return &Engine{
        policies: map[string]models.Policy{
            "global_default": {
                ID:       "global_default",
                Name:     "Global Default",
                Type:     models.PolicyTypeGlobal,
                Action:   models.ActionAllow,
                Priority: 0,
            },
        },
    }
}

// UpsertPolicy adds or updates a policy in the engine.
func (e *Engine) UpsertPolicy(p models.Policy) {
    e.mu.Lock()
    defer e.mu.Unlock()
    e.policies[p.ID] = p
}

// DeletePolicy removes a policy from the engine.
func (e *Engine) DeletePolicy(id string) {
    e.mu.Lock()
    defer e.mu.Unlock()
    delete(e.policies, id)
}

// ListPolicies returns all configured policies.
func (e *Engine) ListPolicies() []models.Policy {
    e.mu.RLock()
    defer e.mu.RUnlock()
    list := make([]models.Policy, 0, len(e.policies))
    for _, p := range e.policies {
        list = append(list, p)
    }
    return list
}

// GetEffectivePolicy determines the highest precedence policy applicable to the device.
func (e *Engine) GetEffectivePolicy(d *liasSync.LocalDevice) models.Policy {
    e.mu.RLock()
    defer e.mu.RUnlock()

    // 0. Infrastructure short-circuit (Never blocked)
    if len(d.Tags) > 0 && d.Tags[0] == "infrastructure" {
        return models.Policy{
            ID:     "infrastructure_override",
            Name:   "Infrastructure Override",
            Type:   models.PolicyTypeTag,
            Action: models.ActionAllow,
        }
    }

    // 1. Device-specific policy
    var bestDevPolicy *models.Policy
    for _, p := range e.policies {
        if p.Type == models.PolicyTypeDevice && p.TargetID == d.PDID {
            if bestDevPolicy == nil || p.Priority > bestDevPolicy.Priority {
                pp := p
                bestDevPolicy = &pp
            }
        }
    }
    if bestDevPolicy != nil {
        return *bestDevPolicy
    }

    // 2. Tag policy
    if len(d.Tags) > 0 {
        tagID := d.Tags[0]
        var bestTagPolicy *models.Policy
        for _, p := range e.policies {
            if p.Type == models.PolicyTypeTag && p.TargetID == tagID {
                if bestTagPolicy == nil || p.Priority > bestTagPolicy.Priority {
                    pp := p
                    bestTagPolicy = &pp
                }
            }
        }
        if bestTagPolicy != nil {
            return *bestTagPolicy
        }
    }

    // 3. Global default
    var bestGlobalPolicy *models.Policy
    for _, p := range e.policies {
        if p.Type == models.PolicyTypeGlobal {
            if bestGlobalPolicy == nil || p.Priority > bestGlobalPolicy.Priority {
                pp := p
                bestGlobalPolicy = &pp
            }
        }
    }
    if bestGlobalPolicy != nil {
        return *bestGlobalPolicy
    }

    // 4. Generic fallback (fail-open)
    return models.Policy{
        ID:     "fallback",
        Name:   "Fallback Allow",
        Type:   models.PolicyTypeGlobal,
        Action: models.ActionAllow,
    }
}

// EvaluateAction resolves the final action (allow/block) for a device.
// Satisfies the PolicyEvaluator interface.
func (e *Engine) EvaluateAction(d *liasSync.LocalDevice, schedEval ScheduleEvaluator) models.Action {
    p := e.GetEffectivePolicy(d)

    if p.Action == models.ActionSchedule {
        if p.ScheduleID == nil || schedEval == nil {
            return models.ActionBlock // Fail-closed per §6.4
        }
        return schedEval.EvaluateNow(*p.ScheduleID)
    }

    return p.Action
}
