// Package policy implements the rule evaluation engine for LIAS.
//
// File:    apps/lias/internal/policy/engine.go
// Version: 2.2
package policy

import (
    "sync"

    liasSync "github.com/user/lias-dis/apps/lias/internal/sync"
    "github.com/user/lias-dis/shared/models"
)

// Policy Precedence Chain (Enhancement 4.0 §12):
// 1. Infrastructure Immunity — always Allow, cannot be overridden
// 2a. Global Kill-Switch (Block) — overrides all non-infra policies
// 2b. Global Allow Override — overrides all non-infra policies (P5/P7)
// 3. Device-Specific Policy — highest priority non-global policy
// 4. Tag-Group Policy — per-tag policies (fail-closed OR for multiple tags)
// 5. Global Schedule Fallback — when global is Schedule, evaluate global bundle
//
// Key invariant: Global Allow/Block always overrides tag/device schedules.
// Global Schedule defers to per-tag schedules for each tagged group.

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

// NewEngine initializes policy engine with 'global_default' defaulted to ActionSchedule.
func NewEngine() *Engine {
    return &Engine{
        policies: map[string]models.Policy{
            "global_default": {
                ID:       "global_default",
                Name:     "Global Access Switch",
                Type:     models.PolicyTypeGlobal,
                Action:   models.ActionSchedule,
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

    // 2. GLOBAL KILL-SWITCH CHECK (ONLY ActionBlock acts as override)
    globalPol, hasGlobal := e.policies["global_default"]
    if hasGlobal && globalPol.Action == models.ActionBlock {
        return models.Policy{
            ID:     "global_killswitch",
            Name:   "Global Access Switch (Block All)",
            Type:   models.PolicyTypeGlobal,
            Action: models.ActionBlock,
        }
    }

    // 2b. GLOBAL ALLOW OVERRIDE (GAP-L01)
    if hasGlobal && globalPol.Action == models.ActionAllow {
        return models.Policy{
            ID:     "global_allow_override",
            Name:   "Global Access Switch (Allow All)",
            Type:   models.PolicyTypeGlobal,
            Action: models.ActionAllow,
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

    // 4. TAG-GROUP POLICIES
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

// EvaluateAction resolves final action for a device record using strict precedence hierarchy:
// Infrastructure Immunity > Global Kill-Switch (Block) > Global Allow Override > Device Policies > Tag Policies > Global Default Fallback
func (e *Engine) EvaluateAction(d *liasSync.LocalDevice, schedEval ScheduleEvaluator) models.Action {
    if d == nil {
        return models.ActionAllow
    }

    // 1. Infrastructure immunity check
    if d.HasTag("infrastructure") {
        return models.ActionAllow
    }

    e.mu.RLock()
    defer e.mu.RUnlock()

    // 2. Global Kill-Switch Check: ONLY ActionBlock acts as global override
    if globalPol, ok := e.policies["global_default"]; ok {
        if globalPol.Action == models.ActionBlock {
            return models.ActionBlock
        }

        // 2b. NEW: Global Allow override (P5, P7) (GAP-L01)
        // If global is explicitly Allow, all non-infrastructure devices are allowed
        // regardless of their tag/device policies.
        if globalPol.Action == models.ActionAllow {
            return models.ActionAllow
        }
    }

    // 3. Evaluate Device-Specific Policies
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
        if bestDevPolicy.Action == models.ActionSchedule && schedEval != nil {
            return schedEval.EvaluateBundle(bestDevPolicy.GetScheduleIDs())
        }
        return bestDevPolicy.Action
    }

    // 4. Evaluate Tag-Group Policies
    var tagActions []models.Action
    for _, tagID := range d.Tags {
        for _, p := range e.policies {
            if p.Type == models.PolicyTypeTag && p.TargetID == tagID {
                act := p.Action
                if act == models.ActionSchedule && schedEval != nil {
                    act = schedEval.EvaluateBundle(p.GetScheduleIDs())
                }
                tagActions = append(tagActions, act)
            }
        }
    }

    // Fail-Closed Rule for multiple tag policies: If ANY attached policy resolves to BLOCK, drop traffic.
    if len(tagActions) > 0 {
        for _, act := range tagActions {
            if act == models.ActionBlock {
                return models.ActionBlock
            }
        }
        return models.ActionAllow
    }

    // 5. Fallback to Global Default Policy
    if globalPol, ok := e.policies["global_default"]; ok {
        if globalPol.Action == models.ActionSchedule && schedEval != nil {
            return schedEval.EvaluateBundle(globalPol.GetScheduleIDs())
        }
        return globalPol.Action
    }

    return models.ActionAllow
}
