// Package policy implements the rule evaluation engine for LIAS.
//
// File:    apps/lias/internal/policy/engine.go
// Version: 2.4
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

// GetPolicy retrieves a specific policy by its ID.
// FIX: Added missing method required by handlers.ToggleVacationMode
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

    // 2b. GLOBAL ALLOW OVERRIDE
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
        if !p.Enabled {
            continue
        }
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
    var bestTagPol *models.Policy
    for _, tagID := range d.Tags {
        for _, p := range e.policies {
            if !p.Enabled {
                continue
            }
            if p.Type == models.PolicyTypeTag && p.TargetID == tagID {
                if bestTagPol == nil || p.Priority > bestTagPol.Priority {
                    pCopy := p
                    bestTagPol = &pCopy
                }
            }
        }
    }
    if bestTagPol != nil {
        return *bestTagPol
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
        if !globalPol.Enabled && globalPol.Action == models.ActionBlock {
            // If disabled, we skip it. But if it's enabled and Block, we return Block.
        } else if globalPol.Enabled && globalPol.Action == models.ActionBlock {
            return models.ActionBlock
        }

        // 2b. Global Allow override
        if globalPol.Enabled && globalPol.Action == models.ActionAllow {
            return models.ActionAllow
        }
    }

    // 3. Evaluate Device-Specific Policies
    var bestDevPolicy *models.Policy
    for _, p := range e.policies {
        if !p.Enabled {
            continue
        }
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
    var bestTagPolicy *models.Policy
    for _, tagID := range d.Tags {
        for _, p := range e.policies {
            if !p.Enabled {
                continue
            }
            if p.Type == models.PolicyTypeTag && p.TargetID == tagID {
                if bestTagPolicy == nil || p.Priority > bestTagPolicy.Priority {
                    pCopy := p
                    bestTagPolicy = &pCopy
                }
            }
        }
    }

    if bestTagPolicy != nil {
        if bestTagPolicy.Action == models.ActionSchedule && schedEval != nil {
            return schedEval.EvaluateBundle(bestTagPolicy.GetScheduleIDs())
        }
        return bestTagPolicy.Action
    }

    // 5. Fallback to Global Default Policy
    if globalPol, ok := e.policies["global_default"]; ok {
        if globalPol.Enabled && globalPol.Action == models.ActionSchedule && schedEval != nil {
            return schedEval.EvaluateBundle(globalPol.GetScheduleIDs())
        }
        return globalPol.Action
    }

    return models.ActionAllow
}
