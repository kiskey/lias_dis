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

    // 4. TAG-GROUP POLICIES (MATH-06 Fix: Fail-Closed OR Model)
    var hasAllowTag bool
    var tagSchedIDs []string
    for _, tagID := range d.Tags {
        for _, p := range e.policies {
            if !p.Enabled {
                continue
            }
            if p.Type == models.PolicyTypeTag && p.TargetID == tagID {
                switch p.Action {
                case models.ActionBlock:
                    return models.Policy{
                        ID:     "tag_block_override",
                        Name:   "Tag Block (" + tagID + ")",
                        Type:   models.PolicyTypeTag,
                        Action: models.ActionBlock,
                    }
                case models.ActionAllow:
                    hasAllowTag = true
                case models.ActionSchedule:
                    tagSchedIDs = append(tagSchedIDs, p.GetScheduleIDs()...)
                }
            }
        }
    }

    if hasAllowTag {
        return models.Policy{
            ID:     "tag_allow_override",
            Name:   "Tag Allow Override",
            Type:   models.PolicyTypeTag,
            Action: models.ActionAllow,
        }
    }

    if len(tagSchedIDs) > 0 {
        return models.Policy{
            ID:          "tag_schedule_bundle",
            Name:        "Tag Schedule Bundle",
            Type:        models.PolicyTypeTag,
            Action:      models.ActionSchedule,
            ScheduleIDs: tagSchedIDs,
        }
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

// EvaluateAction resolves final action for a device record using strict
// precedence hierarchy.
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

    // 2. Global Kill-Switch / Allow Override
    if globalPol, ok := e.policies["global_default"]; ok {
        if globalPol.Enabled && globalPol.Action == models.ActionBlock {
            return models.ActionBlock
        }
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

    // 4. Evaluate Tag-Group Policies (MATH-06 Fix: Fail-Closed OR Model)
    var hasAllowTag bool
    var tagSchedIDs []string
    for _, tagID := range d.Tags {
        for _, p := range e.policies {
            if !p.Enabled {
                continue
            }
            if p.Type == models.PolicyTypeTag && p.TargetID == tagID {
                switch p.Action {
                case models.ActionBlock:
                    return models.ActionBlock
                case models.ActionAllow:
                    hasAllowTag = true
                case models.ActionSchedule:
                    tagSchedIDs = append(tagSchedIDs, p.GetScheduleIDs()...)
                }
            }
        }
    }

    if hasAllowTag {
        return models.ActionAllow
    }

    if len(tagSchedIDs) > 0 && schedEval != nil {
        return schedEval.EvaluateBundle(tagSchedIDs)
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
