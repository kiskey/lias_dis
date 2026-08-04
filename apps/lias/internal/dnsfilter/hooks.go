// Package dnsfilter provides hooks for DNS-level domain filtering.
//
// File:    apps/lias/internal/dnsfilter/hooks.go
// Version: 1.0
package dnsfilter

import (
    "strings"
    "sync"
)

// FilterAction determines how a DNS query should be handled.
type FilterAction string

const (
    ActionAllow FilterAction = "allow"
    ActionBlock FilterAction = "block"
)

// DomainRule defines a DNS filtering rule.
type DomainRule struct {
    Domain string      `json:"domain"` // e.g., "example.com", "*.example.com"
    Action FilterAction `json:"action"`
    Scope  string      `json:"scope"`  // "global", "tag:kids", "user:john"
}

// Engine evaluates domain rules against device tags/users.
type Engine struct {
    mu    sync.RWMutex
    rules []DomainRule
}

// NewEngine initializes the DNS filter engine.
func NewEngine() *Engine {
    return &Engine{
        rules: make([]DomainRule, 0),
    }
}

// UpsertRule adds or updates a domain filtering rule.
func (e *Engine) UpsertRule(rule DomainRule) {
    e.mu.Lock()
    defer e.mu.Unlock()

    for i, r := range e.rules {
        if r.Domain == rule.Domain && r.Scope == rule.Scope {
            e.rules[i] = rule
            return
        }
    }
    e.rules = append(e.rules, rule)
}

// ShouldBlock determines if a domain should be blocked for a device with the given tags/user.
func (e *Engine) ShouldBlock(domain string, tags []string, userID string) bool {
    e.mu.RLock()
    defer e.mu.RUnlock()

    domain = strings.ToLower(strings.TrimSpace(domain))
    if domain == "" {
        return false
    }

    for _, rule := range e.rules {
        if rule.Action != ActionBlock {
            continue
        }

        scopeMatch := false
        if rule.Scope == "global" {
            scopeMatch = true
        } else if strings.HasPrefix(rule.Scope, "tag:") {
            for _, t := range tags {
                if "tag:"+t == rule.Scope {
                    scopeMatch = true
                    break
                }
            }
        } else if strings.HasPrefix(rule.Scope, "user:") {
            if "user:"+userID == rule.Scope {
                scopeMatch = true
            }
        }

        if !scopeMatch {
            continue
        }

        // Domain matching (supports wildcards)
        if strings.HasPrefix(rule.Domain, "*.") {
            suffix := rule.Domain[1:] // ".example.com"
            if strings.HasSuffix(domain, suffix) {
                return true
            }
        } else if domain == rule.Domain {
            return true
        }
    }

    return false
}
