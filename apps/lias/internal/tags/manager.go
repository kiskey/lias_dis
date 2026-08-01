// Package tags manages the built-in and custom device tags for LIAS.
// It enforces the one-tag-per-device rule and handles tag precedence.
//
// File:    apps/lias/internal/tags/manager.go
// Version: 1.0
package tags

import (
    "fmt"
    "sync"
)

// Tag represents a classification label applied to devices.
type Tag struct {
    ID         string `json:"id"`
    Name       string `json:"name"`
    Color      string `json:"color"`
    Precedence int    `json:"precedence"`
    Builtin    bool   `json:"builtin"`
}

// Manager handles the collection of available tags and their precedence.
type Manager struct {
    mu   sync.RWMutex
    tags []Tag
}

// NewManager initializes the tag manager with built-in tags.
func NewManager() *Manager {
    return &Manager{
        tags: []Tag{
            {ID: "infrastructure", Name: "Infrastructure", Color: "#8e8e93", Precedence: 100, Builtin: true},
            {ID: "generic", Name: "Generic", Color: "#d1d1d6", Precedence: 0, Builtin: true},
        },
    }
}

// List returns all available tags.
func (m *Manager) List() []Tag {
    m.mu.RLock()
    defer m.mu.RUnlock()
    out := make([]Tag, len(m.tags))
    copy(out, m.tags)
    return out
}

// Create adds a new custom tag.
func (m *Manager) Create(name, color string) (Tag, error) {
    m.mu.Lock()
    defer m.mu.Unlock()

    if name == "" {
        return Tag{}, fmt.Errorf("tag name cannot be empty")
    }

    for _, t := range m.tags {
        if t.Name == name {
            return Tag{}, fmt.Errorf("tag with name '%s' already exists", name)
        }
    }

    t := Tag{
        ID:         name, // Using name as ID for simplicity in v1.0
        Name:       name,
        Color:      color,
        Precedence: 50, // Default precedence for custom tags
        Builtin:    false,
    }
    m.tags = append(m.tags, t)
    return t, nil
}

// Delete removes a custom tag. Built-in tags cannot be deleted.
func (m *Manager) Delete(id string) error {
    m.mu.Lock()
    defer m.mu.Unlock()

    for i, t := range m.tags {
        if t.ID == id {
            if t.Builtin {
                return fmt.Errorf("cannot delete built-in tag")
            }
            m.tags = append(m.tags[:i], m.tags[i+1:]...)
            return nil
        }
    }
    return fmt.Errorf("tag not found")
}

// SetPrecedence updates the precedence of tags based on an ordered list of IDs.
// The earlier the ID appears in the slice, the higher its precedence.
func (m *Manager) SetPrecedence(orderedIDs []string) error {
    m.mu.Lock()
    defer m.mu.Unlock()

    tagMap := make(map[string]Tag)
    for _, t := range m.tags {
        tagMap[t.ID] = t
    }

    for i, id := range orderedIDs {
        if t, ok := tagMap[id]; ok {
            t.Precedence = len(orderedIDs) - i
            tagMap[id] = t
        }
    }

    m.tags = make([]Tag, 0, len(tagMap))
    for _, t := range tagMap {
        m.tags = append(m.tags, t)
    }
    return nil
}

// GetDeviceTag retrieves the active tag for a device.
// Enforces the one-tag-per-device rule by returning the first tag in the list,
// or "generic" if the list is empty or the tag is unknown.
func (m *Manager) GetDeviceTag(tags []string) string {
    if len(tags) > 0 {
        tagID := tags[0]
        m.mu.RLock()
        defer m.mu.RUnlock()
        for _, t := range m.tags {
            if t.ID == tagID {
                return tagID
            }
        }
    }
    return "generic"
}
