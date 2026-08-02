// Package tags manages the built-in and custom device tags for LIAS.
//
// File:    apps/lias/internal/tags/manager.go
// Version: 1.4
package tags

import (
	"fmt"
	"strings"
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

// Manager handles available tags and their evaluation precedence.
type Manager struct {
	mu   sync.RWMutex
	tags []Tag
}

// NewManager initializes the tag manager with standard built-in tag presets.
func NewManager() *Manager {
	return &Manager{
		tags: []Tag{
			{ID: "infrastructure", Name: "Infrastructure", Color: "#8e8e93", Precedence: 100, Builtin: true},
			{ID: "work", Name: "Work Devices", Color: "#5856d6", Precedence: 90, Builtin: true},
			{ID: "kids", Name: "Kids Devices", Color: "#ff9500", Precedence: 80, Builtin: true},
			{ID: "gaming", Name: "Gaming Consoles", Color: "#ff2d55", Precedence: 70, Builtin: true},
			{ID: "streaming", Name: "Streaming Devices", Color: "#af52de", Precedence: 65, Builtin: true},
			{ID: "mobile", Name: "Mobile Devices", Color: "#0a84ff", Precedence: 60, Builtin: true},
			{ID: "audio", Name: "Audio Devices", Color: "#00c7be", Precedence: 55, Builtin: true},
			{ID: "computers", Name: "Desktops & Laptops", Color: "#32ade6", Precedence: 50, Builtin: true},
			{ID: "smart_home", Name: "Smart Home & Appliances", Color: "#30d158", Precedence: 40, Builtin: true},
			{ID: "printers", Name: "Printers & Scanners", Color: "#a28b55", Precedence: 35, Builtin: true},
			{ID: "servers", Name: "Servers & NAS", Color: "#ffcc00", Precedence: 30, Builtin: true},
			{ID: "guests", Name: "Guest Devices", Color: "#ff3b30", Precedence: 20, Builtin: true},
			{ID: "generic", Name: "Generic Devices", Color: "#636366", Precedence: 0, Builtin: true},
		},
	}
}

// RestoreTag restores a stored tag from persistent storage without mutating its ID or Precedence.
func (m *Manager) RestoreTag(t Tag) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for i, existing := range m.tags {
		if existing.ID == t.ID {
			m.tags[i] = t
			return nil
		}
	}

	m.tags = append(m.tags, t)
	return nil
}

// List returns all available tag groups ordered by precedence.
func (m *Manager) List() []Tag {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]Tag, len(m.tags))
	copy(out, m.tags)
	return out
}

// Create adds a new custom tag group.
func (m *Manager) Create(name, color string) (Tag, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	cleanName := strings.TrimSpace(name)
	if cleanName == "" {
		return Tag{}, fmt.Errorf("tag name cannot be empty")
	}

	tagID := strings.ToLower(strings.ReplaceAll(cleanName, " ", "_"))

	for _, t := range m.tags {
		if t.ID == tagID || strings.EqualFold(t.Name, cleanName) {
			return Tag{}, fmt.Errorf("tag group '%s' already exists", cleanName)
		}
	}

	t := Tag{
		ID:         tagID,
		Name:       cleanName,
		Color:      color,
		Precedence: 50,
		Builtin:    false,
	}
	m.tags = append(m.tags, t)
	return t, nil
}

// Update modifies an existing custom tag group's name and color.
func (m *Manager) Update(id, name, color string) (Tag, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	for i, t := range m.tags {
		if t.ID == id {
			if t.Builtin {
				return Tag{}, fmt.Errorf("cannot modify built-in system tag '%s'", t.Name)
			}

			if name != "" && name != t.Name {
				m.tags[i].Name = name
			}
			if color != "" {
				m.tags[i].Color = color
			}
			return m.tags[i], nil
		}
	}
	return Tag{}, fmt.Errorf("tag not found")
}

// Delete removes a custom tag. Built-in tags are protected from deletion.
func (m *Manager) Delete(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for i, t := range m.tags {
		if t.ID == id {
			if t.Builtin {
				return fmt.Errorf("cannot delete built-in system tag '%s'", t.Name)
			}
			m.tags = append(m.tags[:i], m.tags[i+1:]...)
			return nil
		}
	}
	return fmt.Errorf("tag not found")
}

// GetDeviceTag retrieves the active tag for a device, falling back to "generic".
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
