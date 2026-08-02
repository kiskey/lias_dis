// Package config handles loading, parsing, and validating configuration
// for the Discovery Intelligence Service (DIS).
//
// File:    apps/discovery-service/internal/config/config.go
// Version: 1.3
package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config represents the root configuration object for DIS.
type Config struct {
	HTTP      HTTPConfig      `yaml:"http"`
	Discovery DiscoveryConfig `yaml:"discovery"`
	Storage   StorageConfig   `yaml:"storage"`
	Logging   LoggingConfig   `yaml:"logging"`
}

// HTTPConfig defines the listen address and optional auth token for the REST API.
type HTTPConfig struct {
	Listen    string `yaml:"listen"`
	AuthToken string `yaml:"auth_token"`
}

// DiscoveryConfig groups all provider and enrichment configurations.
type DiscoveryConfig struct {
	Interface  string           `yaml:"interface"`
	Netlink    NetlinkConfig    `yaml:"netlink"`
	Pihole     PiholeConfig     `yaml:"pihole"`
	DHCP       DHCPConfig       `yaml:"dhcp"`
	Enrichment EnrichmentConfig `yaml:"enrichment"`
}

// NetlinkConfig enables the real-time netlink neighbor provider.
type NetlinkConfig struct {
	Enabled bool `yaml:"enabled"`
}

// PiholeConfig configures the Pi-hole v6 API client.
type PiholeConfig struct {
	Enabled  bool   `yaml:"enabled"`
	URL      string `yaml:"url"`
	Password string `yaml:"password"`
}

// DHCPConfig configures the DHCP lease file parser.
type DHCPConfig struct {
	Enabled   bool   `yaml:"enabled"`
	Type      string `yaml:"type"`       // router, pihole, dnsmasq, kea
	LeaseFile string `yaml:"lease_file"` // Local file path
	LeaseURL  string `yaml:"lease_url"`  // Remote HTTP URL
	SSHHost   string `yaml:"ssh_host"`   // Remote SSH host
	SSHUser   string `yaml:"ssh_user"`   // SSH user
}

// EnrichmentConfig enables or disables on-demand enrichers.
type EnrichmentConfig struct {
	NmapEnabled        bool          `yaml:"nmap_enabled"`
	AvahiEnabled       bool          `yaml:"avahi_enabled"`
	SSDPEnabled        bool          `yaml:"ssdp_enabled"`
	NetbiosEnabled     bool          `yaml:"netbios_enabled"`
	UnknownDeviceScan  bool          `yaml:"unknown_device_scan"`
	ValidationInterval time.Duration `yaml:"validation_interval"`
}

// StorageConfig defines the path to the DIS persistent database file.
type StorageConfig struct {
	Path string `yaml:"path"`
}

// LoggingConfig defines the log output format and verbosity.
type LoggingConfig struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
}

// Load reads the YAML configuration file from the provided path, applies
// default values for missing fields, and returns a populated Config struct.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	// Apply defaults
	if cfg.HTTP.Listen == "" {
		cfg.HTTP.Listen = ":8080"
	}
	if cfg.Discovery.Interface == "" {
		cfg.Discovery.Interface = "eth0"
	}
	if cfg.Discovery.Enrichment.ValidationInterval == 0 {
		cfg.Discovery.Enrichment.ValidationInterval = 24 * time.Hour
	}
	if cfg.Storage.Path == "" {
		cfg.Storage.Path = "/var/lib/dis/state.db"
	}
	if cfg.Logging.Level == "" {
		cfg.Logging.Level = "info"
	}
	if cfg.Logging.Format == "" {
		cfg.Logging.Format = "json"
	}

	return &cfg, nil
}
