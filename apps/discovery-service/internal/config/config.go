// Package config handles loading, parsing, and validating configuration
// for the Discovery Intelligence Service (DIS).
//
// File:    apps/discovery-service/internal/config/config.go
// Version: 1.6 (Renamed Bridge FDB to ARP Table Standard)
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
	Type         string        `yaml:"type"`          // dnsmasq/openwrt/pihole or kea
	LeaseFile    string        `yaml:"lease_file"`    // Local or remote lease path
    LeaseURL  string `yaml:"lease_url"`  // Remote HTTP URL
    SSHHost   string `yaml:"ssh_host"`   // Remote SSH host
    SSHUser   string `yaml:"ssh_user"`   // SSH user
	PollInterval time.Duration `yaml:"poll_interval"` // Defaults to 2m

	// OpenWrt sampling: current AP associations and NUD_REACHABLE neighbours.
    OpenWrtAPEnabled bool `yaml:"openwrt_ap_enabled"`
	NeighborTableEnabled bool `yaml:"neighbor_table_enabled"`
	ArpTableEnabled      bool `yaml:"arp_table_enabled"` // Deprecated compatibility alias.
}

// EnrichmentConfig enables or disables on-demand enrichers.
type EnrichmentConfig struct {
    NmapEnabled        bool          `yaml:"nmap_enabled"`
    AvahiEnabled       bool          `yaml:"avahi_enabled"`
    SSDPEnabled        bool          `yaml:"ssdp_enabled"`
    NetbiosEnabled     bool          `yaml:"netbios_enabled"`
    TLSEnabled         bool          `yaml:"tls_enabled"`
    UnknownDeviceScan  bool          `yaml:"unknown_device_scan"`
    ValidationInterval time.Duration `yaml:"validation_interval"`
	WorkerCount        int           `yaml:"worker_count"`
	QueueSize          int           `yaml:"queue_size"`
	PrimaryTimeout     time.Duration `yaml:"primary_timeout"`
	FallbackTimeout    time.Duration `yaml:"fallback_timeout"`
	NmapHostTimeout    time.Duration `yaml:"nmap_host_timeout"`
	NmapProcessTimeout time.Duration `yaml:"nmap_process_timeout"`
	NmapMaxRate        int           `yaml:"nmap_max_rate"`
	NmapMaxOutputBytes int64         `yaml:"nmap_max_output_bytes"`
	NmapOSDetection    bool          `yaml:"nmap_os_detection"`
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
	if cfg.Discovery.Enrichment.WorkerCount == 0 {
		cfg.Discovery.Enrichment.WorkerCount = 2
	}
	if cfg.Discovery.Enrichment.QueueSize == 0 {
		cfg.Discovery.Enrichment.QueueSize = 128
	}
	if cfg.Discovery.Enrichment.PrimaryTimeout == 0 {
		cfg.Discovery.Enrichment.PrimaryTimeout = 5 * time.Second
	}
	if cfg.Discovery.Enrichment.FallbackTimeout == 0 {
		cfg.Discovery.Enrichment.FallbackTimeout = 20 * time.Second
	}
	if cfg.Discovery.Enrichment.NmapHostTimeout == 0 {
		cfg.Discovery.Enrichment.NmapHostTimeout = 10 * time.Second
	}
	if cfg.Discovery.Enrichment.NmapProcessTimeout == 0 {
		cfg.Discovery.Enrichment.NmapProcessTimeout = 15 * time.Second
	}
	if cfg.Discovery.Enrichment.NmapMaxRate == 0 {
		cfg.Discovery.Enrichment.NmapMaxRate = 50
	}
	if cfg.Discovery.Enrichment.NmapMaxOutputBytes == 0 {
		cfg.Discovery.Enrichment.NmapMaxOutputBytes = 1 << 20
	}
	if err := validateEnrichment(cfg.Discovery.Enrichment); err != nil {
		return nil, err
	}
	if cfg.Discovery.DHCP.PollInterval == 0 {
		cfg.Discovery.DHCP.PollInterval = 2 * time.Minute
	}
	if cfg.Discovery.DHCP.PollInterval < 30*time.Second {
		return nil, fmt.Errorf("discovery.dhcp.poll_interval must be at least 30s")
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

func validateEnrichment(cfg EnrichmentConfig) error {
	if cfg.WorkerCount < 1 || cfg.WorkerCount > 8 {
		return fmt.Errorf("discovery.enrichment.worker_count must be between 1 and 8")
	}
	if cfg.QueueSize < 1 || cfg.QueueSize > 4096 {
		return fmt.Errorf("discovery.enrichment.queue_size must be between 1 and 4096")
	}
	if cfg.PrimaryTimeout < time.Second || cfg.PrimaryTimeout > time.Minute {
		return fmt.Errorf("discovery.enrichment.primary_timeout must be between 1s and 1m")
	}
	if cfg.FallbackTimeout < 5*time.Second || cfg.FallbackTimeout > 2*time.Minute {
		return fmt.Errorf("discovery.enrichment.fallback_timeout must be between 5s and 2m")
	}
	if cfg.NmapHostTimeout < time.Second || cfg.NmapHostTimeout > time.Minute {
		return fmt.Errorf("discovery.enrichment.nmap_host_timeout must be between 1s and 1m")
	}
	if cfg.NmapProcessTimeout < cfg.NmapHostTimeout || cfg.NmapProcessTimeout > 2*time.Minute {
		return fmt.Errorf("discovery.enrichment.nmap_process_timeout must be >= nmap_host_timeout and <= 2m")
	}
	if cfg.NmapMaxRate < 1 || cfg.NmapMaxRate > 1000 {
		return fmt.Errorf("discovery.enrichment.nmap_max_rate must be between 1 and 1000 packets/s")
	}
	if cfg.NmapMaxOutputBytes < 64<<10 || cfg.NmapMaxOutputBytes > 16<<20 {
		return fmt.Errorf("discovery.enrichment.nmap_max_output_bytes must be between 65536 and 16777216")
	}
	return nil
}
