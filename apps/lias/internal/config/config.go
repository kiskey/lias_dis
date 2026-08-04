// Package config handles loading, parsing, and validating configuration
// for the LIAS binary. It expects a YAML file following the structure
// defined in Appendix A of the implementation specification.
//
// File:    apps/lias/internal/config/config.go
// Version: 1.1
package config

import (
    "fmt"
    "os"
    "time"

    "gopkg.in/yaml.v3"
)

// Config represents the root configuration object for LIAS.
type Config struct {
    HTTP      HTTPConfig      `yaml:"http"`
    DIS       DISConfig       `yaml:"dis"`
    Nftables  NftablesConfig  `yaml:"nftables"`
    Schedules SchedulesConfig `yaml:"schedules"`
    Storage   StorageConfig   `yaml:"storage"`
    Logging   LoggingConfig   `yaml:"logging"`
}

// HTTPConfig defines the listen address for the LIAS REST API.
type HTTPConfig struct {
    Listen string `yaml:"listen"`
}

// DISConfig defines connection parameters to the Discovery Intelligence Service.
type DISConfig struct {
    URL          string        `yaml:"url"`
    AuthToken    string        `yaml:"auth_token"`
    SyncInterval time.Duration `yaml:"sync_interval"`
}

// NftablesConfig defines the isolated netdev table properties.
type NftablesConfig struct {
    Interface        string `yaml:"interface"`
    TableName        string `yaml:"table_name"`
    ShutdownBehavior string `yaml:"shutdown_behavior"` // "flush" or "persist"
}

// SchedulesConfig defines the default timezone for schedule evaluation.
type SchedulesConfig struct {
    Timezone string `yaml:"timezone"`
}

// StorageConfig defines the path to the persistent state database.
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
        cfg.HTTP.Listen = ":8081"
    }
    if cfg.DIS.SyncInterval == 0 {
        cfg.DIS.SyncInterval = 30 * time.Second
    }
    if cfg.Nftables.Interface == "" {
        cfg.Nftables.Interface = "eth0"
    }
    if cfg.Nftables.TableName == "" {
        cfg.Nftables.TableName = "lancontrol"
    }
    // GAP-L-H03 Fix: Default to "persist" to prevent fail-open during service restarts
    if cfg.Nftables.ShutdownBehavior == "" {
        cfg.Nftables.ShutdownBehavior = "persist"
    }
    if cfg.Schedules.Timezone == "" {
        cfg.Schedules.Timezone = "UTC"
    }
    if cfg.Storage.Path == "" {
        cfg.Storage.Path = "/var/lib/lias/state.db"
    }
    if cfg.Logging.Level == "" {
        cfg.Logging.Level = "info"
    }
    if cfg.Logging.Format == "" {
        cfg.Logging.Format = "json"
    }

    return &cfg, nil
}
