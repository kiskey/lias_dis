// Package config handles loading, parsing, and validating configuration
// for the LIAS binary.
//
// File:    apps/lias/internal/config/config.go
// Version: 1.2
package config

import (
    "fmt"
    "os"
    "time"

    "gopkg.in/yaml.v3"
)

type Config struct {
    HTTP      HTTPConfig      `yaml:"http"`
    DIS       DISConfig       `yaml:"dis"`
    Nftables  NftablesConfig  `yaml:"nftables"`
    Schedules SchedulesConfig `yaml:"schedules"`
    Storage   StorageConfig   `yaml:"storage"`
    Logging   LoggingConfig   `yaml:"logging"`
}

type HTTPConfig struct {
    Listen    string `yaml:"listen"`
    AuthToken string `yaml:"auth_token"`
}

type DISConfig struct {
    URL          string        `yaml:"url"`
    AuthToken    string        `yaml:"auth_token"`
    SyncInterval time.Duration `yaml:"sync_interval"`
}

// NftablesConfig defines the isolated netdev table properties.
type NftablesConfig struct {
    Interface        string   `yaml:"interface"`
    TableName        string   `yaml:"table_name"`
    ShutdownBehavior string   `yaml:"shutdown_behavior"`
    LanSubnets       []string `yaml:"lan_subnets"` // NEW: Subnets to bypass block rules (LAN traffic allowed)
}

type SchedulesConfig struct {
    Timezone string `yaml:"timezone"`
}

type StorageConfig struct {
    Path string `yaml:"path"`
}

type LoggingConfig struct {
    Level  string `yaml:"level"`
    Format string `yaml:"format"`
}

func Load(path string) (*Config, error) {
    data, err := os.ReadFile(path)
    if err != nil {
        return nil, fmt.Errorf("failed to read config file: %w", err)
    }

    var cfg Config
    if err := yaml.Unmarshal(data, &cfg); err != nil {
        return nil, fmt.Errorf("failed to parse config file: %w", err)
    }

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
    if cfg.Nftables.ShutdownBehavior == "" {
        cfg.Nftables.ShutdownBehavior = "persist"
    }
    
    // Default LAN subnets if none provided (Standard RFC1918 + IPv6 ULA/Link-Local)
    if len(cfg.Nftables.LanSubnets) == 0 {
        cfg.Nftables.LanSubnets = []string{
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16",
            "fc00::/7",   // IPv6 Unique Local Addresses
            "fe80::/10", // IPv6 Link-Local
        }
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
