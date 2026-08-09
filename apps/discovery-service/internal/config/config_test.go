package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDHCPPollIntervalDefaultAndFloor(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("discovery:\n  dhcp:\n    poll_interval: 2m\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Discovery.DHCP.PollInterval != 2*time.Minute {
		t.Fatalf("unexpected interval: %s", cfg.Discovery.DHCP.PollInterval)
	}
	if err := os.WriteFile(path, []byte("discovery:\n  dhcp:\n    poll_interval: 10s\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("aggressive DHCP polling interval accepted")
	}
}
