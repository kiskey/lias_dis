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

func TestEnrichmentResourceDefaults(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("discovery: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	enr := cfg.Discovery.Enrichment
	if enr.WorkerCount != 2 || enr.QueueSize != 128 || enr.PrimaryTimeout != 5*time.Second || enr.FallbackTimeout != 20*time.Second {
		t.Fatalf("unexpected orchestrator defaults: %#v", enr)
	}
	if enr.NmapHostTimeout != 10*time.Second || enr.NmapProcessTimeout != 15*time.Second || enr.NmapMaxRate != 50 || enr.NmapMaxOutputBytes != 1<<20 || enr.NmapOSDetection {
		t.Fatalf("unexpected nmap safety defaults: %#v", enr)
	}
}

func TestEnrichmentResourceLimitsRejectUnsafeValues(t *testing.T) {
	cases := []string{
		"worker_count: 9",
		"queue_size: 5000",
		"primary_timeout: 500ms",
		"fallback_timeout: 3s",
		"nmap_host_timeout: 2m",
		"nmap_process_timeout: 5s\n    nmap_host_timeout: 10s",
		"nmap_max_rate: 5000",
		"nmap_max_output_bytes: 1024",
	}
	for _, value := range cases {
		path := filepath.Join(t.TempDir(), "config.yaml")
		data := []byte("discovery:\n  enrichment:\n    " + value + "\n")
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(path); err == nil {
			t.Fatalf("unsafe enrichment configuration accepted: %q", value)
		}
	}
}
