package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg == nil {
		t.Fatal("expected non-nil default config")
	}
	if !cfg.Pihole.Enabled {
		t.Errorf("expected Pi-hole to be enabled by default")
	}
	if !cfg.Wireguard.Enabled {
		t.Errorf("expected WireGuard to be enabled by default")
	}
	if cfg.AnomalyEngine.DNSSpikeThresholdPercent != 200.0 {
		t.Errorf("expected DNS spike threshold 200, got %f", cfg.AnomalyEngine.DNSSpikeThresholdPercent)
	}
}

func TestLoadValidConfig(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.json")
	content := `{
		"pihole": {
			"enabled": true,
			"url": "http://192.168.1.100",
			"token": "secret123"
		},
		"wireguard": {
			"enabled": true,
			"interface": "wg0"
		},
		"anomaly_engine": {
			"dns_spike_threshold_percent": 150.0,
			"alert_cooldown_minutes": 30
		},
		"storage": {
			"db_path": "/tmp/test.db",
			"retention_days": 14
		}
	}`
	if err := os.WriteFile(configPath, []byte(content), 0600); err != nil {
		t.Fatalf("failed to write test config: %v", err)
	}

	cfg, err := Load(configPath)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if cfg.Pihole.URL != "http://192.168.1.100" {
		t.Errorf("unexpected URL: %s", cfg.Pihole.URL)
	}
	if cfg.Pihole.Token != "secret123" {
		t.Errorf("unexpected token: %s", cfg.Pihole.Token)
	}
	if cfg.AnomalyEngine.DNSSpikeThresholdPercent != 150.0 {
		t.Errorf("unexpected spike threshold: %f", cfg.AnomalyEngine.DNSSpikeThresholdPercent)
	}
	if cfg.RedactedToken() != "se*****23" {
		t.Errorf("unexpected redacted token: %s", cfg.RedactedToken())
	}
}

func TestLoadEnvOverrides(t *testing.T) {
	os.Setenv("HNW_PIHOLE_TOKEN", "env-token-xyz")
	defer os.Unsetenv("HNW_PIHOLE_TOKEN")

	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if cfg.Pihole.Token != "env-token-xyz" {
		t.Errorf("expected env override token, got: %s", cfg.Pihole.Token)
	}
}

func TestValidateConfigErrors(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Pihole.URL = "ftp://invalid-scheme"
	if err := cfg.Validate(); err == nil {
		t.Errorf("expected error for invalid URL scheme, got nil")
	}
}
