package config

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// Config holds all configuration parameters for Home Network Watch.
type Config struct {
	Pihole        PiholeConfig        `json:"pihole"`
	Wireguard     WireguardConfig     `json:"wireguard"`
	AnomalyEngine AnomalyEngineConfig `json:"anomaly_engine"`
	Storage       StorageConfig       `json:"storage"`
	PollInterval  int                 `json:"poll_interval_seconds,omitempty"` // Default 300s (5 min)
}

// PiholeConfig holds Pi-hole collector settings.
type PiholeConfig struct {
	Enabled bool   `json:"enabled"`
	URL     string `json:"url"`
	Token   string `json:"token"`
}

// WireguardConfig holds WireGuard collector settings.
type WireguardConfig struct {
	Enabled   bool   `json:"enabled"`
	Interface string `json:"interface"` // e.g. "wg0" or "" for all
}

// AnomalyEngineConfig holds anomaly detection thresholds.
type AnomalyEngineConfig struct {
	DNSSpikeThresholdPercent float64 `json:"dns_spike_threshold_percent"` // e.g. 200 (%)
	AlertCooldownMinutes     int     `json:"alert_cooldown_minutes"`      // e.g. 60
	WGInactivityDays         int     `json:"wg_inactivity_days"`          // e.g. 30 days before reconnect alert
}

// StorageConfig holds local SQLite storage settings.
type StorageConfig struct {
	DBPath        string `json:"db_path"`
	RetentionDays int    `json:"retention_days"`
}

// DefaultConfig returns a safe, sensible default configuration.
func DefaultConfig() *Config {
	homeDir, err := os.UserHomeDir()
	dbPath := "hnw.db"
	if err == nil {
		dataDir := filepath.Join(homeDir, ".local", "share", "hnw")
		dbPath = filepath.Join(dataDir, "hnw.db")
	}

	return &Config{
		Pihole: PiholeConfig{
			Enabled: true,
			URL:     "http://pi.hole",
			Token:   "",
		},
		Wireguard: WireguardConfig{
			Enabled:   true,
			Interface: "wg0",
		},
		AnomalyEngine: AnomalyEngineConfig{
			DNSSpikeThresholdPercent: 200.0,
			AlertCooldownMinutes:     60,
			WGInactivityDays:         30,
		},
		Storage: StorageConfig{
			DBPath:        dbPath,
			RetentionDays: 30,
		},
		PollInterval: 300,
	}
}

// Load reads and parses configuration from a JSON file, applying environment overrides.
func Load(path string) (*Config, error) {
	cfg := DefaultConfig()

	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("reading config file %s: %w", path, err)
		}
		if err := json.Unmarshal(data, cfg); err != nil {
			return nil, fmt.Errorf("parsing config file %s: %w", path, err)
		}
	}

	// Environment variable overrides
	if token := os.Getenv("HNW_PIHOLE_TOKEN"); token != "" {
		cfg.Pihole.Token = token
	}
	if piURL := os.Getenv("HNW_PIHOLE_URL"); piURL != "" {
		cfg.Pihole.URL = piURL
	}
	if dbPath := os.Getenv("HNW_DB_PATH"); dbPath != "" {
		cfg.Storage.DBPath = dbPath
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	return cfg, nil
}

// Validate checks the configuration for semantic errors.
func (c *Config) Validate() error {
	if c.Pihole.Enabled {
		if c.Pihole.URL == "" {
			return fmt.Errorf("pihole.url cannot be empty when pihole is enabled")
		}
		parsed, err := url.Parse(c.Pihole.URL)
		if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") {
			return fmt.Errorf("pihole.url must be a valid http or https URL: %s", c.Pihole.URL)
		}
	}

	if c.AnomalyEngine.DNSSpikeThresholdPercent < 10.0 {
		c.AnomalyEngine.DNSSpikeThresholdPercent = 200.0
	}
	if c.AnomalyEngine.AlertCooldownMinutes <= 0 {
		c.AnomalyEngine.AlertCooldownMinutes = 60
	}
	if c.AnomalyEngine.WGInactivityDays <= 0 {
		c.AnomalyEngine.WGInactivityDays = 30
	}
	if c.Storage.RetentionDays <= 0 {
		c.Storage.RetentionDays = 30
	}
	if strings.TrimSpace(c.Storage.DBPath) == "" {
		c.Storage.DBPath = "hnw.db"
	}
	if c.PollInterval <= 0 {
		c.PollInterval = 300
	}

	return nil
}

// RedactedToken returns a masked representation of the Pi-hole token.
func (c *Config) RedactedToken() string {
	if c.Pihole.Token == "" {
		return "<none>"
	}
	if len(c.Pihole.Token) <= 4 {
		return "****"
	}
	return c.Pihole.Token[:2] + strings.Repeat("*", len(c.Pihole.Token)-4) + c.Pihole.Token[len(c.Pihole.Token)-2:]
}
