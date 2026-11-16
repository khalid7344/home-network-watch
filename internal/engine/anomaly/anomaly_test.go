package anomaly

import (
	"context"
	"testing"
	"time"

	"github.com/khalid7344/home-network-watch/internal/config"
	"github.com/khalid7344/home-network-watch/internal/models"
)

type mockStorageReader struct {
	knownClients map[string]bool
	avgQueries   float64
	queryCount   int
	recentAlerts map[string]bool
	snapshots    []models.Snapshot
}

func (m *mockStorageReader) GetKnownClients(since time.Time) (map[string]bool, error) {
	return m.knownClients, nil
}

func (m *mockStorageReader) GetAverageTotalQueries(since time.Time) (float64, int, error) {
	return m.avgQueries, m.queryCount, nil
}

func (m *mockStorageReader) HasRecentAlert(alertType string, since time.Time) (bool, error) {
	return m.recentAlerts[alertType], nil
}

func (m *mockStorageReader) GetSnapshotsCount(limit int) ([]models.Snapshot, error) {
	if len(m.snapshots) <= limit {
		return m.snapshots, nil
	}
	return m.snapshots[:limit], nil
}

func TestDetectNewClient(t *testing.T) {
	cfg := config.AnomalyEngineConfig{
		DNSSpikeThresholdPercent: 200,
		AlertCooldownMinutes:     60,
		WGInactivityDays:         30,
	}

	mockStore := &mockStorageReader{
		knownClients: map[string]bool{
			"192.168.1.10": true,
			"192.168.1.20": true,
		},
		recentAlerts: make(map[string]bool),
	}

	engine := New(cfg, mockStore)
	now := time.Now().UTC()

	snap := &models.Snapshot{
		Timestamp: now,
		DNSMetrics: models.DNSMetrics{
			TotalQueries: 1000,
			ActiveClients: map[string]int{
				"192.168.1.10":  500,
				"192.168.1.250": 100, // New client!
			},
		},
	}

	alerts, err := engine.Evaluate(context.Background(), snap)
	if err != nil {
		t.Fatalf("Evaluate failed: %v", err)
	}

	foundNewClientAlert := false
	for _, a := range alerts {
		if a.Type == models.AlertTypeNewClient {
			foundNewClientAlert = true
			if a.Severity != models.SeverityWarning {
				t.Errorf("expected WARNING severity, got %s", a.Severity)
			}
		}
	}
	if !foundNewClientAlert {
		t.Errorf("expected NEW_CLIENT alert, but got none")
	}
}

func TestDetectDNSSpike(t *testing.T) {
	cfg := config.AnomalyEngineConfig{
		DNSSpikeThresholdPercent: 200, // 200% above baseline (i.e. > 3x)
		AlertCooldownMinutes:     60,
		WGInactivityDays:         30,
	}

	mockStore := &mockStorageReader{
		knownClients: map[string]bool{"192.168.1.10": true},
		avgQueries:   10000.0,
		queryCount:   10,
		recentAlerts: make(map[string]bool),
	}

	engine := New(cfg, mockStore)
	now := time.Now().UTC()

	// Normal queries: 15,000 -> not a spike (threshold is 10,000 * 3.0 = 30,000)
	normalSnap := &models.Snapshot{
		Timestamp: now,
		DNSMetrics: models.DNSMetrics{
			TotalQueries:  15000,
			ActiveClients: map[string]int{"192.168.1.10": 15000},
		},
	}
	alerts, err := engine.Evaluate(context.Background(), normalSnap)
	if err != nil {
		t.Fatalf("Evaluate failed: %v", err)
	}
	for _, a := range alerts {
		if a.Type == models.AlertTypeDNSSpike {
			t.Errorf("did not expect DNS_SPIKE alert for 15,000 queries")
		}
	}

	// Spike queries: 35,000 -> spike!
	spikeSnap := &models.Snapshot{
		Timestamp: now,
		DNSMetrics: models.DNSMetrics{
			TotalQueries:  35000,
			ActiveClients: map[string]int{"192.168.1.10": 35000},
		},
	}
	alerts, err = engine.Evaluate(context.Background(), spikeSnap)
	if err != nil {
		t.Fatalf("Evaluate failed: %v", err)
	}

	foundSpike := false
	for _, a := range alerts {
		if a.Type == models.AlertTypeDNSSpike {
			foundSpike = true
			if a.Severity != models.SeverityCritical {
				t.Errorf("expected CRITICAL severity, got %s", a.Severity)
			}
		}
	}
	if !foundSpike {
		t.Errorf("expected DNS_SPIKE alert for 35,000 queries")
	}

	// Test Cooldown: if recent alert exists, suppress
	mockStore.recentAlerts[models.AlertTypeDNSSpike] = true
	alerts, err = engine.Evaluate(context.Background(), spikeSnap)
	if err != nil {
		t.Fatalf("Evaluate failed: %v", err)
	}
	for _, a := range alerts {
		if a.Type == models.AlertTypeDNSSpike {
			t.Errorf("expected DNS_SPIKE alert to be suppressed by cooldown")
		}
	}
}

func TestDetectWireGuardReconnection(t *testing.T) {
	cfg := config.AnomalyEngineConfig{
		DNSSpikeThresholdPercent: 200,
		AlertCooldownMinutes:     60,
		WGInactivityDays:         30,
	}

	now := time.Now().UTC()
	pubKey := "test-peer-key-1234567890="

	oldHandshake := now.AddDate(0, 0, -35) // 35 days ago (inactive > 30 days)
	newHandshake := now.Add(-10 * time.Second)

	mockStore := &mockStorageReader{
		knownClients: map[string]bool{},
		recentAlerts: make(map[string]bool),
		snapshots: []models.Snapshot{
			// current snapshot is index 0
			{
				Timestamp: now,
				WireGuardState: []models.WGPeerState{
					{PublicKey: pubKey, LatestHandshake: newHandshake},
				},
			},
			// previous snapshot is index 1
			{
				Timestamp: now.Add(-5 * time.Minute),
				WireGuardState: []models.WGPeerState{
					{PublicKey: pubKey, LatestHandshake: oldHandshake},
				},
			},
		},
	}

	engine := New(cfg, mockStore)
	currentSnap := &mockStore.snapshots[0]

	alerts, err := engine.Evaluate(context.Background(), currentSnap)
	if err != nil {
		t.Fatalf("Evaluate failed: %v", err)
	}

	foundReconnect := false
	for _, a := range alerts {
		if a.Type == models.AlertTypeWGReconnect {
			foundReconnect = true
		}
	}
	if !foundReconnect {
		t.Errorf("expected WG_RECONNECT alert for peer dormant for 35 days")
	}
}
