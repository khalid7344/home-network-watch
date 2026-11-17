package sqlite

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/khalid7344/home-network-watch/internal/models"
)

func TestSQLiteSnapshotAndAlertOperations(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test_hnw.db")

	store, err := New(dbPath)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	defer store.Close()

	now := time.Now().UTC().Truncate(time.Second)

	snap1 := &models.Snapshot{
		Timestamp: now.Add(-10 * time.Minute),
		DNSMetrics: models.DNSMetrics{
			TotalQueries:   1000,
			BlockedQueries: 200,
			TopDomains: map[string]int{
				"github.com": 50,
			},
			ActiveClients: map[string]int{
				"192.168.1.10": 800,
				"192.168.1.20": 200,
			},
		},
		WireGuardState: []models.WGPeerState{
			{
				PublicKey:       "key1===",
				LatestHandshake: now.Add(-5 * time.Minute),
				RxBytes:         5000,
				TxBytes:         6000,
			},
		},
	}

	id1, err := store.SaveSnapshot(snap1)
	if err != nil {
		t.Fatalf("SaveSnapshot snap1 failed: %v", err)
	}
	if id1 <= 0 {
		t.Errorf("expected positive ID, got %d", id1)
	}

	snap2 := &models.Snapshot{
		Timestamp: now,
		DNSMetrics: models.DNSMetrics{
			TotalQueries:   2000,
			BlockedQueries: 400,
			TopDomains: map[string]int{
				"google.com": 100,
			},
			ActiveClients: map[string]int{
				"192.168.1.10": 1500,
				"192.168.1.30": 500, // new client
			},
		},
	}

	id2, err := store.SaveSnapshot(snap2)
	if err != nil {
		t.Fatalf("SaveSnapshot snap2 failed: %v", err)
	}
	if id2 <= id1 {
		t.Errorf("expected id2 > id1, got %d <= %d", id2, id1)
	}

	// Verify GetLatestSnapshot
	latest, err := store.GetLatestSnapshot()
	if err != nil {
		t.Fatalf("GetLatestSnapshot failed: %v", err)
	}
	if latest == nil {
		t.Fatal("expected latest snapshot, got nil")
	}
	if latest.DNSMetrics.TotalQueries != 2000 {
		t.Errorf("expected 2000 queries in latest snapshot, got %d", latest.DNSMetrics.TotalQueries)
	}
	if latest.DNSMetrics.TopDomains["google.com"] != 100 {
		t.Errorf("expected google.com count 100, got %d", latest.DNSMetrics.TopDomains["google.com"])
	}

	// Verify GetKnownClients
	clients, err := store.GetKnownClients(now.Add(-1*time.Hour), 0)
	if err != nil {
		t.Fatalf("GetKnownClients failed: %v", err)
	}
	if len(clients) != 3 {
		t.Errorf("expected 3 known clients (10, 20, 30), got %d: %v", len(clients), clients)
	}
	if !clients["192.168.1.10"] || !clients["192.168.1.20"] || !clients["192.168.1.30"] {
		t.Errorf("missing expected client in known clients: %v", clients)
	}

	// Verify GetAverageTotalQueries
	avg, count, err := store.GetAverageTotalQueries(now.Add(-1*time.Hour), 0)
	if err != nil {
		t.Fatalf("GetAverageTotalQueries failed: %v", err)
	}
	if count != 2 {
		t.Errorf("expected 2 snapshots, got %d", count)
	}
	if avg != 1500.0 {
		t.Errorf("expected average 1500.0, got %f", avg)
	}

	// Test Alerts
	alert := &models.Alert{
		Timestamp:   now,
		Severity:    models.SeverityWarning,
		Type:        models.AlertTypeDNSSpike,
		Description: "Simulated DNS query spike",
		Resolved:    false,
	}

	alertID, err := store.SaveAlert(alert)
	if err != nil {
		t.Fatalf("SaveAlert failed: %v", err)
	}
	if alertID <= 0 {
		t.Errorf("expected positive alert ID, got %d", alertID)
	}

	// Test HasRecentAlert
	hasAlert, err := store.HasRecentAlert(models.AlertTypeDNSSpike, now.Add(-5*time.Minute))
	if err != nil {
		t.Fatalf("HasRecentAlert failed: %v", err)
	}
	if !hasAlert {
		t.Errorf("expected HasRecentAlert to be true")
	}

	hasOtherAlert, err := store.HasRecentAlert(models.AlertTypeNewClient, now.Add(-5*time.Minute))
	if err != nil {
		t.Fatalf("HasRecentAlert failed: %v", err)
	}
	if hasOtherAlert {
		t.Errorf("expected HasRecentAlert to be false for new client")
	}

	// Test GetAlerts
	unresolved := false
	alerts, err := store.GetAlerts(&unresolved, 10)
	if err != nil {
		t.Fatalf("GetAlerts unresolved failed: %v", err)
	}
	if len(alerts) != 1 {
		t.Errorf("expected 1 unresolved alert, got %d", len(alerts))
	}

	// Test ResolveAlert
	if err := store.ResolveAlert(alertID); err != nil {
		t.Fatalf("ResolveAlert failed: %v", err)
	}

	alertsAfter, err := store.GetAlerts(&unresolved, 10)
	if err != nil {
		t.Fatalf("GetAlerts after resolve failed: %v", err)
	}
	if len(alertsAfter) != 0 {
		t.Errorf("expected 0 unresolved alerts after resolve, got %d", len(alertsAfter))
	}

	// Test PruneRetention
	pruned, err := store.PruneRetention(30)
	if err != nil {
		t.Fatalf("PruneRetention failed: %v", err)
	}
	if pruned != 0 {
		t.Errorf("expected 0 pruned for fresh data, got %d", pruned)
	}
}
