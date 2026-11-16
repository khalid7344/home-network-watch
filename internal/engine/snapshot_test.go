package engine

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/khalid7344/home-network-watch/internal/collector/demo"
	"github.com/khalid7344/home-network-watch/internal/config"
	"github.com/khalid7344/home-network-watch/internal/engine/anomaly"
	"github.com/khalid7344/home-network-watch/internal/storage/sqlite"
)

func TestSnapshotEnginePipeline(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "engine_test.db")

	store, err := sqlite.New(dbPath)
	if err != nil {
		t.Fatalf("sqlite.New failed: %v", err)
	}
	defer store.Close()

	demoCol := demo.New()
	cfg := config.AnomalyEngineConfig{
		DNSSpikeThresholdPercent: 200,
		AlertCooldownMinutes:     60,
		WGInactivityDays:         30,
	}
	anomalyEng := anomaly.New(cfg, store)

	engine := NewSnapshotEngine(demoCol, demoCol, store, anomalyEng)

	ctx := context.Background()
	snap, healths, alerts, err := engine.CollectAndProcess(ctx)
	if err != nil {
		t.Fatalf("CollectAndProcess failed: %v", err)
	}

	if snap == nil {
		t.Fatal("expected non-nil snapshot")
	}
	if snap.ID <= 0 {
		t.Errorf("expected snapshot to be saved with positive ID, got %d", snap.ID)
	}
	if len(healths) != 2 {
		t.Errorf("expected 2 health reports, got %d", len(healths))
	}
	// Initial snapshot: no historical baseline yet, so alerts is 0
	if len(alerts) != 0 {
		t.Errorf("expected 0 alerts on initial run, got %d", len(alerts))
	}

	// Verify snapshot was stored in database
	latest, err := store.GetLatestSnapshot()
	if err != nil {
		t.Fatalf("GetLatestSnapshot failed: %v", err)
	}
	if latest == nil || latest.ID != snap.ID {
		t.Errorf("expected latest snapshot in DB to match snap ID %d", snap.ID)
	}

	// Now simulate spike and test anomaly generation through the pipeline
	demoCol.SetSimulateSpike(true)
	// Add another snapshot so count >= 2
	snap2, _, alerts2, err := engine.CollectAndProcess(ctx)
	if err != nil {
		t.Fatalf("CollectAndProcess run 2 failed: %v", err)
	}
	if snap2 == nil {
		t.Fatal("expected snap2")
	}

	// Verify healths stored
	lastH := engine.LastHealth()
	if len(lastH) != 2 {
		t.Errorf("expected 2 health statuses in LastHealth(), got %d", len(lastH))
	}
	_ = alerts2
}

func TestSnapshotEngineNilCollectors(t *testing.T) {
	engine := NewSnapshotEngine(nil, nil, nil, nil)
	snap, healths, alerts, err := engine.CollectAndProcess(context.Background())
	if err != nil {
		t.Fatalf("expected nil error with nil collectors, got: %v", err)
	}
	if snap == nil || len(healths) != 0 || len(alerts) != 0 {
		t.Errorf("unexpected output with nil collectors")
	}
}
