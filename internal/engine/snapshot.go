package engine

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/khalid7344/home-network-watch/internal/collector"
	"github.com/khalid7344/home-network-watch/internal/engine/anomaly"
	"github.com/khalid7344/home-network-watch/internal/models"
	"github.com/khalid7344/home-network-watch/internal/storage/sqlite"
)

// SnapshotEngine coordinates collection, persistence, and anomaly detection.
type SnapshotEngine struct {
	dnsCol     collector.DNSCollector
	wgCol      collector.WireGuardCollector
	storage    *sqlite.Storage
	anomalyEng *anomaly.Engine
	mu         sync.Mutex
	lastHealth []models.CollectorHealth
}

// NewSnapshotEngine creates an orchestrator with collectors and storage.
func NewSnapshotEngine(
	dnsCol collector.DNSCollector,
	wgCol collector.WireGuardCollector,
	storage *sqlite.Storage,
	anomalyEng *anomaly.Engine,
) *SnapshotEngine {
	return &SnapshotEngine{
		dnsCol:     dnsCol,
		wgCol:      wgCol,
		storage:    storage,
		anomalyEng: anomalyEng,
	}
}

// LastHealth returns the most recently observed collector health statuses.
func (s *SnapshotEngine) LastHealth() []models.CollectorHealth {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]models.CollectorHealth(nil), s.lastHealth...)
}

// CollectAndProcess performs one full cycle: collection -> save snapshot -> anomaly check -> save alerts.
func (s *SnapshotEngine) CollectAndProcess(ctx context.Context) (*models.Snapshot, []models.CollectorHealth, []*models.Alert, error) {
	snap := &models.Snapshot{
		Timestamp: time.Now().UTC(),
	}

	var healths []models.CollectorHealth
	var healthMu sync.Mutex

	var wg sync.WaitGroup

	// Concurrently collect DNS if collector present
	if s.dnsCol != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			dns, h, _ := s.dnsCol.CollectDNS(ctx)
			snap.DNSMetrics = dns
			healthMu.Lock()
			healths = append(healths, h)
			healthMu.Unlock()
		}()
	}

	// Concurrently collect WireGuard if collector present
	if s.wgCol != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			peers, h, _ := s.wgCol.CollectWireGuard(ctx)
			snap.WireGuardState = peers
			healthMu.Lock()
			healths = append(healths, h)
			healthMu.Unlock()
		}()
	}

	wg.Wait()

	s.mu.Lock()
	s.lastHealth = healths
	s.mu.Unlock()

	// Persist snapshot to SQLite if storage is available
	if s.storage != nil {
		if _, err := s.storage.SaveSnapshot(snap); err != nil {
			return snap, healths, nil, fmt.Errorf("saving snapshot: %w", err)
		}
	}

	// Evaluate anomalies if engine is available
	var newAlerts []*models.Alert
	if s.anomalyEng != nil {
		alerts, err := s.anomalyEng.Evaluate(ctx, snap)
		if err != nil {
			return snap, healths, nil, fmt.Errorf("evaluating anomalies: %w", err)
		}
		newAlerts = alerts

		// Persist alerts
		if s.storage != nil {
			for _, a := range newAlerts {
				_, _ = s.storage.SaveAlert(a)
			}
		}
	}

	return snap, healths, newAlerts, nil
}
