package anomaly

import (
	"context"
	"fmt"
	"time"

	"github.com/khalid7344/home-network-watch/internal/config"
	"github.com/khalid7344/home-network-watch/internal/models"
)

// StorageReader defines the database queries required by the anomaly engine.
type StorageReader interface {
	GetKnownClients(since time.Time) (map[string]bool, error)
	GetAverageTotalQueries(since time.Time) (float64, int, error)
	HasRecentAlert(alertType string, since time.Time) (bool, error)
	GetSnapshotsCount(limit int) ([]models.Snapshot, error)
}

// Engine evaluates snapshots for suspicious patterns or policy deviations.
type Engine struct {
	cfg     config.AnomalyEngineConfig
	storage StorageReader
}

// New creates a new Anomaly Detection Engine.
func New(cfg config.AnomalyEngineConfig, storage StorageReader) *Engine {
	return &Engine{
		cfg:     cfg,
		storage: storage,
	}
}

// Evaluate analyzes the current snapshot against historical data.
func (e *Engine) Evaluate(ctx context.Context, current *models.Snapshot) ([]*models.Alert, error) {
	if current == nil {
		return nil, nil
	}

	var alerts []*models.Alert
	now := current.Timestamp
	if now.IsZero() {
		now = time.Now().UTC()
	}

	cooldown := time.Duration(e.cfg.AlertCooldownMinutes) * time.Minute

	// Rule 1: New Client Detection (Past 7 days)
	newClientAlerts, err := e.detectNewClients(current, now, cooldown)
	if err != nil {
		return nil, fmt.Errorf("detecting new clients: %w", err)
	}
	alerts = append(alerts, newClientAlerts...)

	// Rule 2: DNS Volume Spike (> configured % of 24h rolling average)
	spikeAlert, err := e.detectDNSSpike(current, now, cooldown)
	if err != nil {
		return nil, fmt.Errorf("detecting DNS spike: %w", err)
	}
	if spikeAlert != nil {
		alerts = append(alerts, spikeAlert)
	}

	// Rule 3: WireGuard Reconnect after prolonged inactivity (> 30 days)
	wgAlerts, err := e.detectWGReconnection(current, now, cooldown)
	if err != nil {
		return nil, fmt.Errorf("detecting WireGuard reconnection: %w", err)
	}
	alerts = append(alerts, wgAlerts...)

	return alerts, nil
}

func (e *Engine) detectNewClients(current *models.Snapshot, now time.Time, cooldown time.Duration) ([]*models.Alert, error) {
	if len(current.DNSMetrics.ActiveClients) == 0 {
		return nil, nil
	}

	sevenDaysAgo := now.AddDate(0, 0, -7)
	knownClients, err := e.storage.GetKnownClients(sevenDaysAgo)
	if err != nil {
		return nil, err
	}

	// If no historical clients at all (e.g. brand new db), we don't alert on initial population
	if len(knownClients) == 0 {
		return nil, nil
	}

	var alerts []*models.Alert
	for clientIP := range current.DNSMetrics.ActiveClients {
		if !knownClients[clientIP] {
			// Check cooldown for this specific alert
			hasAlert, err := e.storage.HasRecentAlert(fmt.Sprintf("%s:%s", models.AlertTypeNewClient, clientIP), now.Add(-cooldown))
			if err != nil {
				return nil, err
			}
			if !hasAlert {
				alerts = append(alerts, &models.Alert{
					Timestamp:   now,
					Severity:    models.SeverityWarning,
					Type:        models.AlertTypeNewClient,
					Description: fmt.Sprintf("New unseen client device detected on network: %s", clientIP),
					Resolved:    false,
				})
			}
		}
	}

	return alerts, nil
}

func (e *Engine) detectDNSSpike(current *models.Snapshot, now time.Time, cooldown time.Duration) (*models.Alert, error) {
	twentyFourHoursAgo := now.Add(-24 * time.Hour)
	avgQueries, count, err := e.storage.GetAverageTotalQueries(twentyFourHoursAgo)
	if err != nil {
		return nil, err
	}

	// Need at least 2 historical snapshots to establish a baseline
	if count < 2 || avgQueries <= 0 {
		return nil, nil
	}

	currentQueries := float64(current.DNSMetrics.TotalQueries)
	thresholdMultiplier := 1.0 + (e.cfg.DNSSpikeThresholdPercent / 100.0)
	spikeThreshold := avgQueries * thresholdMultiplier

	if currentQueries > spikeThreshold {
		hasRecent, err := e.storage.HasRecentAlert(models.AlertTypeDNSSpike, now.Add(-cooldown))
		if err != nil {
			return nil, err
		}
		if !hasRecent {
			pctAbove := ((currentQueries - avgQueries) / avgQueries) * 100.0
			return &models.Alert{
				Timestamp:   now,
				Severity:    models.SeverityCritical,
				Type:        models.AlertTypeDNSSpike,
				Description: fmt.Sprintf("Abnormal DNS volume spike: %d queries (%.1f%% above 24h baseline of %.0f)", int64(currentQueries), pctAbove, avgQueries),
				Resolved:    false,
			}, nil
		}
	}

	return nil, nil
}

func (e *Engine) detectWGReconnection(current *models.Snapshot, now time.Time, cooldown time.Duration) ([]*models.Alert, error) {
	if len(current.WireGuardState) == 0 {
		return nil, nil
	}

	// Look at the previous snapshot to compare peer handshakes
	snapshots, err := e.storage.GetSnapshotsCount(2)
	if err != nil || len(snapshots) < 2 {
		return nil, nil
	}
	prevSnap := snapshots[1]

	prevHandshakes := make(map[string]time.Time)
	for _, p := range prevSnap.WireGuardState {
		prevHandshakes[p.PublicKey] = p.LatestHandshake
	}

	inactivityThreshold := time.Duration(e.cfg.WGInactivityDays) * 24 * time.Hour
	var alerts []*models.Alert

	for _, peer := range current.WireGuardState {
		if peer.LatestHandshake.IsZero() {
			continue
		}

		prevHandshake, exists := prevHandshakes[peer.PublicKey]
		if !exists || prevHandshake.IsZero() {
			continue
		}

		// Check if handshake updated recently
		if peer.LatestHandshake.After(prevHandshake) {
			// Was the previous handshake older than inactivity threshold?
			if now.Sub(prevHandshake) > inactivityThreshold {
				hasRecent, err := e.storage.HasRecentAlert(models.AlertTypeWGReconnect, now.Add(-cooldown))
				if err != nil {
					return nil, err
				}
				if !hasRecent {
					alerts = append(alerts, &models.Alert{
						Timestamp:   now,
						Severity:    models.SeverityInfo,
						Type:        models.AlertTypeWGReconnect,
						Description: fmt.Sprintf("Dormant WireGuard peer %s reconnected after >%d days of inactivity", peer.TruncatedKey(), e.cfg.WGInactivityDays),
						Resolved:    false,
					})
				}
			}
		}
	}

	return alerts, nil
}
