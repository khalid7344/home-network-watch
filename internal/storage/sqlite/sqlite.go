package sqlite

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/khalid7344/home-network-watch/internal/models"
	_ "modernc.org/sqlite"
)

// Storage manages local SQLite persistence for snapshots and alerts.
type Storage struct {
	db *sql.DB
	mu sync.RWMutex
}

type snapshotPayload struct {
	TopDomains     map[string]int       `json:"top_domains"`
	ActiveClients  map[string]int       `json:"active_clients"`
	WireGuardState []models.WGPeerState `json:"wireguard_state"`
}

// New opens or creates a SQLite database at dbPath and runs schema migrations.
func New(dbPath string) (*Storage, error) {
	if dbPath == "" {
		dbPath = "hnw.db"
	}

	// Ensure parent directory exists if not current dir or in-memory
	if !strings.HasPrefix(dbPath, ":memory:") && dbPath != "hnw.db" {
		dir := filepath.Dir(dbPath)
		if dir != "." && dir != "" {
			if err := os.MkdirAll(dir, 0750); err != nil {
				return nil, fmt.Errorf("creating database directory %s: %w", dir, err)
			}
		}
	}

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("opening sqlite database at %s: %w", dbPath, err)
	}

	// Configure connection pool for SQLite single-writer safety
	db.SetMaxOpenConns(1)

	s := &Storage{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, fmt.Errorf("database migration failed: %w", err)
	}

	return s, nil
}

// Close closes the database connection.
func (s *Storage) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

func (s *Storage) migrate() error {
	schema := `
	CREATE TABLE IF NOT EXISTS snapshots (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
		total_queries INTEGER,
		blocked_queries INTEGER,
		data JSON
	);

	CREATE INDEX IF NOT EXISTS idx_snapshots_timestamp ON snapshots(timestamp);

	CREATE TABLE IF NOT EXISTS alerts (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
		severity TEXT,
		alert_type TEXT,
		description TEXT,
		resolved BOOLEAN DEFAULT 0
	);

	CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp);
	CREATE INDEX IF NOT EXISTS idx_alerts_type ON alerts(alert_type);
	`
	_, err := s.db.Exec(schema)
	return err
}

// SaveSnapshot inserts a new snapshot into SQLite.
func (s *Storage) SaveSnapshot(snap *models.Snapshot) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	payload := snapshotPayload{
		TopDomains:     snap.DNSMetrics.TopDomains,
		ActiveClients:  snap.DNSMetrics.ActiveClients,
		WireGuardState: snap.WireGuardState,
	}

	dataBytes, err := json.Marshal(payload)
	if err != nil {
		return 0, fmt.Errorf("serializing snapshot payload: %w", err)
	}

	ts := snap.Timestamp
	if ts.IsZero() {
		ts = time.Now().UTC()
	} else {
		ts = ts.UTC()
	}

	query := `INSERT INTO snapshots (timestamp, total_queries, blocked_queries, data) VALUES (?, ?, ?, ?)`
	res, err := s.db.Exec(query, ts.Format(time.RFC3339), snap.DNSMetrics.TotalQueries, snap.DNSMetrics.BlockedQueries, string(dataBytes))
	if err != nil {
		return 0, fmt.Errorf("inserting snapshot: %w", err)
	}

	id, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}
	snap.ID = id
	return id, nil
}

// GetLatestSnapshot retrieves the most recent snapshot.
func (s *Storage) GetLatestSnapshot() (*models.Snapshot, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	query := `SELECT id, timestamp, total_queries, blocked_queries, data FROM snapshots ORDER BY id DESC LIMIT 1`
	row := s.db.QueryRow(query)

	var id int64
	var tsStr string
	var totalQueries, blockedQueries int64
	var dataStr string

	if err := row.Scan(&id, &tsStr, &totalQueries, &blockedQueries, &dataStr); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("querying latest snapshot: %w", err)
	}

	ts, _ := time.Parse(time.RFC3339, tsStr)
	if ts.IsZero() {
		ts, _ = time.Parse("2006-01-02 15:04:05", tsStr)
	}

	var payload snapshotPayload
	if err := json.Unmarshal([]byte(dataStr), &payload); err != nil {
		return nil, fmt.Errorf("deserializing snapshot data: %w", err)
	}

	return &models.Snapshot{
		ID:        id,
		Timestamp: ts,
		DNSMetrics: models.DNSMetrics{
			TotalQueries:   totalQueries,
			BlockedQueries: blockedQueries,
			TopDomains:     payload.TopDomains,
			ActiveClients:  payload.ActiveClients,
		},
		WireGuardState: payload.WireGuardState,
	}, nil
}

// GetSnapshotsCount returns up to `limit` snapshots ordered by timestamp descending.
func (s *Storage) GetSnapshotsCount(limit int) ([]models.Snapshot, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if limit <= 0 {
		limit = 50
	}

	query := `SELECT id, timestamp, total_queries, blocked_queries, data FROM snapshots ORDER BY id DESC LIMIT ?`
	rows, err := s.db.Query(query, limit)
	if err != nil {
		return nil, fmt.Errorf("querying snapshots: %w", err)
	}
	defer rows.Close()

	var snapshots []models.Snapshot
	for rows.Next() {
		var id int64
		var tsStr string
		var totalQueries, blockedQueries int64
		var dataStr string

		if err := rows.Scan(&id, &tsStr, &totalQueries, &blockedQueries, &dataStr); err != nil {
			return nil, fmt.Errorf("scanning snapshot row: %w", err)
		}

		ts, _ := time.Parse(time.RFC3339, tsStr)
		if ts.IsZero() {
			ts, _ = time.Parse("2006-01-02 15:04:05", tsStr)
		}

		var payload snapshotPayload
		_ = json.Unmarshal([]byte(dataStr), &payload)

		snapshots = append(snapshots, models.Snapshot{
			ID:        id,
			Timestamp: ts,
			DNSMetrics: models.DNSMetrics{
				TotalQueries:   totalQueries,
				BlockedQueries: blockedQueries,
				TopDomains:     payload.TopDomains,
				ActiveClients:  payload.ActiveClients,
			},
			WireGuardState: payload.WireGuardState,
		})
	}

	return snapshots, nil
}

// GetKnownClients returns the set of all unique client identifiers recorded since the specified time.
func (s *Storage) GetKnownClients(since time.Time) (map[string]bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	query := `SELECT data FROM snapshots WHERE timestamp >= ?`
	rows, err := s.db.Query(query, since.UTC().Format(time.RFC3339))
	if err != nil {
		return nil, fmt.Errorf("querying snapshots for clients: %w", err)
	}
	defer rows.Close()

	known := make(map[string]bool)
	for rows.Next() {
		var dataStr string
		if err := rows.Scan(&dataStr); err != nil {
			return nil, err
		}
		var payload snapshotPayload
		if err := json.Unmarshal([]byte(dataStr), &payload); err == nil {
			for client := range payload.ActiveClients {
				known[client] = true
			}
		}
	}

	return known, nil
}

// GetAverageTotalQueries calculates the average total queries from snapshots since the given time.
func (s *Storage) GetAverageTotalQueries(since time.Time) (avg float64, count int, err error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	query := `SELECT AVG(total_queries), COUNT(id) FROM snapshots WHERE timestamp >= ?`
	row := s.db.QueryRow(query, since.UTC().Format(time.RFC3339))

	var avgNull sql.NullFloat64
	if err := row.Scan(&avgNull, &count); err != nil {
		return 0, 0, fmt.Errorf("querying avg queries: %w", err)
	}

	if avgNull.Valid {
		avg = avgNull.Float64
	}
	return avg, count, nil
}

// SaveAlert records a new alert.
func (s *Storage) SaveAlert(alert *models.Alert) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	ts := alert.Timestamp
	if ts.IsZero() {
		ts = time.Now().UTC()
	} else {
		ts = ts.UTC()
	}

	query := `INSERT INTO alerts (timestamp, severity, alert_type, description, resolved) VALUES (?, ?, ?, ?, ?)`
	res, err := s.db.Exec(query, ts.Format(time.RFC3339), alert.Severity, alert.Type, alert.Description, alert.Resolved)
	if err != nil {
		return 0, fmt.Errorf("inserting alert: %w", err)
	}

	id, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}
	alert.ID = id
	return id, nil
}

// GetAlerts returns alerts with optional filtering on resolved status.
func (s *Storage) GetAlerts(resolvedOnly *bool, limit int) ([]models.Alert, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if limit <= 0 {
		limit = 100
	}

	var query string
	var args []any

	if resolvedOnly == nil {
		query = `SELECT id, timestamp, severity, alert_type, description, resolved FROM alerts ORDER BY id DESC LIMIT ?`
		args = []any{limit}
	} else {
		query = `SELECT id, timestamp, severity, alert_type, description, resolved FROM alerts WHERE resolved = ? ORDER BY id DESC LIMIT ?`
		args = []any{*resolvedOnly, limit}
	}

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("querying alerts: %w", err)
	}
	defer rows.Close()

	var alerts []models.Alert
	for rows.Next() {
		var a models.Alert
		var tsStr string
		if err := rows.Scan(&a.ID, &tsStr, &a.Severity, &a.Type, &a.Description, &a.Resolved); err != nil {
			return nil, fmt.Errorf("scanning alert row: %w", err)
		}
		ts, _ := time.Parse(time.RFC3339, tsStr)
		if ts.IsZero() {
			ts, _ = time.Parse("2006-01-02 15:04:05", tsStr)
		}
		a.Timestamp = ts
		alerts = append(alerts, a)
	}

	return alerts, nil
}

// ResolveAlert marks an alert as resolved.
func (s *Storage) ResolveAlert(id int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	query := `UPDATE alerts SET resolved = 1 WHERE id = ?`
	_, err := s.db.Exec(query, id)
	return err
}

// HasRecentAlert checks if an alert of the given type was generated since `since`.
func (s *Storage) HasRecentAlert(alertType string, since time.Time) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	query := `SELECT COUNT(id) FROM alerts WHERE alert_type = ? AND timestamp >= ?`
	var count int
	err := s.db.QueryRow(query, alertType, since.UTC().Format(time.RFC3339)).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("checking recent alert: %w", err)
	}
	return count > 0, nil
}

// PruneRetention deletes snapshots older than retention days.
func (s *Storage) PruneRetention(retentionDays int) (int64, error) {
	if retentionDays <= 0 {
		return 0, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	cutoff := time.Now().UTC().AddDate(0, 0, -retentionDays).Format(time.RFC3339)
	res, err := s.db.Exec(`DELETE FROM snapshots WHERE timestamp < ?`, cutoff)
	if err != nil {
		return 0, fmt.Errorf("pruning snapshots: %w", err)
	}
	return res.RowsAffected()
}
