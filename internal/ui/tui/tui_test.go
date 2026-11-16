package tui

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/khalid7344/home-network-watch/internal/models"
	"github.com/khalid7344/home-network-watch/internal/storage/sqlite"
)

func TestTUIModelTabsAndRendering(t *testing.T) {
	tmpDir := t.TempDir()
	store, err := sqlite.New(filepath.Join(tmpDir, "tui_test.db"))
	if err != nil {
		t.Fatalf("sqlite.New failed: %v", err)
	}
	defer store.Close()

	// Seed alert and snapshot
	snap := &models.Snapshot{
		Timestamp: time.Now(),
		DNSMetrics: models.DNSMetrics{
			TotalQueries:   12500,
			BlockedQueries: 2500,
			TopDomains: map[string]int{
				"github.com": 400,
			},
			ActiveClients: map[string]int{
				"192.168.1.10": 8000,
			},
		},
		WireGuardState: []models.WGPeerState{
			{
				PublicKey:       "test-pub-key-1234567890=",
				Endpoint:        "192.0.2.1:51820",
				LatestHandshake: time.Now().Add(-30 * time.Second),
				RxBytes:         1048576,
				TxBytes:         2097152,
			},
		},
	}
	_, _ = store.SaveSnapshot(snap)

	alert := &models.Alert{
		Timestamp:   time.Now(),
		Severity:    models.SeverityWarning,
		Type:        models.AlertTypeNewClient,
		Description: "New client detected: 192.168.1.200",
		Resolved:    false,
	}
	_, _ = store.SaveAlert(alert)

	m := NewModel(nil, store, true)

	// Test Init
	cmd := m.Init()
	if cmd == nil {
		t.Errorf("expected Init cmd batch")
	}

	// Test Overview rendering
	viewOverview := m.View()
	if !strings.Contains(viewOverview, "HOME NETWORK WATCH") {
		t.Errorf("expected title in view")
	}
	if !strings.Contains(viewOverview, "DEMO MODE") {
		t.Errorf("expected DEMO MODE badge in demo view")
	}
	if !strings.Contains(viewOverview, "TOTAL QUERIES") {
		t.Errorf("expected TOTAL QUERIES KPI card")
	}

	// Test Tab switching to DNS (key "2" or "tab")
	newModel, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'2'}})
	m = newModel.(Model)
	if m.activeTab != TabDNS {
		t.Errorf("expected active tab DNS (1), got %d", m.activeTab)
	}
	viewDNS := m.View()
	if !strings.Contains(viewDNS, "TOP DOMAIN") || !strings.Contains(viewDNS, "github.com") {
		t.Errorf("expected DNS tables in DNS tab view: %s", viewDNS)
	}

	// Test Tab switching to WireGuard (key "3")
	newModel, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'3'}})
	m = newModel.(Model)
	if m.activeTab != TabWG {
		t.Errorf("expected active tab WG (2), got %d", m.activeTab)
	}
	viewWG := m.View()
	if !strings.Contains(viewWG, "PEER KEY") || !strings.Contains(viewWG, "test-pub…") {
		t.Errorf("expected WireGuard table in WG tab view: %s", viewWG)
	}

	// Test Tab switching to Alerts (key "4")
	newModel, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'4'}})
	m = newModel.(Model)
	if m.activeTab != TabAlerts {
		t.Errorf("expected active tab Alerts (3), got %d", m.activeTab)
	}
	viewAlerts := m.View()
	if !strings.Contains(viewAlerts, "New client detected") {
		t.Errorf("expected alert description in Alerts tab view: %s", viewAlerts)
	}

	// Test resolving alert with 'r'
	newModel, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'r'}})
	m = newModel.(Model)
	if !m.alerts[0].Resolved {
		t.Errorf("expected alert 0 to be resolved after pressing 'r'")
	}

	// Test navigation keys
	newModel, _ = m.Update(tea.KeyMsg{Type: tea.KeyDown})
	m = newModel.(Model)
	newModel, _ = m.Update(tea.KeyMsg{Type: tea.KeyUp})
	m = newModel.(Model)

	// Test quit key
	_, quitCmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'q'}})
	if quitCmd == nil {
		t.Errorf("expected quit cmd on 'q'")
	}

	// Test Window resize
	newModel, _ = m.Update(tea.WindowSizeMsg{Width: 120, Height: 40})
	m = newModel.(Model)
	if m.width != 120 || m.height != 40 {
		t.Errorf("expected updated window size 120x40, got %dx%d", m.width, m.height)
	}
}

func TestFormattingHelpers(t *testing.T) {
	if got := formatNumber(1234567); got != "1,234,567" {
		t.Errorf("expected '1,234,567', got '%s'", got)
	}
	if got := formatNumber(99); got != "99" {
		t.Errorf("expected '99', got '%s'", got)
	}

	if got := formatBytes(500); got != "500 B" {
		t.Errorf("expected '500 B', got '%s'", got)
	}
	if got := formatBytes(1048576); got != "1.0 MB" {
		t.Errorf("expected '1.0 MB', got '%s'", got)
	}

	if got := truncate("short", 10); got != "short" {
		t.Errorf("expected 'short', got '%s'", got)
	}
	if got := truncate("this is a very long string", 10); got != "this is a…" {
		t.Errorf("expected 'this is a…', got '%s'", got)
	}
}
