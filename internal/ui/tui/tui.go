package tui

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/khalid7344/home-network-watch/internal/engine"
	"github.com/khalid7344/home-network-watch/internal/models"
	"github.com/khalid7344/home-network-watch/internal/storage/sqlite"
)

// Tab identifiers.
const (
	TabOverview = 0
	TabDNS      = 1
	TabWG       = 2
	TabAlerts   = 3
	TotalTabs   = 4
)

// TickMsg signals a background data refresh tick.
type TickMsg time.Time

// SnapshotMsg carries newly gathered telemetry.
type SnapshotMsg struct {
	Snapshot *models.Snapshot
	Healths  []models.CollectorHealth
	Alerts   []models.Alert
	Err      error
}

// Model represents the Bubble Tea TUI state.
type Model struct {
	engine        *engine.SnapshotEngine
	storage       *sqlite.Storage
	isDemo        bool
	activeTab     int
	width         int
	height        int
	snapshot      *models.Snapshot
	healths       []models.CollectorHealth
	alerts        []models.Alert
	selectedAlert int
	statusMsg     string
	statusTime    time.Time
}

// NewModel creates an initialized TUI model.
func NewModel(eng *engine.SnapshotEngine, store *sqlite.Storage, isDemo bool) Model {
	m := Model{
		engine:        eng,
		storage:       store,
		isDemo:        isDemo,
		activeTab:     TabOverview,
		width:         100,
		height:        30,
		selectedAlert: 0,
	}

	// Load existing alerts from storage if present
	if store != nil {
		if existing, err := store.GetAlerts(nil, 50); err == nil {
			m.alerts = existing
		}
		if latest, err := store.GetLatestSnapshot(); err == nil && latest != nil {
			m.snapshot = latest
		}
	}

	return m
}

func tickCmd() tea.Cmd {
	return tea.Tick(3*time.Second, func(t time.Time) tea.Msg {
		return TickMsg(t)
	})
}

func collectCmd(eng *engine.SnapshotEngine, store *sqlite.Storage) tea.Cmd {
	return func() tea.Msg {
		if eng == nil {
			return SnapshotMsg{}
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		snap, healths, _, err := eng.CollectAndProcess(ctx)
		var alerts []models.Alert
		if store != nil {
			alerts, _ = store.GetAlerts(nil, 50)
		}
		return SnapshotMsg{
			Snapshot: snap,
			Healths:  healths,
			Alerts:   alerts,
			Err:      err,
		}
	}
}

// Init initializes the Bubble Tea program.
func (m Model) Init() tea.Cmd {
	return tea.Batch(
		collectCmd(m.engine, m.storage),
		tickCmd(),
	)
}

// Update handles UI events, user input, and timers.
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit
		case "tab":
			m.activeTab = (m.activeTab + 1) % TotalTabs
		case "shift+tab":
			m.activeTab = (m.activeTab + TotalTabs - 1) % TotalTabs
		case "1":
			m.activeTab = TabOverview
		case "2":
			m.activeTab = TabDNS
		case "3":
			m.activeTab = TabWG
		case "4":
			m.activeTab = TabAlerts
		case "up", "k":
			if m.activeTab == TabAlerts && m.selectedAlert > 0 {
				m.selectedAlert--
			}
		case "down", "j":
			if m.activeTab == TabAlerts && m.selectedAlert < len(m.alerts)-1 {
				m.selectedAlert++
			}
		case "r":
			if m.activeTab == TabAlerts && len(m.alerts) > 0 && m.storage != nil {
				target := m.alerts[m.selectedAlert]
				if !target.Resolved {
					_ = m.storage.ResolveAlert(target.ID)
					m.alerts[m.selectedAlert].Resolved = true
					m.statusMsg = fmt.Sprintf("Alert #%d marked as resolved", target.ID)
					m.statusTime = time.Now()
				}
			}
		case "s":
			m.statusMsg = "Forcing snapshot collection..."
			m.statusTime = time.Now()
			return m, collectCmd(m.engine, m.storage)
		}

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height

	case TickMsg:
		return m, tea.Batch(
			collectCmd(m.engine, m.storage),
			tickCmd(),
		)

	case SnapshotMsg:
		if msg.Err != nil {
			m.statusMsg = fmt.Sprintf("Collection warning: %v", msg.Err)
			m.statusTime = time.Now()
		} else {
			if msg.Snapshot != nil {
				m.snapshot = msg.Snapshot
			}
			if len(msg.Healths) > 0 {
				m.healths = msg.Healths
			}
			if msg.Alerts != nil {
				m.alerts = msg.Alerts
			}
		}
	}

	return m, nil
}

// Styles
var (
	headerStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#FAFAFA")).
			Background(lipgloss.Color("#1E3A8A")).
			Padding(0, 1)

	demoBadge = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#111827")).
			Background(lipgloss.Color("#F59E0B")).
			Padding(0, 1)

	tabActiveStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#FFFFFF")).
			Background(lipgloss.Color("#2563EB")).
			Padding(0, 2)

	tabInactiveStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("#9CA3AF")).
				Background(lipgloss.Color("#1F2937")).
				Padding(0, 2)

	cardStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("#3B82F6")).
			Padding(1, 2).
			Width(24)

	tableHeaderStyle = lipgloss.NewStyle().
				Bold(true).
				Foreground(lipgloss.Color("#60A5FA")).
				Border(lipgloss.NormalBorder(), false, false, true, false).
				BorderForeground(lipgloss.Color("#4B5563"))

	footerStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#6B7280")).
			Padding(0, 1)

	alertCriticalStyle = lipgloss.NewStyle().
				Bold(true).
				Foreground(lipgloss.Color("#EF4444"))

	alertWarningStyle = lipgloss.NewStyle().
				Bold(true).
				Foreground(lipgloss.Color("#F59E0B"))

	alertInfoStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#3B82F6"))

	alertResolvedStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("#10B981"))
)

// View renders the TUI screen.
func (m Model) View() string {
	var b strings.Builder

	// Top Title Bar
	title := "  HOME NETWORK WATCH (HNW) "
	if m.isDemo {
		title += demoBadge.Render("DEMO MODE") + " "
	}
	topBar := headerStyle.Render(title)

	// Health status summary
	var healthParts []string
	if len(m.healths) > 0 {
		for _, h := range m.healths {
			color := "#10B981" // green
			if h.Status == models.StatusDegraded {
				color = "#F59E0B" // amber
			} else if h.Status == models.StatusError {
				color = "#EF4444" // red
			}
			tag := lipgloss.NewStyle().Foreground(lipgloss.Color(color)).Bold(true).Render(h.Status)
			healthParts = append(healthParts, fmt.Sprintf("%s: %s", h.Name, tag))
		}
	} else {
		healthParts = append(healthParts, "Collectors: Initializing")
	}
	healthSummary := strings.Join(healthParts, "  │  ")

	b.WriteString(fmt.Sprintf("%s   %s\n\n", topBar, healthSummary))

	// Tab Bar
	tabs := []string{"[1] Overview", "[2] DNS Details", "[3] WireGuard", "[4] Alerts"}
	var renderedTabs []string
	for i, tab := range tabs {
		if i == m.activeTab {
			renderedTabs = append(renderedTabs, tabActiveStyle.Render(tab))
		} else {
			renderedTabs = append(renderedTabs, tabInactiveStyle.Render(tab))
		}
	}
	b.WriteString(strings.Join(renderedTabs, " ") + "\n\n")

	// Tab Content
	switch m.activeTab {
	case TabOverview:
		b.WriteString(m.renderOverview())
	case TabDNS:
		b.WriteString(m.renderDNS())
	case TabWG:
		b.WriteString(m.renderWG())
	case TabAlerts:
		b.WriteString(m.renderAlerts())
	}

	// Status Message
	if m.statusMsg != "" && time.Since(m.statusTime) < 10*time.Second {
		b.WriteString(fmt.Sprintf("\n  ▶ %s\n", lipgloss.NewStyle().Foreground(lipgloss.Color("#FCD34D")).Render(m.statusMsg)))
	} else {
		b.WriteString("\n")
	}

	// Footer
	b.WriteString(footerStyle.Render("Keybindings: [Tab/1-4] Switch Tab  •  [r] Resolve Alert  •  [s] Force Snapshot  •  [q] Quit"))
	b.WriteString("\n")

	return b.String()
}

func (m Model) renderOverview() string {
	if m.snapshot == nil {
		return "  Collecting initial telemetry snapshot...\n"
	}

	// KPI Cards
	dns := m.snapshot.DNSMetrics
	blockPct := dns.BlockedPercentage()

	card1 := cardStyle.Render(fmt.Sprintf("TOTAL QUERIES\n\n%s", lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#38BDF8")).Render(formatNumber(dns.TotalQueries))))
	card2 := cardStyle.Render(fmt.Sprintf("BLOCKED QUERIES\n\n%s", lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#F87171")).Render(formatNumber(dns.BlockedQueries))))
	card3 := cardStyle.Render(fmt.Sprintf("BLOCK RATE\n\n%s", lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FBBF24")).Render(fmt.Sprintf("%.1f%%", blockPct))))

	activePeers := 0
	for _, p := range m.snapshot.WireGuardState {
		if !p.LatestHandshake.IsZero() && time.Since(p.LatestHandshake) < 5*time.Minute {
			activePeers++
		}
	}
	card4 := cardStyle.Render(fmt.Sprintf("ACTIVE WG PEERS\n\n%s", lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#34D399")).Render(fmt.Sprintf("%d / %d", activePeers, len(m.snapshot.WireGuardState)))))

	cardsRow := lipgloss.JoinHorizontal(lipgloss.Top, card1, "  ", card2, "  ", card3, "  ", card4)

	// Recent critical alerts summary
	var alertLines []string
	unresolvedCount := 0
	for _, a := range m.alerts {
		if !a.Resolved {
			unresolvedCount++
			if len(alertLines) < 4 {
				style := alertInfoStyle
				if a.Severity == models.SeverityCritical {
					style = alertCriticalStyle
				} else if a.Severity == models.SeverityWarning {
					style = alertWarningStyle
				}
				alertLines = append(alertLines, fmt.Sprintf("  • %s [%s] %s (%s)", style.Render(a.Severity), a.Type, a.Description, a.Timestamp.Format("15:04:05")))
			}
		}
	}

	alertsHeader := fmt.Sprintf("  ACTIVE ALERTS (%d pending)", unresolvedCount)
	if unresolvedCount == 0 {
		alertLines = append(alertLines, "  ✓ No active anomalies detected. Network baseline normal.")
	}

	return fmt.Sprintf("%s\n\n%s\n%s\n", cardsRow, lipgloss.NewStyle().Bold(true).Render(alertsHeader), strings.Join(alertLines, "\n"))
}

func (m Model) renderDNS() string {
	if m.snapshot == nil {
		return "  No DNS telemetry available.\n"
	}

	dns := m.snapshot.DNSMetrics

	// Top Domains Table
	type kv struct {
		Key   string
		Value int
	}
	var domains []kv
	for k, v := range dns.TopDomains {
		domains = append(domains, kv{k, v})
	}
	sort.Slice(domains, func(i, j int) bool {
		return domains[i].Value > domains[j].Value
	})

	var domLines []string
	domLines = append(domLines, tableHeaderStyle.Render(fmt.Sprintf("%-38s %10s", "TOP DOMAIN", "QUERIES")))
	for i, d := range domains {
		if i >= 10 {
			break
		}
		domLines = append(domLines, fmt.Sprintf("%-38s %10s", truncate(d.Key, 38), formatNumber(int64(d.Value))))
	}
	domTable := lipgloss.JoinVertical(lipgloss.Left, domLines...)

	// Top Clients Table
	var clients []kv
	for k, v := range dns.ActiveClients {
		clients = append(clients, kv{k, v})
	}
	sort.Slice(clients, func(i, j int) bool {
		return clients[i].Value > clients[j].Value
	})

	var cliLines []string
	cliLines = append(cliLines, tableHeaderStyle.Render(fmt.Sprintf("%-24s %10s", "CLIENT IP / DEVICE", "QUERIES")))
	for i, c := range clients {
		if i >= 10 {
			break
		}
		cliLines = append(cliLines, fmt.Sprintf("%-24s %10s", c.Key, formatNumber(int64(c.Value))))
	}
	cliTable := lipgloss.JoinVertical(lipgloss.Left, cliLines...)

	tablesRow := lipgloss.JoinHorizontal(lipgloss.Top,
		lipgloss.NewStyle().Padding(0, 2).Render(domTable),
		"    ",
		lipgloss.NewStyle().Padding(0, 2).Render(cliTable),
	)

	return tablesRow + "\n"
}

func (m Model) renderWG() string {
	if m.snapshot == nil || len(m.snapshot.WireGuardState) == 0 {
		return "  No WireGuard peers configured or reachable.\n"
	}

	var lines []string
	lines = append(lines, tableHeaderStyle.Render(fmt.Sprintf("%-14s %-22s %-16s %-16s %12s %12s", "PEER KEY", "ENDPOINT", "ALLOWED IPS", "LAST HANDSHAKE", "RX BYTES", "TX BYTES")))

	for _, p := range m.snapshot.WireGuardState {
		hsStr := "Never"
		if !p.LatestHandshake.IsZero() {
			ago := time.Since(p.LatestHandshake).Round(time.Second)
			if ago < time.Minute {
				hsStr = fmt.Sprintf("%ds ago", int(ago.Seconds()))
			} else if ago < time.Hour {
				hsStr = fmt.Sprintf("%dm ago", int(ago.Minutes()))
			} else {
				hsStr = fmt.Sprintf("%dh ago", int(ago.Hours()))
			}
		}

		ips := strings.Join(p.AllowedIPs, ", ")
		if ips == "" {
			ips = "(none)"
		}

		lines = append(lines, fmt.Sprintf("%-14s %-22s %-16s %-16s %12s %12s",
			p.TruncatedKey(),
			truncate(p.Endpoint, 22),
			truncate(ips, 16),
			hsStr,
			formatBytes(p.RxBytes),
			formatBytes(p.TxBytes),
		))
	}

	return strings.Join(lines, "\n") + "\n"
}

func (m Model) renderAlerts() string {
	if len(m.alerts) == 0 {
		return "  No alert history recorded yet.\n"
	}

	var lines []string
	lines = append(lines, tableHeaderStyle.Render(fmt.Sprintf("  %-4s %-10s %-16s %-48s %-10s", "ID", "SEVERITY", "TYPE", "DESCRIPTION", "STATUS")))

	for i, a := range m.alerts {
		prefix := "  "
		if i == m.selectedAlert {
			prefix = "▶ "
		}

		sevStyle := alertInfoStyle
		switch a.Severity {
		case models.SeverityCritical:
			sevStyle = alertCriticalStyle
		case models.SeverityWarning:
			sevStyle = alertWarningStyle
		}

		statusStr := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#EF4444")).Render("ACTIVE")
		if a.Resolved {
			statusStr = alertResolvedStyle.Render("RESOLVED")
		}

		line := fmt.Sprintf("%s%-4d %-10s %-16s %-48s %s",
			prefix,
			a.ID,
			sevStyle.Render(a.Severity),
			a.Type,
			truncate(a.Description, 48),
			statusStr,
		)

		if i == m.selectedAlert {
			line = lipgloss.NewStyle().Background(lipgloss.Color("#1F2937")).Render(line)
		}

		lines = append(lines, line)
	}

	return strings.Join(lines, "\n") + "\n"
}

func formatNumber(n int64) string {
	in := fmt.Sprintf("%d", n)
	var out []byte
	for i, c := range in {
		if i > 0 && (len(in)-i)%3 == 0 {
			out = append(out, ',')
		}
		out = append(out, byte(c))
	}
	return string(out)
}

func formatBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	if max <= 1 {
		return s[:max]
	}
	return s[:max-1] + "…"
}
