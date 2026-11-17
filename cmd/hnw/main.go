package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/khalid7344/home-network-watch/internal/collector"
	"github.com/khalid7344/home-network-watch/internal/collector/demo"
	"github.com/khalid7344/home-network-watch/internal/collector/pihole"
	"github.com/khalid7344/home-network-watch/internal/collector/wireguard"
	"github.com/khalid7344/home-network-watch/internal/config"
	"github.com/khalid7344/home-network-watch/internal/engine"
	"github.com/khalid7344/home-network-watch/internal/engine/anomaly"
	"github.com/khalid7344/home-network-watch/internal/models"
	"github.com/khalid7344/home-network-watch/internal/storage/sqlite"
	"github.com/khalid7344/home-network-watch/internal/ui/tui"
)

const version = "1.0.1"

func printUsage() {
	fmt.Printf(`Home Network Watch (HNW) v%s
A local-first, privacy-respecting network observability and anomaly detection tool.

Usage:
  hnw [command] [flags]

Available Commands:
  start     Launch the background collection engine and interactive TUI
  demo      Run HNW in offline demo mode using synthetic telemetry
  snapshot  Force an immediate collection and anomaly evaluation (cron-friendly)
  status    Print non-interactive summary of collector health and active alerts
  version   Print version information

Flags:
  -c, --config string   Path to config.json file (default "config.json")
  -d, --db string       Path to SQLite database file
      --json            Output results in JSON format (for demo, snapshot, status)
  -h, --help            Show help
  -v, --version         Show version

`, version)
}

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "-h", "--help", "help":
			printUsage()
			os.Exit(0)
		case "-v", "--version", "version":
			fmt.Printf("hnw version %s\n", version)
			os.Exit(0)
		}
	}

	cmd := "start"
	args := os.Args[1:]

	if len(os.Args) > 1 && !strings.HasPrefix(os.Args[1], "-") {
		cmd = os.Args[1]
		args = os.Args[2:]
	}

	fs := flag.NewFlagSet("hnw", flag.ExitOnError)
	configPath := fs.String("config", "config.json", "Path to config file")
	fs.StringVar(configPath, "c", "config.json", "Path to config file (shorthand)")
	dbPathOverride := fs.String("db", "", "Path to SQLite database")
	fs.StringVar(dbPathOverride, "d", "", "Path to SQLite database (shorthand)")
	jsonOutput := fs.Bool("json", false, "Output results as JSON")

	_ = fs.Parse(args)

	cfg, err := config.Load(*configPath)
	if err != nil {
		// If custom config wasn't specified and default config.json is missing, use defaults
		if *configPath == "config.json" {
			cfg = config.DefaultConfig()
		} else {
			fmt.Fprintf(os.Stderr, "Error loading configuration: %v\n", err)
			os.Exit(1)
		}
	}

	if *dbPathOverride != "" {
		cfg.Storage.DBPath = *dbPathOverride
	}

	switch cmd {
	case "demo":
		runDemo(cfg, *jsonOutput)
	case "snapshot":
		runSnapshot(cfg, *jsonOutput)
	case "status":
		runStatus(cfg, *jsonOutput)
	case "start":
		runStart(cfg)
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\nRun 'hnw --help' for usage.\n", cmd)
		os.Exit(1)
	}
}

func runDemo(cfg *config.Config, forceJSON bool) {
	demoCol := demo.New()

	// If stdout is not a terminal or JSON output was explicitly requested, print synthetic JSON
	if forceJSON || !isTerminal(os.Stdout) {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		snap, healths, err := demoCol.CollectSnapshot(ctx)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Demo collection failed: %v\n", err)
			os.Exit(1)
		}
		out := map[string]any{
			"snapshot": snap,
			"health":   healths,
		}
		data, _ := json.MarshalIndent(out, "", "  ")
		fmt.Println(string(data))
		return
	}

	// Use temporary SQLite database in demo mode to keep demo clean
	dbPath := "hnw_demo.db"
	store, err := sqlite.New(dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed opening demo database (%v), continuing in-memory\n", err)
		store, _ = sqlite.New(":memory:")
	}
	if store != nil {
		defer store.Close()
	}

	anomalyEng := anomaly.New(cfg.AnomalyEngine, store)
	eng := engine.NewSnapshotEngine(demoCol, demoCol, store, anomalyEng)

	// Pre-seed baseline snapshot and a simulated alert so demo UI has immediate rich content
	ctx := context.Background()
	_, _, _, _ = eng.CollectAndProcess(ctx)
	if store != nil {
		_, _ = store.SaveAlert(&models.Alert{
			Timestamp:   time.Now().Add(-14 * time.Minute),
			Severity:    models.SeverityWarning,
			Type:        models.AlertTypeNewClient,
			Description: "New device detected on network: 192.168.1.185",
			Resolved:    false,
		})
	}

	p := tea.NewProgram(tui.NewModel(eng, store, true), tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error running demo TUI: %v\n", err)
		os.Exit(1)
	}
}

func runStart(cfg *config.Config) {
	store, err := sqlite.New(cfg.Storage.DBPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to initialize storage at %s: %v\n", cfg.Storage.DBPath, err)
		os.Exit(1)
	}
	defer store.Close()

	var dnsCol collector.DNSCollector
	if cfg.Pihole.Enabled {
		dnsCol = pihole.New(cfg.Pihole.URL, cfg.Pihole.Token, 5*time.Second)
	}

	var wgCol collector.WireGuardCollector
	if cfg.Wireguard.Enabled {
		wgCol = wireguard.New(cfg.Wireguard.Interface, nil)
	}

	anomalyEng := anomaly.New(cfg.AnomalyEngine, store)
	eng := engine.NewSnapshotEngine(dnsCol, wgCol, store, anomalyEng)

	p := tea.NewProgram(tui.NewModel(eng, store, false), tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error running TUI: %v\n", err)
		os.Exit(1)
	}
}

func runSnapshot(cfg *config.Config, forceJSON bool) {
	store, err := sqlite.New(cfg.Storage.DBPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to initialize storage: %v\n", err)
		os.Exit(1)
	}
	defer store.Close()

	var dnsCol collector.DNSCollector
	if cfg.Pihole.Enabled {
		dnsCol = pihole.New(cfg.Pihole.URL, cfg.Pihole.Token, 5*time.Second)
	}
	var wgCol collector.WireGuardCollector
	if cfg.Wireguard.Enabled {
		wgCol = wireguard.New(cfg.Wireguard.Interface, nil)
	}

	anomalyEng := anomaly.New(cfg.AnomalyEngine, store)
	eng := engine.NewSnapshotEngine(dnsCol, wgCol, store, anomalyEng)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	snap, healths, alerts, err := eng.CollectAndProcess(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Snapshot collection error: %v\n", err)
		os.Exit(1)
	}

	if forceJSON {
		out := map[string]any{
			"snapshot": snap,
			"health":   healths,
			"alerts":   alerts,
		}
		data, _ := json.MarshalIndent(out, "", "  ")
		fmt.Println(string(data))
		return
	}

	fmt.Printf("Snapshot recorded successfully at %s (ID: %d)\n", snap.Timestamp.Format(time.RFC3339), snap.ID)
	fmt.Printf("  • DNS: %d total queries, %d blocked (%.1f%%)\n", snap.DNSMetrics.TotalQueries, snap.DNSMetrics.BlockedQueries, snap.DNSMetrics.BlockedPercentage())
	fmt.Printf("  • WireGuard: %d peers observed\n", len(snap.WireGuardState))
	for _, h := range healths {
		fmt.Printf("  • Health: %s [%s] %s\n", h.Name, h.Status, h.Message)
	}
	if len(alerts) > 0 {
		fmt.Printf("  • Anomaly alerts triggered: %d\n", len(alerts))
		for _, a := range alerts {
			fmt.Printf("    - [%s] %s: %s\n", a.Severity, a.Type, a.Description)
		}
	} else {
		fmt.Println("  • No new anomaly alerts.")
	}
}

func runStatus(cfg *config.Config, forceJSON bool) {
	store, err := sqlite.New(cfg.Storage.DBPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to initialize storage: %v\n", err)
		os.Exit(1)
	}
	defer store.Close()

	latestSnap, _ := store.GetLatestSnapshot()
	unresolved := false
	activeAlerts, _ := store.GetAlerts(&unresolved, 20)

	if forceJSON {
		out := map[string]any{
			"latest_snapshot": latestSnap,
			"active_alerts":   activeAlerts,
		}
		data, _ := json.MarshalIndent(out, "", "  ")
		fmt.Println(string(data))
		return
	}

	fmt.Println("=== Home Network Watch (HNW) Status ===")
	if latestSnap != nil {
		fmt.Printf("Latest Snapshot: %s\n", latestSnap.Timestamp.Format(time.RFC3339))
		fmt.Printf("  Total DNS Queries: %d (Blocked: %d, %.1f%%)\n",
			latestSnap.DNSMetrics.TotalQueries,
			latestSnap.DNSMetrics.BlockedQueries,
			latestSnap.DNSMetrics.BlockedPercentage(),
		)
		fmt.Printf("  WireGuard Peers: %d\n", len(latestSnap.WireGuardState))
	} else {
		fmt.Println("No historical snapshots found in database.")
	}

	fmt.Printf("\nActive Alerts: %d\n", len(activeAlerts))
	for _, a := range activeAlerts {
		fmt.Printf("  [%s] #%d %s: %s (%s)\n", a.Severity, a.ID, a.Type, a.Description, a.Timestamp.Format(time.RFC3339))
	}
}

func isTerminal(f *os.File) bool {
	stat, err := f.Stat()
	if err != nil {
		return false
	}
	return (stat.Mode() & os.ModeCharDevice) != 0
}
