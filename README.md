# Home Network Watch (HNW)

A local-first, privacy-respecting network observability and anomaly detection tool for home infrastructure.

HNW aggregates and analyzes telemetry from local DNS servers (Pi-hole) and VPN gateways (WireGuard) to provide immediate visibility into DNS traffic, client query behaviors, and peer connection states directly inside your terminal—without external cloud dependencies or deep packet inspection.

![Home Network Watch TUI Dashboard](docs/screenshot.png)

*Genuine TUI capture running offline demo mode with synthetic DNS and WireGuard telemetry.*

---

## Key Features

- **Terminal-Native Dashboard:** Responsive, keyboard-driven Terminal User Interface (TUI) built with Bubble Tea and Lip Gloss.
- **Privacy-First & Local-Only:** All metrics, snapshots, and alerts are stored in a local SQLite database. No external cloud sync, telemetry, or remote dependencies.
- **DNS Telemetry & Insights:** Polls Pi-hole API for total volume, blocked query percentage, top requested domains, and top querying clients.
- **WireGuard Peer Monitoring:** Parses WireGuard interface status, tracking handshake recency, transfer counters (Rx/Tx), and peer activity.
- **Automated Anomaly Detection:**
  - **New Client Detection:** Alerts when an unrecognized device queries the local DNS infrastructure.
  - **DNS Volume Spikes:** Compares current query rates against a rolling 24-hour baseline.
  - **WireGuard Inactivity & Reconnect:** Flags dormant peers reconnecting after prolonged inactivity (>30 days).
  - **Alert Cooldown:** Suppresses duplicate notifications during configurable cooldown windows.
- **Zero-Dependency Static Binary:** Compiles into a single, self-contained Go binary (`CGO_ENABLED=0`) with embedded pure-Go SQLite (`modernc.org/sqlite`).
- **Deterministic Offline Demo Mode:** Explore the full interface and anomaly alerting without live network infrastructure via `hnw demo`.
- **Scriptable CLI:** Includes non-interactive subcommands (`hnw snapshot`, `hnw status`) suitable for cron tasks and automation.

---

## Architecture Overview

```
                      ┌──────────────────────┐
                      │    Configuration     │
                      │    (config.json)     │
                      └──────────┬───────────┘
                                 │
                 ┌───────────────┴───────────────┐
                 ▼                               ▼
       ┌───────────────────┐           ┌───────────────────┐
       │ Pi-hole Collector │           │ WireGuard Parser  │
       │  (HTTP / Admin)   │           │    (wg show)      │
       └─────────┬─────────┘           └─────────┬─────────┘
                 │                               │
                 └───────────────┬───────────────┘
                                 ▼
                     ┌───────────────────────┐
                     │    Snapshot Engine    │
                     └───────────┬───────────┘
                                 │
        ┌────────────────────────┼────────────────────────┐
        ▼                        ▼                        ▼
┌───────────────┐        ┌───────────────┐        ┌───────────────┐
│ Local SQLite  │◄───────┤    Anomaly    │        │  Bubble Tea   │
│  Persistence  │        │    Engine     │        │ TUI Dashboard │
└───────────────┘        └───────────────┘        └───────────────┘
```

---

## Installation

### Pre-Built Binaries
Download the latest static binary release for Linux (`amd64` or `arm64`) from the [Releases](https://github.com/khalid7344/home-network-watch/releases) page:

```bash
# Example for Linux amd64
tar -xzf hnw_v1.0.0_linux_amd64.tar.gz
chmod +x hnw
sudo mv hnw /usr/local/bin/
```

### Build From Source
Requires Go 1.22+:

```bash
git clone https://github.com/khalid7344/home-network-watch.git
cd home-network-watch
CGO_ENABLED=0 go build -ldflags="-s -w" -o hnw ./cmd/hnw
```

---

## Quick Start & Demo Mode

You can run HNW immediately without configuring Pi-hole or WireGuard:

```bash
./hnw demo
```

To pipe synthetic JSON telemetry to stdout:

```bash
./hnw demo --json
```

---

## Configuration

Create a `config.json` file in your working directory or pass `--config <path>`:

```json
{
  "pihole": {
    "enabled": true,
    "url": "http://pi.hole",
    "token": "YOUR_PIHOLE_API_TOKEN"
  },
  "wireguard": {
    "enabled": true,
    "interface": "wg0"
  },
  "anomaly_engine": {
    "dns_spike_threshold_percent": 200,
    "alert_cooldown_minutes": 60,
    "wg_inactivity_days": 30
  },
  "storage": {
    "db_path": "hnw.db",
    "retention_days": 30
  },
  "poll_interval_seconds": 300
}
```

### Environment Variable Overrides
Configuration parameters can also be supplied via environment variables:
- `HNW_PIHOLE_TOKEN`: Overrides `pihole.token`
- `HNW_PIHOLE_URL`: Overrides `pihole.url`
- `HNW_DB_PATH`: Overrides `storage.db_path`

---

## Usage

### Interactive TUI
Launch the background engine and live interactive dashboard:

```bash
hnw start --config config.json
```

#### Keyboard Shortcuts
| Key | Action |
|---|---|
| `Tab` / `Shift+Tab` | Cycle through dashboard tabs |
| `1`, `2`, `3`, `4` | Directly select tabs (Overview, DNS, WireGuard, Alerts) |
| `↑` / `k`, `↓` / `j` | Navigate through alert history |
| `r` | Mark highlighted alert as resolved |
| `s` | Trigger immediate snapshot refresh |
| `q` / `Ctrl+C` | Quit application |

### CLI & Automation Commands

**Record Snapshot (Cron Mode):**
```bash
hnw snapshot --db /var/lib/hnw/hnw.db
```

**Query Status & Health:**
```bash
hnw status --db /var/lib/hnw/hnw.db
```

**Output JSON for Scripting:**
```bash
hnw status --json --db /var/lib/hnw/hnw.db
```

---

## Security Model

1. **Least Privilege:** HNW runs as an unprivileged user process. Root access is never required.
2. **WireGuard Inspection:** WireGuard metrics are fetched via direct argument execution (`os/exec`) preventing shell injection. If `wg show` requires elevated permissions, configure passwordless sudo strictly for `wg show`:
   ```text
   youruser ALL=(ALL) NOPASSWD: /usr/bin/wg show * dump
   ```
3. **No Private Keys Stored:** HNW only reads public keys, endpoint IPs, and byte transfer metrics. Interface private keys and preshared keys are never extracted, logged, or written to SQLite.
4. **Token Redaction:** API tokens are redacted in error messages, status screens, and logs.

---

## Development & Testing

Run all unit tests:
```bash
go test -v ./...
```

Run race detector:
```bash
go test -v -race ./...
```

Run linter / static analysis:
```bash
go vet ./...
```

---

## License

MIT License. See [LICENSE](LICENSE) for details.
