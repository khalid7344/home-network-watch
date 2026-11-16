```markdown
# Home Network Watch (HNW) — System Specification

Status: READY FOR IMPLEMENTATION

## 1. Executive Summary
Home Network Watch (HNW) is a local-first, privacy-respecting network observability and anomaly detection tool. It aggregates and analyzes data from existing home network infrastructure (specifically Pi-hole and WireGuard) to provide actionable insights into DNS traffic and VPN peer activity without relying on external cloud services or packet inspection. 

## 2. Problem Statement
Home network administrators often lack a unified, easily accessible dashboard for monitoring local infrastructure health and identifying unusual activity. Existing solutions are often overly complex (requiring Kubernetes or heavy containerized stacks), privacy-invasive (relying on cloud telemetry), or require invasive network monitoring techniques (deep packet inspection). There is a need for a lightweight, secure, and privacy-respecting tool that provides immediate visibility into DNS behavior and VPN usage directly from a terminal.

## 3. Project Goals
*   **Unified Observability:** Provide a single dashboard for Pi-hole DNS metrics and WireGuard VPN status.
*   **Privacy First:** Ensure all data collection, storage, and processing remain strictly local.
*   **Lightweight:** Implement as a single, zero-dependency Go binary.
*   **Terminal Native:** Deliver a responsive, keyboard-driven Terminal User Interface (TUI) using Bubble Tea.
*   **Anomaly Detection:** Identify and alert on unusual patterns in DNS volume, domain requests, and VPN peer handshakes.
*   **Developer Friendly:** Provide a robust 'demo mode' utilizing synthetic data for development and demonstration without requiring a live Pi-hole or WireGuard setup.

## 4. Non-Goals (Out of Scope)
*   Modifying Pi-hole or WireGuard configurations.
*   Deep Packet Inspection (DPI) or payload analysis.
*   Active network scanning or intrusion prevention (IPS).
*   Cloud synchronization, remote telemetry, or mandatory central logging.
*   Kubernetes or Docker deployment requirements (though Dockerization is possible, it is not the primary deployment target).
*   Supporting paid or enterprise network appliances.

## 5. User Stories
*   **As a home network admin**, I want to see a summary of my Pi-hole DNS traffic (top domains, blocked percentage) in my terminal so I can quickly assess network health.
*   **As a privacy advocate**, I want to be alerted if a new, previously unseen device starts making DNS requests on my network.
*   **As a VPN user**, I want to see which WireGuard peers have recently completed a handshake so I know who is actively connected.
*   **As a developer**, I want to run HNW in 'demo mode' on my laptop so I can contribute to the UI without needing a complex home lab setup.
*   **As a security-conscious user**, I want assurance that HNW will never modify my network settings or export my DNS history.

## 6. Functional Requirements
*   **REQ-F01 (Pi-hole Collection):** Authenticate with and fetch statistics (top domains, active clients, block rates) from the Pi-hole API. [Priority: P0]
*   **REQ-F02 (WireGuard Collection):** Parse `wg show` output to extract peer identifiers, handshake times, and transfer statistics. [Priority: P0]
*   **REQ-F03 (Data Persistence):** Store aggregated metrics and alerts locally in a SQLite database using periodic snapshots. [Priority: P0]
*   **REQ-F04 (Anomaly Engine):** Evaluate snapshots against configured rules (e.g., volume spikes, new clients) and generate alerts. [Priority: P1]
*   **REQ-F05 (TUI Dashboard):** Display real-time and historical data, alerts, and collector health in a Bubble Tea TUI. [Priority: P0]
*   **REQ-F06 (Demo Mode):** Generate deterministic, synthetic data for all collectors and the anomaly engine when invoked with `hnw demo`. [Priority: P0]
*   **REQ-F07 (CLI Mode):** Provide non-interactive commands (e.g., `hnw snapshot`, `hnw status`) for scripting and cron execution. [Priority: P1]

## 7. Nonfunctional Requirements
*   **Performance:** The TUI must remain responsive (60fps target) regardless of background collection or database queries.
*   **Reliability:** The application must not crash if Pi-hole or WireGuard are unreachable; it must gracefully report collector health degradation.
*   **Security:** HNW must run with the least privilege necessary. Root access is strictly prohibited unless explicitly required for `wg show` (and even then, alternatives like `sudo` configurations should be prioritized).
*   **Portability:** Compile to a single static binary for Linux (amd64/arm64).

## 8. Architecture Overview
HNW employs a modular, event-driven architecture within a single Go process.

1.  **Configuration Manager:** Loads settings from a local JSON/YAML file.
2.  **Collectors (Pi-hole, WireGuard, Demo):** Periodically poll data sources and emit normalized metric structs.
3.  **Snapshot Engine:** Receives metrics, aggregates them, and writes them to the SQLite database.
4.  **Anomaly Engine:** Analyzes new snapshots against historical baselines in SQLite and generates Alert events.
5.  **TUI / CLI Presentation:** Subscribes to the Snapshot Engine and Anomaly Engine to render the current state.

## 9. Component Responsibilities
*   **`config`:** Parses and validates `config.json`. Manages Pi-hole API tokens and thresholds.
*   **`collector/pihole`:** Handles HTTP requests to the Pi-hole API, parsing JSON responses into internal models.
*   **`collector/wireguard`:** Executes `wg show all dump` (or parses similar output) and formats peer data.
*   **`collector/demo`:** Implements the collector interface using synthetic, hardcoded, or procedurally generated data patterns.
*   **`storage/sqlite`:** Manages the database schema, migrations, and CRUD operations for snapshots and alerts.
*   **`engine/anomaly`:** Implements the logic for detecting spikes, new clients, and unexpected WireGuard activity.
*   **`ui/tui`:** Manages the Bubble Tea application state, views, and update loops.

## 10. Directory Structure

```

home-network-watch/
├── cmd/
│   └── hnw/          # Main application entrypoint
├── internal/
│   ├── config/       # Configuration parsing and validation
│   ├── collector/    # Data gathering (Pi-hole, WireGuard, Demo)
│   ├── models/       # Shared data structures
│   ├── storage/      # SQLite implementation and queries
│   ├── engine/       # Anomaly detection logic
│   └── ui/           # Bubble Tea TUI components
├── pkg/              # Publicly importable utilities (if any)
├── tests/            # Integration and end-to-end tests
├── demo/             # Synthetic data fixtures for testing/demo mode
├── PROJECT.md        # This specification
├── AGENTS.md         # Autonomous agent instructions
├── README.md         # Public documentation
├── go.mod
└── go.sum

```

## 11. Data Models
```go
// internal/models/models.go

type Snapshot struct {
    Timestamp      time.Time
    DNSMetrics     DNSMetrics
    WireGuardState []WGPeerState
}

type DNSMetrics struct {
    TotalQueries int64
    BlockedQueries int64
    TopDomains   map[string]int
    ActiveClients map[string]int
}

type WGPeerState struct {
    PublicKey      string
    LatestHandshake time.Time // Zero value if no recent handshake
    RxBytes        int64
    TxBytes        int64
}

type Alert struct {
    ID          string
    Timestamp   time.Time
    Severity    string // INFO, WARNING, CRITICAL
    Type        string // e.g., "NEW_CLIENT", "DNS_SPIKE"
    Description string
}

```

## 12. Pi-hole Integration Design

* **Authentication:** The Pi-hole API token will be provided via `config.json` or an environment variable (`HNW_PIHOLE_TOKEN`).
* **Endpoints:**
* `api.php?summaryRaw` (Total queries, blocked percentage)
* `api.php?topItems=10` (Top domains and clients)


* **Resilience:** The collector must handle connection timeouts, invalid JSON responses, and HTTP error codes gracefully, returning an error to the Snapshot Engine rather than panicking.

## 13. WireGuard Integration Design

* **Collection Method:** Execute `wg show all dump` (or parse a provided mock file).
* **Security:** HNW will not run as root. It is expected that the user configures `sudo` without a password for the `wg show` command specifically for the user running HNW, or runs HNW in an environment where `wg show` is accessible.
* **Data Handling:** Public keys will be truncated (e.g., first 8 characters) in the UI for readability. A "handshake unknown" state must be clearly distinguished from a recent handshake.

## 14. SQLite Schema

```sql
CREATE TABLE snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    total_queries INTEGER,
    blocked_queries INTEGER,
    data JSON -- Stores serialized TopDomains, ActiveClients, and WGPeerState to avoid complex relational mapping for snapshots
);

CREATE TABLE alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    severity TEXT,
    alert_type TEXT,
    description TEXT,
    resolved BOOLEAN DEFAULT 0
);

```

## 15. Snapshot Processing

1. A ticker triggers the snapshot process (e.g., every 5 minutes).
2. The Snapshot Engine concurrently requests data from enabled collectors.
3. Collector results are aggregated into a `Snapshot` struct.
4. The snapshot is serialized and inserted into the `snapshots` SQLite table.
5. The Anomaly Engine is triggered with the new snapshot ID.
6. The TUI receives an event that a new snapshot is available.

## 16. Anomaly Detection Algorithms

* **New Client:** Compare the `ActiveClients` in the current snapshot against a set of all known clients from the past 7 days. If a client IP/MAC is not in the historical set, generate a `NEW_CLIENT` alert.
* **DNS Spike:** Calculate the rolling average of `total_queries` over the last 24 hours. If the current snapshot's `total_queries` exceeds the average by a configurable threshold (e.g., > 200%), generate a `DNS_SPIKE` alert.
* **WG Inactivity:** If a configured peer has a `LatestHandshake` older than a configurable threshold (e.g., 30 days) and then suddenly registers a new handshake, generate a `WG_RECONNECT` alert.

## 17. Alert Lifecycle

* **Generation:** Alerts are created by the Anomaly Engine and stored in the `alerts` table.
* **Display:** Unresolved alerts are prioritized in the TUI dashboard.
* **Resolution:** Users can mark alerts as "resolved" via the TUI, which updates the `resolved` boolean in the database.
* **Cooldown:** The Anomaly Engine will suppress duplicate alerts (e.g., repeated `DNS_SPIKE` alerts for the same spike event) for a configurable cooldown period.

## 18. TUI Design

The Bubble Tea interface will use a tabbed or panel layout:

* **Header:** Application title, current time, and overall collector health status (e.g., "Pi-hole: OK | WG: Err").
* **Main Content Area (Tabs):**
* **Overview:** High-level metrics (Total DNS, Block %, Active WG Peers) and recent critical alerts.
* **DNS Details:** Tables for Top Domains and Top Clients.
* **WireGuard:** Table of peers with Last Handshake, Rx, and Tx.
* **Alerts:** Scrollable list of active and historical alerts.


* **Footer:** Keybindings (e.g., `q` to quit, `tab` to switch views, `r` to resolve alert).

## 19. CLI Commands

* `hnw start`: Launches the background collection engine and the TUI.
* `hnw demo`: Launches HNW using the `collector/demo` implementation.
* `hnw snapshot`: Forces an immediate data collection and anomaly evaluation (useful for cron jobs).
* `hnw status`: Prints a brief, non-interactive text summary of current collector health and active alerts.

## 20. Configuration Schema

```json
{
  "pihole": {
    "enabled": true,
    "url": "[http://pi.hole](http://pi.hole)",
    "token": "YOUR_API_TOKEN_HERE"
  },
  "wireguard": {
    "enabled": true,
    "interface": "wg0"
  },
  "anomaly_engine": {
    "dns_spike_threshold_percent": 200,
    "alert_cooldown_minutes": 60
  },
  "storage": {
    "db_path": "/var/lib/hnw/hnw.db",
    "retention_days": 30
  }
}

```

## 21. Security Model

* **Least Privilege:** HNW operates as a standard user. It does not require root.
* **Credential Storage:** Pi-hole tokens are read from the configuration file, which must be secured by the user with appropriate OS-level permissions (e.g., `0600`).
* **Data Protection:** The SQLite database contains historical network metadata but no packet payloads or private keys. The database file must also be secured via OS permissions.
* **Command Execution:** Calls to `wg show` use the `os/exec` package with strictly defined arguments, preventing shell injection vulnerabilities.

## 22. Testing Strategy

* **Unit Tests:** Verify parsing logic in collectors (especially `wg show` parsing) and anomaly detection algorithms.
* **Mocking:** Create mock HTTP servers to simulate Pi-hole API responses (success, error, timeout).
* **Fixtures:** Use static text files containing sample `wg show` output for testing the WireGuard collector.
* **Integration Tests:** Verify that the Snapshot Engine correctly writes to an in-memory SQLite database and that the Anomaly Engine reads from it correctly.
* **Demo Mode Tests:** Ensure `hnw demo` functions without any external dependencies or network access.

## 23. Milestones M1–M8

### M1 — Repository foundation and demo data

* **Scope:** Initialize project structure, configuration parser, and the `demo` collector.
* **Deliverables:** Basic Go module, `config.json` parsing, `collector/demo` generating synthetic DNS and WG data.
* **Verification:** `go test ./...` passes; `hnw demo` prints synthetic JSON data to stdout (no TUI yet).

### M2 — Pi-hole collector

* **Scope:** Implement the Pi-hole HTTP client and data parsing.
* **Deliverables:** `collector/pihole` module.
* **Verification:** Unit tests with HTTP mocks pass. Can successfully fetch data from a real or simulated Pi-hole instance.

### M3 — WireGuard collector

* **Scope:** Implement `wg show` execution and parsing.
* **Deliverables:** `collector/wireguard` module.
* **Verification:** Unit tests against text fixtures pass. Correctly handles missing `wg` executable gracefully.

### M4 — SQLite snapshots and history

* **Scope:** Implement the SQLite storage engine and periodic snapshot logic.
* **Deliverables:** `storage/sqlite` module, database schema, snapshot ticker.
* **Verification:** Integration tests verify data is correctly written to and read from a temporary SQLite file.

### M5 — Anomaly detection and alerts

* **Scope:** Implement the baseline calculation and alerting rules.
* **Deliverables:** `engine/anomaly` module.
* **Verification:** Tests demonstrate that synthetic spikes and new clients correctly generate alert records in the database.

### M6 — Professional TUI and CLI

* **Scope:** Build the Bubble Tea interface and CLI commands.
* **Deliverables:** `ui/tui` module, `hnw` command routing.
* **Verification:** `hnw demo` launches a responsive TUI displaying synthetic data and alerts.

### M7 — Security hardening and testing

* **Scope:** Comprehensive review of subprocess execution, file permissions, and error handling. Expand test coverage.
* **Deliverables:** Hardened codebase, complete test suite.
* **Verification:** `go vet` and race detector pass. All unit and integration tests pass consistently.

### M8 — Documentation, release, and GitHub publication

* **Scope:** Finalize README, generate verifiable demo screenshots, and prepare the release artifact.
* **Deliverables:** Production-ready `README.md`, GitHub Actions CI workflow, compiled Linux amd64 binary with SHA256SUMS.
* **Verification:** GitHub Actions successfully build and test the project. Documentation accurately reflects the final implementation.

## 24. Acceptance Criteria

* The application compiles to a single binary.
* `hnw demo` launches a fully functional TUI without requiring actual Pi-hole or WireGuard installations.
* The TUI displays Top Domains, Active Clients, and WireGuard peer status.
* The Anomaly Engine correctly identifies simulated DNS spikes and new clients in demo mode.
* No root privileges are required to run the core application or the demo.

## 25. GitHub Actions Design

* **Trigger:** Push to `main` and Pull Requests.
* **Jobs:**
* `test`: Runs `go test -v -race ./...` and `go vet`.
* `build`: Compiles the binary for `linux/amd64` and `linux/arm64`.



## 26. Release Engineering

* Releases will be tagged (e.g., `v1.0.0`).
* A GitHub Actions release workflow will automatically compile the binaries, generate SHA256 checksums, and attach them to a GitHub Release.

## 27. Documentation Requirements

* `README.md` must include:
* Clear project description and goals.
* High-quality screenshot of the TUI (captured in demo mode).
* Installation instructions (downloading the binary).
* Configuration guide (example `config.json`).
* Explicit privacy and security guarantees (local only, no DPI).
* Instructions for running `hnw demo`.



## 28. Known Limitations

* WireGuard monitoring relies on `wg show`, which may require specific `sudo` configurations for non-root users.
* Pi-hole API structure may change in future versions, potentially requiring updates to the collector parsing logic.

## 29. Future Enhancements (Post MVP)

* Support for AdGuard Home as an alternative DNS source.
* Support for Tailscale as an alternative VPN source.
* Exporting metrics to Prometheus/Grafana (currently explicitly out of scope for MVP to maintain simplicity).
* Telegram or Discord notifications for critical alerts.

## 30. Final Definition of Done

The project is complete when all milestones (M1-M8) are finished, the TUI is responsive and visually polished, the `hnw demo` command works flawlessly, and the repository is published to `github.com/khalid7344/home-network-watch` with a comprehensive `README.md` and passing CI pipeline.

---

## 10. Live Execution State (Maintained by Coding Agent)

Active Milestone: M1
Milestones:
[ ] M1: Repository foundation and demo data
[ ] M2: Pi-hole collector
[ ] M3: WireGuard collector
[ ] M4: SQLite snapshots and history
[ ] M5: Anomaly detection and alerts
[ ] M6: Professional TUI and CLI
[ ] M7: Security hardening and testing
[ ] M8: Documentation, release, and GitHub publication

Last Verified Git Checkpoint: None
Dead Ends / Do Not Repeat: None

```

```