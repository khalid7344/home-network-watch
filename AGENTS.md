# AGENTS.md — Repository Engineering Guidelines

These rules apply to autonomous agents and contributors working in this repository.

## 1. Safety and Security Rules
- **No Secrets:** Never commit passwords, tokens, private keys, `.env` files, or production credentials. Use environment variables (e.g. `HNW_PIHOLE_TOKEN`) or local configuration files excluded from Git.
- **Least Privilege:** HNW operates as an unprivileged user process. Never require root execution. WireGuard inspections should use unprivileged commands or strictly scoped passwordless `sudo wg show`.
- **Read-Only Ingestion:** HNW is purely an observability tool. Never execute configuration-modifying commands against Pi-hole or WireGuard.
- **Local Isolation:** All telemetry, metrics, and alerts must remain strictly on the local machine within SQLite. Never introduce external cloud synchronization or analytics.

## 2. Code Quality & Architecture
- **Idiomatic Go:** Follow standard Go idioms, format with `gofmt -s`, and pass `go vet ./...` without warnings.
- **Race Safety:** All concurrent pipelines, database access, and collectors must pass `go test -v -race ./...`.
- **Modular Boundaries:** Keep collectors (`internal/collector/`), storage (`internal/storage/`), anomaly rules (`internal/engine/anomaly/`), and UI (`internal/ui/tui/`) decoupled via clean Go interfaces.
- **Zero Heavy C-Dependencies:** Maintain portability by using pure-Go SQLite (`modernc.org/sqlite`) so binaries can compile statically without CGO.

## 3. Testing & Verification
- Unit test all parsing logic, calculation formulas, and edge cases.
- Use synthetic fixtures (`demo/`) and HTTP mock servers (`httptest`) for reproducible offline tests.
- Never require live network access, physical hardware, or real Pi-hole/WireGuard infrastructure for tests to pass.
- Verify user-facing commands (`hnw demo`, `hnw snapshot`, `hnw status`) before committing.
