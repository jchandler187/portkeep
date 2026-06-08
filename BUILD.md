# PortKeep — Build Plan

## Architecture

Single Go binary. SQLite (WAL mode) for local storage. No CGO (pure Go SQLite via `modernc.org/sqlite`). Builds for linux/amd64, linux/arm64, darwin/amd64, darwin/arm64.

## Actual Repository Structure (v0.1.0)

```
portkeep/
├── README.md
├── SPEC.md                      # Full feature specification
├── CLI.md                       # CLI design and usage examples
├── BUILD.md                     # This file — build architecture
├── LICENSE
├── go.mod
├── go.sum
├── main.go                      # Entrypoint: calls cmd.Execute()
├── cmd/
│   ├── root.go                  # Cobra root, persistent flags, DB open/close
│   ├── scan.go                  # portkeep scan
│   ├── scan_helpers.go          # parseSSOutput for remote SSH scan results
│   ├── claim.go                 # portkeep claim
│   ├── unclaim.go               # portkeep unclaim
│   ├── list.go                  # portkeep list
│   ├── diff.go                  # portkeep drift
│   ├── audit.go                 # portkeep audit (uses threat intel cache)
│   ├── sync.go                  # portkeep sync (9-source threat intel)
│   ├── history.go               # portkeep history
│   ├── node.go                  # portkeep node add/list/health
│   ├── alert.go                 # portkeep alert add/list/test
│   ├── daemon.go                # portkeep daemon start/stop/install/status
│   ├── config.go                # portkeep config init/show
│   └── db.go                    # SQLite open + schema migration
├── internal/
│   ├── portscanner/
│   │   └── scanner.go           # Local port discovery via /proc/net/tcp[6]
│   │                            # + /proc inode → PID/process resolution
│   ├── sshclient/
│   │   └── sshclient.go         # SSH key-only client for remote node scanning
│   ├── threatintel/
│   │   └── client.go            # 9-source threat intel sync + query API
│   ├── firewall/
│   │   └── firewall.go          # UFW/iptables/nftables/firewalld detection
│   ├── alert/
│   │   └── alert.go             # Telegram/webhook/email alert dispatcher
│   ├── scoring/
│   │   └── scorer.go            # Programmatic exposure scoring (used by audit)
│   └── config/
│       └── config.go            # Path helpers + env var config (AbuseChAuthKey)
└── configs/
    └── config.example.yaml      # Example configuration
```

## Dependencies

| Package | Purpose |
|---------|---------|
| `github.com/spf13/cobra` v1.8.0 | CLI framework |
| `modernc.org/sqlite` v1.33.1 | Pure Go SQLite (no CGO) |
| `golang.org/x/crypto` v0.24.0 | SSH remote scanning |

All threat intel HTTP fetching uses standard library (`net/http`, `encoding/json`, `bufio`). No additional dependencies required.

## Database Schema

```sql
CREATE TABLE nodes (
    name TEXT PRIMARY KEY,
    host TEXT NOT NULL,
    ssh_key TEXT DEFAULT '',
    labels TEXT DEFAULT '[]',
    last_scan_at DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE ports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    node_name TEXT NOT NULL DEFAULT 'localhost' REFERENCES nodes(name),
    port INTEGER NOT NULL,
    protocol TEXT NOT NULL DEFAULT 'tcp',
    bind_addr TEXT NOT NULL,
    scope TEXT NOT NULL DEFAULT 'unknown',  -- loopback/lan/tailscale/wan/wildcard
    pid INTEGER DEFAULT 0,
    process_name TEXT DEFAULT '',
    binary_path TEXT DEFAULT '',
    systemd_unit TEXT DEFAULT '',
    docker_container TEXT DEFAULT '',
    first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(node_name, port, protocol, bind_addr)
);

CREATE TABLE claims (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    node_name TEXT NOT NULL DEFAULT 'localhost' REFERENCES nodes(name),
    port INTEGER NOT NULL,
    protocol TEXT NOT NULL DEFAULT 'tcp',
    service_name TEXT NOT NULL,
    declared_bind TEXT DEFAULT '',
    port_range TEXT DEFAULT '',
    owner TEXT DEFAULT '',
    note TEXT DEFAULT '',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(node_name, port, protocol)
);

CREATE TABLE history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    node_name TEXT NOT NULL DEFAULT 'localhost',
    event_type TEXT NOT NULL,  -- appear/disappear/bind_change/claim/unclaim
    port INTEGER NOT NULL,
    protocol TEXT NOT NULL DEFAULT 'tcp',
    detail TEXT DEFAULT '{}',
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    trigger_type TEXT NOT NULL,  -- rogue/bind-change/score-change
    destination TEXT NOT NULL,   -- telegram/webhook/email/script
    destination_config TEXT DEFAULT '{}',
    threshold INTEGER DEFAULT 0,
    enabled INTEGER DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE snapshots (
    name TEXT PRIMARY KEY,
    node_name TEXT NOT NULL DEFAULT 'localhost',
    data TEXT NOT NULL DEFAULT '{}',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

## Threat Intel Cache

Stored in `~/.portkeep/cache/db.json` (JSON, 0600 permissions).

```json
{
  "last_sync": "2026-06-05T10:00:00Z",
  "c2_ports": [
    {"port": 4444, "ip": "1.2.3.4", "source": "feodo", "malware": "Emotet"}
  ],
  "blocked_ips": [
    {"ip": "5.6.7.8", "source": "emerging-threats"},
    {"ip": "10.20.30.0/24", "source": "dshield-sans"}
  ],
  "kev_entries": [
    {"cve_id": "CVE-2023-46604", "product": "OpenWire", "vendor": "Apache", "added": "2023-11-02"}
  ],
  "epss_top": {
    "CVE-2023-46604": 0.975
  },
  "sources": [
    {"source": "cisa-kev", "status": "ok", "count": 1192, "synced_at": "..."}
  ]
}
```

## Build Steps

```bash
# Development build
go build -o portkeep .

# Release build (ldflags inject version)
go build -ldflags "-X github.com/lowwattlabs/portkeep/cmd.version=v0.1.0 \
                   -X github.com/lowwattlabs/portkeep/cmd.commit=$(git rev-parse --short HEAD) \
                   -X github.com/lowwattlabs/portkeep/cmd.buildDate=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  -o portkeep .

# Cross-compile
GOOS=linux  GOARCH=amd64 go build -o portkeep_linux_amd64 .
GOOS=linux  GOARCH=arm64 go build -o portkeep_linux_arm64 .
GOOS=darwin GOARCH=amd64 go build -o portkeep_darwin_amd64 .
GOOS=darwin GOARCH=arm64 go build -o portkeep_darwin_arm64 .
```

## Build Phases

### Phase 1 — MVP (v0.1.0) — DONE

| Feature | Commands | Status |
|---------|----------|--------|
| Config init | `config init/show` | ✓ |
| Port scanning (local /proc) | `scan` | ✓ |
| Port scanning (SSH remote) | `scan --node` | ✓ |
| Port registry | `claim/unclaim/list` | ✓ |
| Drift detection | `drift` | ✓ |
| Security audit | `audit` | ✓ |
| Firewall cross-reference | (inside audit) | ✓ |
| Threat intel sync (9 sources) | `sync` | ✓ |
| Change history | `history` | ✓ |
| Alerting (Telegram/webhook) | `alert` | ✓ |
| Multi-node management | `node` | ✓ |
| Daemon mode | `daemon start/install/status` | ✓ |
| PID/process resolution | (inside scan) | ✓ |

### Phase 2 — Hardening (v0.2.0)

| Feature | Commands |
|---------|----------|
| CVE lookup | `cve` |
| Process-hash correlation (MalwareBazaar) | (inside audit) |
| Service fingerprinting (nmap -sV) | `fingerprint` |
| Compliance templates (CIS, CISA) | `compliance` |
| Prometheus/Grafana export | `export` |
| Snapshot save/compare | `snapshot` |
| Interactive terminal UI (Bubble Tea) | (no-arg invocation) |

### Phase 3 — Polish (v1.0.0)

| Feature |
|---------|
| Docker container port discovery |
| Shell completions (bash/zsh/fish) |
| Custom compliance policies |
| Full test suite + CI (GitHub Actions + GoReleaser) |

## Performance Targets

- `scan` local: <2 seconds (including /proc inode walk for PID resolution)
- `sync` all 9 sources concurrently: <30 seconds on a typical home broadband connection
- `audit`: <3 seconds (scan + threat intel lookup from in-memory cache)
- Daemon memory footprint: <50MB
- DB size: <10MB for 10 nodes, 500 ports, 1 year of history
- Threat intel cache: typically 2–5MB JSON
