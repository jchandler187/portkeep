# PortKeep — Feature Specification

Self-hosted, bare-metal-first port management + security tool. One binary, one config, zero cloud dependency.

---

## CLI Design Principles

- Single binary (Go or Rust), no runtime deps, no Docker required
- `portkeep <command>` — verb-noun pattern, discoverable
- `--json` flag on every command for scripting/piping
- `--quiet` for cron/automation use
- Color output by default, `--no-color` for pipes
- Tab completion for bash/zsh/fish
- Help text fits in one screen. Examples in every `--help`.

---

## Core Commands

### Discovery & Inventory

- [ ] `portkeep scan` — scan all listening ports on this host (ss/netstat wrapper)
  - [ ] `--node <name>` — scan a remote node via SSH (key-only, no password)
  - [ ] `--all` — scan all registered nodes
  - [ ] `--docker` — include Docker container port mappings
  - [ ] `--format table|json|markdown` — output format
  - [ ] `--watch` — continuous scan, alert on changes (like `watch` but smart)

- [ ] `portkeep ports list` — list all known ports from registry
  - [ ] `--node <name>` filter by node
  - [ ] `--state open|closed|declared|rogue` filter by state
  - [ ] `--bind loopback|lan|wan|wildcard` filter by bind address scope
  - [ ] `--service <name>` filter by service name
  - [ ] `--sort port|service|bind|risk` sort options

- [ ] `portkeep ports show <port>` — detail view for one port
  - [ ] Process name, PID, binary path, systemd unit
  - [ ] Bind address + scope (loopback/LAN/WAN/wildcard)
  - [ ] Declared service (if any) vs actual
  - [ ] Security score + risk flags
  - [ ] Firewall rule status
  - [ ] First seen / last seen timestamps
  - [ ] Change history (last 10 events)

### Registry & Port Claims

- [ ] `portkeep claim <port> --service <name> --note <desc>` — register a port
  - [ ] `--bind <addr>` — declare intended bind address
  - [ ] `--range system|reserved|dashboard|dev|ephemeral` — category
  - [ ] `--owner <name>` — who/what owns this port
  - [ ] Rejects if port already claimed (override with `--force`, logs conflict)

- [ ] `portkeep unclaim <port>` — remove a claim from registry

- [ ] `portkeep claim next [--range <range>]` — suggest next available port in range
  - [ ] Respects range conventions (1-1023 system, 1024-4999 reserved, 5000-9999 dashboards, 10000+ ephemeral)
  - [ ] Ranges configurable in config.yaml

- [ ] `portkeep claim import` — bulk import from JSON/CSV

- [ ] `portkeep claim export` — export registry as JSON/CSV/Markdown

### Drift Detection

- [ ] `portkeep drift` — compare declared registry vs actual listening ports
  - [ ] `--node <name>` per-node check
  - [ ] `--all` all nodes
  - [ ] Reports:
    - Rogue ports: listening but not declared
    - Ghost ports: declared but not listening
    - Bind mismatch: declared loopback, actually 0.0.0.0
    - Service mismatch: declared as X, process is Y
  - [ ] Exit code: 0 = clean, 1 = drift found (useful for CI/cron)

- [ ] `portkeep drift watch` — continuous drift monitoring
  - [ ] `--interval <seconds>` (default 60)
  - [ ] `--alert` — push alert on any drift event

### Security & Scoring

- [ ] `portkeep audit` — full security audit
  - [ ] Per-port risk flags:
    - 🟢 Loopback only (127.0.0.1, ::1) — safe
    - 🟡 LAN-only (192.168.x.x, 10.x.x.x, 172.16-31.x.x) — moderate
    - 🔴 WAN/Tailscale reachable — needs review
    - ⛔ Wildcard (0.0.0.0, ::, *) — dangerous without firewall
  - [ ] Overall exposure score: 0-100 (lower = safer)
    - Weighted by bind scope + port sensitivity (SSH/DB higher weight than random dev port)
  - [ ] Summary: "6 loopback, 3 LAN, 2 WAN, 1 wildcard"
  - [ ] `--json` for machine consumption
  - [ ] `--fix` — suggest concrete remediations for each flag

- [ ] `portkeep firewall check` — cross-reference ports against firewall rules
  - [ ] Supports: UFW, iptables, nftables, firewalld
  - [ ] Reports:
    - Open port with no allow rule (blocked by default? or firewall gap?)
    - Allow rule for port that isn't listening (stale rule)
    - Allow rule too permissive (allows from 0.0.0.0 for a loopback-only service)
  - [ ] `--diff` — firewall rules changed since last check

- [ ] `portkeep cve <port>` — check known CVEs for the service on that port
  - [ ] Service fingerprinting via nmap -sV or banner grab
  - [ ] Local NVD cache (downloaded weekly, ~200MB)
  - [ ] `--refresh` — update NVD cache
  - [ ] `--all` — CVE check every listening service

- [ ] `portkeep shodan` — check if any of your ports appear on Shodan
  - [ ] Requires `SHODAN_API_KEY` (free tier = 100 searches/mo)
  - [ ] Checks each WAN-facing IP/port combo
  - [ ] `--cache` — cache results for 24h (don't burn API quota)

### Service Fingerprinting

- [ ] `portkeep fingerprint <port>` — identify what's actually running
  - [ ] Banner grab (TCP connect, read first bytes)
  - [ ] nmap -sV integration (if nmap available, else graceful fallback)
  - [ ] TLS cert extraction (issuer, expiry, SANs)
  - [ ] HTTP header probe for web services
  - [ ] Stores fingerprint in registry for drift comparison

### Network Segment Awareness

- [ ] `portkeep network map` — show which ports are reachable from which segments
  - [ ] Segments auto-detected: loopback, LAN, Tailscale, Docker bridge, custom VLANs
  - [ ] Configurable in config.yaml (define subnets + names)
  - [ ] "Pi-hole DNS :53 is reachable from IoT subnet — flag?"
  - [ ] `--add-segment <name> <cidr>` — define a custom segment
  - [ ] `--remove-segment <name>` — remove a segment

### History & Timeline

- [ ] `portkeep history` — git-log style change timeline
  - [ ] `--port <n>` — filter by port
  - [ ] `--node <name>` — filter by node
  - [ ] `--since <time>` — "since yesterday", "since 2026-06-01"
  - [ ] `--type appear|disappear|bind-change|process-change|claim|unclaim` — event types
  - [ ] Output: "Jun 3 14:22 port 3200 appeared (python3, PID 1518) — NOT DECLARED"

- [ ] `portkeep history diff` — compare two snapshots
  - [ ] `--from <time> --to <time>` — time range
  - [ ] Shows added/removed/changed ports between snapshots

- [ ] `portkeep snapshot` — save current state as a named checkpoint
  - [ ] `--name <label>` — "pre-deploy", "after-restart", etc.
  - [ ] `portkeep snapshot list` — show all saved snapshots
  - [ ] `portkeep snapshot restore <name>` — compare current vs that snapshot

### Alerting

- [ ] `portkeep alert config` — set up alert destinations
  - [ ] Webhook (generic HTTP POST)
  - [ ] Telegram (chat ID + bot token)
  - [ ] Email (SMTP)
  - [ ] Local script execution
  - [ ] `--test` — send test alert

- [ ] `portkeep alert rules list` — show active alert rules
  - [ ] `portkeep alert rules add` — create a rule
    - [ ] `--on appear|disappear|drift|bind-change|rogue|score-change`
    - [ ] `--port <n>` or `--any-port` (any port matching condition)
    - [ ] `--threshold <n>` — for score-change: alert if exposure score exceeds N
    - [ ] `--destination <name>` — which alert destination to use
  - [ ] `portkeep alert rules remove <id>` — delete a rule

- [ ] Built-in smart alerts (enabled by default, configurable):
  - [ ] New port appeared that isn't declared → alert
  - [ ] Port bind changed from loopback to wider scope → alert
  - [ ] Exposure score increased → alert
  - [ ] Service on well-known port changed process → alert

### Compliance Templates

- [ ] `portkeep compliance list` — available policy templates
  - [ ] CIS Benchmark Level 1 (Linux)
  - [ ] CISA SMB Baseline
  - [ ] Custom (user-defined YAML policies)

- [ ] `portkeep compliance check <template>` — audit against a policy
  - [ ] Returns pass/fail per check with remediation
  - [ ] `--json` for CI integration

- [ ] `portkeep compliance template create <name>` — create custom policy
  - [ ] YAML format: rules like "no wildcard bind on ports < 1024", "SSH must be key-only", etc.

### Multi-Node Management

- [ ] `portkeep node add <name> --host <addr> --ssh-key <path>` — register a node
  - [ ] SSH key-only auth, no passwords
  - [ ] Stores node config in config.yaml
  - [ ] `--labels <k=v,...>` — tag nodes (prod, dev, etc.)

- [ ] `portkeep node remove <name>` — unregister a node

- [ ] `portkeep node list` — show all registered nodes + status
  - [ ] Shows: name, host, last scan time, port count, exposure score
  - [ ] `--health` — ping + SSH connectivity check

- [ ] `portkeep node scan <name>` — scan a specific node
  - [ ] `portkeep node scan --all` — scan every registered node

### Export & Integration

- [ ] `portkeep export prometheus` — expose metrics on :9091/metrics
  - [ ] `port_warden_ports_total`, `port_warden_exposure_score`, `port_warden_drift_events`
  - [ ] Runs as a lightweight HTTP server, integrates with existing Prometheus

- [ ] `portkeep export grafana` — generate Grafana dashboard JSON
  - [ ] Single command, pipe to Grafana provisioning

- [ ] `portkeep export markdown` — generate a runbook
  - [ ] Same format as homelab-runbook skill output
  - [ ] `--output <file>` — write to file

- [ ] `portkeep export json` — full state export
  - [ ] Registry + current scan + history
  - [ ] Useful for backup or migration

### Daemon Mode

- [ ] `portkeep daemon start` — run as background service
  - [ ] `--interval <seconds>` — scan interval (default 300)
  - [ ] `--pid-file <path>` — PID file location
  - [ ] Generates systemd unit file: `portkeep daemon install`
  - [ ] `portkeep daemon stop` / `portkeep daemon status`
  - [ ] All alert rules active in daemon mode
  - [ ] History continuously recorded

### Config

- [ ] `portkeep config init` — create config.yaml with sensible defaults
  - [ ] Interactive wizard or `--defaults` for non-interactive
  - [ ] Config location: `~/.portkeep/config.yaml` (or `$PORT_WARDEN_HOME`)

- [ ] `portkeep config show` — display current config
  - [ ] `--key <dot.path>` — show specific value

- [ ] `portkeep config set <key> <value>` — update config value

- [ ] Config structure:
  ```yaml
  nodes:
    node1:
      host: 127.0.0.1
      labels: [prod]
    myserver:
      host: 10.0.0.50
      ssh_key: ~/.ssh/id_ed25519
      labels: [dev]

  ranges:
    system: [1, 1023]
    reserved: [1024, 4999]
    dashboard: [5000, 9999]
    ephemeral: [10000, 65535]

  segments:
    loopback: [127.0.0.0/8, ::1/128]
    lan: [192.168.1.0/24, 10.0.0.0/8]
    tailscale: [100.64.0.0/10]

  alerts:
    destinations:
      telegram:
        chat_id: "6148810724"
        bot_token: ${TELEGRAM_BOT_TOKEN}
    rules:
      - on: rogue
        destination: telegram
      - on: score-change
        threshold: 15
        destination: telegram

  scan:
    interval: 300
    include_docker: true
    nmap_path: /usr/bin/nmap

  nvd:
    cache_dir: ~/.portkeep/nvd-cache
    refresh_days: 7

  shodan:
    api_key: ${SHODAN_API_KEY}
    cache_hours: 24

  compliance:
    templates_dir: ~/.portkeep/compliance
  ```

---

## Data Storage

- [ ] SQLite (WAL mode) at `~/.portkeep/portkeep.db`
  - Tables: ports, claims, history, alerts, snapshots, nodes, compliance_results
  - Auto-migrated on version upgrade
  - Backup: `portkeep db backup --output <file>`
  - Restore: `portkeep db restore <file>`

---

## Tech Stack (recommendation)

- **Language:** Go (single binary, cross-compile, no runtime)
- **DB:** SQLite via modernc.org/sqlite (pure Go, no CGO needed)
- **SSH:** golang.org/x/crypto/ssh
- **Config:** Viper (YAML + env var substitution)
- **CLI:** Cobra + Bubble Tea for interactive bits
- **Prometheus:** Built-in /metrics endpoint
- **nmap:** Shell out when available, graceful fallback

---

## MVP Scope (v0.1)

Ship these first, everything else is v0.2+:

1. `scan` — discover ports (local + SSH remote)
2. `ports list` / `ports show` — view the registry
3. `claim` / `unclaim` / `claim next` — port registration
4. `drift` — declared vs actual comparison
5. `audit` — security scoring + risk flags
6. `firewall check` — UFW/iptables cross-reference
7. `history` — change timeline
8. `alert config` + `alert rules` — Telegram alerting
9. `node add/list/scan` — multi-node
10. `daemon start/install` — systemd service
11. `config init` — first-run setup

---

## v0.2+

- CVE correlation (NVD cache)
- Shodan check
- Service fingerprinting (nmap -sV)
- Network segment awareness
- Compliance templates
- Prometheus export
- Grafana dashboard generation
- Docker container discovery
- Custom compliance policies
- Snapshot/restore