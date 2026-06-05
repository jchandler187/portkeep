# PortKeep

Port management + security for self-hosted infrastructure.

Know every port. Claim every port. Secure every port.

```
$ portkeep scan
localhost — 29 ports (11 loopback · 1 lan · 3 tailscale · 1 wan · 13 wildcard)

PORT     PROTO    ADDRESS              SCOPE      PID    PROCESS
22       tcp      0.0.0.0              ⛔wildcard  0      
53       tcp      0.0.0.0              ⛔wildcard  0      
443      tcp      100.91.13.85         🔴tailscale 0      
3000     tcp      ::                   ⛔wildcard  0      
18789    tcp      127.0.0.1            🟢loopback  0      
...
```

```
$ portkeep audit
╔══════════════════════════════════════════════════╗
║  PortKeep — Security Audit  ·  localhost        ║
║  Exposure Score: 38/100  ███████░░░░░░░░░░░░░ MODERATE  ║
╚══════════════════════════════════════════════════╝

CRITICAL FINDINGS
  ⛔ port 22 () — wildcard bind, SSH exposed
  ⛔ port 53 () — wildcard bind, privileged port exposed
  🔴 port 443 () — Tailscale reachable, unclaimed
  ...
```

## What it does

- **Discovers** every listening port across multiple nodes (local + SSH)
- **Claims** ports into a registry — no more "I think 3002 was free"
- **Detects drift** — declared vs actual, rogue ports, bind mismatches
- **Audits security** — exposure score (0-100), risk flags, firewall cross-reference
- **Alerts** — Telegram, webhook, or script when something changes
- **Tracks history** — git-log style timeline of every port change
- **Daemon mode** — systemd service for continuous monitoring

## Quick start

```bash
portkeep scan               # see every port on this host
portkeep audit              # security score + risk flags
portkeep claim 3000 "api"  # register a port as expected
portkeep drift              # declared vs actual — exits 1 on drift
portkeep claim next          # suggests next available port
```

## Commands

| Command | Description |
|---------|-------------|
| `scan` | Discover all listening ports (local or remote via SSH) |
| `claim` | Register a port as expected/owned |
| `claim next` | Find the next available port in a range |
| `unclaim` | Remove a port registration |
| `drift` | Compare declared vs actual — exits 1 on drift |
| `audit` | Full security audit — score, risk flags, firewall check |
| `list` | List all registered port claims |
| `history` | Change timeline — git-log style port history |
| `node` | Manage remote nodes for multi-host scanning |
| `alert` | Configure alert rules and notification destinations |
| `daemon` | Run as a background service (systemd support) |
| `config` | Configuration management |

All commands support `--json` for scripts and `--quiet` for cron.

## Install

```bash
# From source (requires Go 1.22+)
git clone https://github.com/jchandler187/portkeep.git
cd portkeep && go build -o portkeep .
sudo mv portkeep /usr/local/bin/

# Cross-compile
GOOS=linux GOARCH=arm64 go build -o portkeep-linux-arm64 .
```

Pre-built binaries available on the [releases page](https://github.com/jchandler187/portkeep/releases).

## Multi-node setup

```bash
# Add a remote node (SSH key auth only)
portkeep node add node2 --host 192.168.1.86 --ssh-key ~/.ssh/id_ed25519

# Scan a remote node
portkeep scan --node node2

# Or add localhost explicitly
portkeep node add localhost --host 127.0.0.1
```

## Daemon mode

```bash
# Run in foreground (default: 5-minute interval)
portkeep daemon start --interval 300

# Install as systemd user service
portkeep daemon install
systemctl --user enable --now portkeep

# Check status
portkeep daemon status
```

## Alerting

```bash
# Add a Telegram alert for rogue ports
portkeep alert add --trigger rogue --destination telegram --config '{"chat_id":"123456","bot_token":"YOUR_TOKEN"}'

# Add a webhook alert for bind changes
portkeep alert add --trigger bind-change --destination webhook --config '{"url":"https://hooks.example.com/portkeep"}'

# Test an alert rule
portkeep alert test --trigger rogue
```

## Architecture

- **Single Go binary** — no runtime dependencies, no Docker, no cloud
- **SQLite storage** (pure Go, no CGO via modernc.org/sqlite) — WAL mode for concurrency
- **SSH remote scanning** — key-only auth, no agent needed on remote nodes
- **Firewall cross-reference** — auto-detects UFW, iptables, nftables, firewalld
- **Exposure scoring** — 0/100 based on bind scope, claims, and known risks

## Project status

**v0.1.0-beta.** Core features working: scan, claim, drift, audit, alert, daemon, history, multi-node SSH. Tested on Linux amd64.

Roadmap:
- CVE correlation (NVD cache)
- Shodan internet exposure check
- Service fingerprinting (nmap -sV)
- Compliance templates (CIS, CISA)
- Prometheus/Grafana export
- Interactive mode (Bubble Tea)

## Documentation

- [SPEC.md](SPEC.md) — Full feature specification
- [CLI.md](CLI.md) — CLI design document
- [BUILD.md](BUILD.md) — Build phases and architecture

## License

MIT

## Author

Jason Chandler · [Low Watt Labs](https://github.com/jchandler187)

---

☕ Found PortKeep useful? [Buy me a coffee](https://buymeacoffee.com/jchandler187)