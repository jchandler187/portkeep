# PortKeep

Port management + security for self-hosted infrastructure.

Know every port. Claim every port. Score your attack surface.

```
$ portkeep scan
localhost — 12 ports (6 loopback · 1 lan · 2 tailscale · 3 wildcard)

PORT     PROTO    ADDRESS              SCOPE         PID    PROCESS
22       tcp      0.0.0.0              ⛔wildcard     1517   sshd
53       tcp      0.0.0.0              ⛔wildcard     1489   pihole-FTL
443      tcp      100.91.13.85         🔴tailscale    1503   nginx
3000     tcp      ::                   ⛔wildcard     1498   node
18789    tcp      127.0.0.1            🟢loopback     1497   openclaw
9090     tcp      127.0.0.1            🟢loopback     1490   prometheus
...

⚠ 3 unclaimed ports
⚠ 3 wildcard binds
```

> **Note:** Process names and PIDs are resolved on Linux by walking `/proc` inode tables.
> Run PortKeep as root for full visibility; non-root users see blank process names for
> processes they don't own.

```
$ portkeep audit
╔══════════════════════════════════════════════════╗
║  PortKeep — Security Audit  ·  localhost         ║
║  Exposure Score:  38/100  ████████░░░░░░░░░░░░ MODERATE ║
╚══════════════════════════════════════════════════╝

THREAT INTEL  synced 2h ago
  ✓ no C2 port or KEV CVE matches

CRITICAL FINDINGS
  ⛔ port 22/tcp (sshd) — wildcard bind, SSH exposed
  ⛔ port 53/tcp (pihole-FTL) — wildcard bind, privileged port exposed
  🔴 port 3000/tcp (node) — wildcard bind, unclaimed
  ...
```

## What it does

- **Discovers** every listening port across multiple nodes (local + SSH remote)
- **Claims** ports into a registry — no more "I think 3002 was free"
- **Detects drift** — declared vs actual, rogue ports, bind scope mismatches
- **Audits security** — exposure score (0–100), risk flags, firewall cross-reference
- **Syncs threat intel** from 9 sources and surfaces C2 port matches + CISA-KEV CVE hits
- **Alerts** — Telegram, webhook, or script when something changes
- **Tracks history** — git-log style timeline of every port change
- **Daemon mode** — systemd user service for continuous monitoring

## Quick start

```bash
portkeep scan               # discover every port on this host
portkeep audit              # security score + risk flags
portkeep sync               # pull threat intel from 9 sources
portkeep claim 3000 "api"  # register a port as expected
portkeep drift              # declared vs actual — exits 1 on drift
portkeep claim next         # find the next available port in a range
```

## Threat intelligence

PortKeep syncs 9 sources on demand via `portkeep sync`.

**No authentication required (syncs out of the box):**

| Source | What it provides |
|--------|-----------------|
| CISA-KEV | Known Exploited Vulnerabilities catalog (CVE + product names) |
| EPSS | Top-1000 CVEs by exploit probability (FIRST.org) |
| Feodo | Active C2 botnet IPs and destination ports (abuse.ch) |
| Emerging Threats | Compromised host IP list (Proofpoint/ET) |
| Blocklist.de | Attacking IP list |
| DShield/SANS | Top attacking /24 netblocks (SANS Internet Storm Center) |

**Free Auth-Key required** — obtain at [https://auth.abuse.ch](https://auth.abuse.ch):

| Source | What it provides |
|--------|-----------------|
| ThreatFox | IOC database with C2 IPs and ports (abuse.ch) |
| URLhaus | Malicious URL host IPs (abuse.ch) |
| MalwareBazaar | Malware hash metadata cached for process correlation (planned v0.2) |

```bash
# Set key once; the other 6 sources always sync without it
export ABUSE_CH_AUTH_KEY=your-key-here
portkeep sync
```

**What the audit uses from threat intel:**
- C2 port matches: if your machine exposes a port that Feodo/ThreatFox track as an active C2 port, it gets flagged as CRITICAL (+30 score)
- CISA-KEV hits: if a port's process name matches a product in the KEV catalog (e.g., `nginx`, `openssh`), the count of active CVEs is surfaced as a finding

## Commands

| Command | Description |
|---------|-------------|
| `scan` | Discover all listening ports (local or SSH remote) |
| `sync` | Pull threat intel from all 9 sources |
| `audit` | Full security audit — score, risk flags, threat intel, firewall |
| `claim` | Register a port as expected/owned |
| `claim next` | Find the next available port in a range |
| `unclaim` | Remove a port registration |
| `drift` | Compare declared vs actual — exits 1 on drift |
| `list` | List all registered port claims |
| `history` | Change timeline — git-log style |
| `node` | Manage remote nodes for multi-host scanning |
| `alert` | Configure alert rules and notification destinations |
| `daemon` | Run as a background service (systemd support) |
| `config` | Configuration management |
| `version` | Print version info |

All commands support `--json` for scripting and `--quiet` for cron.

## Install

**From binary (Linux/macOS):**
```bash
# Download from https://github.com/jchandler187/portkeep/releases/latest
curl -sSL https://github.com/jchandler187/portkeep/releases/download/v0.1.0/portkeep_0.1.0_linux_amd64.tar.gz | tar xz
sudo mv portkeep /usr/local/bin/
```

**From source (requires Go 1.22+):**
```bash
git clone https://github.com/jchandler187/portkeep.git
cd portkeep && go build -o portkeep .
sudo mv portkeep /usr/local/bin/
```

**Homebrew tap (macOS / Linux):**
```bash
brew tap jchandler187/tap
brew install portkeep
```

## Multi-node setup

```bash
# Add a remote node (key-only SSH auth)
portkeep node add myserver --host 10.0.0.50 --ssh-key ~/.ssh/id_ed25519

# Scan a remote node
portkeep scan --node myserver
```

## Daemon mode

```bash
# Install as systemd user service
portkeep daemon install
systemctl --user enable --now portkeep

# Check status
portkeep daemon status
```

## Alerting

```bash
# Telegram alert for rogue ports
portkeep alert add --trigger rogue --destination telegram \
  --config '{"chat_id":"YOUR_CHAT_ID","bot_token":"YOUR_TOKEN"}'

# Webhook alert for bind changes
portkeep alert add --trigger bind-change --destination webhook \
  --config '{"url":"https://hooks.example.com/portkeep"}'
```

## Architecture

- **Single Go binary** — no runtime dependencies, no Docker, no cloud
- **SQLite storage** (pure Go, no CGO via `modernc.org/sqlite`) — WAL mode
- **SSH remote scanning** — key-only auth, no agent required on remote nodes
- **Firewall cross-reference** — auto-detects UFW, iptables, nftables, firewalld
- **Exposure scoring** — 0–100 based on bind scope, claims, and threat intel

## How PortKeep differs from ClawSecure / SecureClaw

ClawSecure scans OpenClaw skill code in the ClawHub registry for malicious patterns. SecureClaw audits OpenClaw configuration and hardens the OpenClaw gateway (port exposure, permissions, sandbox settings). Neither tool inventories the full host network layer across all non-OpenClaw services.

On a typical homelab node, dozens of processes expose ports: databases, dashboards, metrics collectors, game servers, n8n, Home Assistant. None of those go through the OpenClaw agent, so ClawSecure/SecureClaw have no visibility into them. PortKeep sees every listening socket on the machine, claims them into a registry, detects when one appears unexpectedly, and cross-references every port against live threat intel.

**PortKeep and ClawSecure/SecureClaw solve different problems.** You'd run both: ClawSecure to harden the agent, PortKeep to harden the host.

## Why not cloud ASM?

Cloud-hosted attack surface management platforms typically cost $100+/month per host and require an internet-connected agent phoning home. PortKeep is free, runs locally, and stores all data in a SQLite file on your own machine. It is not a replacement for a full external ASM scan — it is a local registry and continuous monitor for hosts you own and can SSH into.

## Project status

**v0.1.0** — Core features implemented: scan, claim, drift, audit, sync (6-of-9 sources without Auth-Key), alert, daemon, history, multi-node SSH. Tested on Linux amd64.

## OpenClaw Plugin

PortKeep is also available as an [OpenClaw tool plugin](https://clawhub.ai/jchandler187/portkeep). Install it and any OpenClaw agent can scan, audit, drift-check, and claim ports — including remote nodes — without knowing the CLI.

```bash
openclaw plugins install portkeep
```

Six tools: `portkeep_scan`, `portkeep_audit`, `portkeep_drift`, `portkeep_claim`, `portkeep_list`, `portkeep_sync`.

## Install

Download the latest binary from [GitHub Releases](https://github.com/jchandler187/portkeep/releases) for your platform:

```bash
# Linux amd64
curl -sL https://github.com/jchandler187/portkeep/releases/latest/download/portkeep_linux_amd64.tar.gz | tar xz
sudo mv portkeep /usr/local/bin/

# macOS (Apple Silicon)
curl -sL https://github.com/jchandler187/portkeep/releases/latest/download/portkeep_darwin_arm64.tar.gz | tar xz
sudo mv portkeep /usr/local/bin/

# Verify
portkeep version
```

## Roadmap

- Process-hash correlation against MalwareBazaar (v0.2)
- CVE lookup command (`portkeep cve`) cross-referencing running services with KEV/EPSS
- Service fingerprinting (nmap -sV integration)
- Compliance templates (CIS, CISA SMB baseline)
- Prometheus/Grafana export
- Interactive terminal UI (Bubble Tea, v0.2)

## Documentation

- [SPEC.md](SPEC.md) — Full feature specification
- [CLI.md](CLI.md) — CLI design and usage examples
- [BUILD.md](BUILD.md) — Architecture and build phases

## License

MIT

## Author

Jason Chandler · [Low Watt Labs](https://github.com/jchandler187)

---

☕ Found PortKeep useful? [Buy me a coffee](https://buymeacoffee.com/jchandler187)
