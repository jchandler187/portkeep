# PortKeep — CLI Design

The interface is the product. Every command should feel obvious after using it once.

---

## Design Rules

1. **Defaults are smart.** Zero flags for 90% of use. `portkeep scan` just works.
2. **Output is skimmable.** Tables for lists, color for severity, one line per port.
3. **Errors are actionable.** Not "connection refused" — "Node-2 (192.168.1.86) unreachable on SSH. Key at ~/.ssh/id_ed25519. Diagnose: `ssh node2`"
4. **Pipes work.** `--json` on everything. `--quiet` kills all output except errors. Exit codes: 0=good, 1=issues, 2=error.
5. **Learn in 30 seconds.** `portkeep help` fits one screen.

---

## First Run

```
$ portkeep config init

PortKeep — initial setup

  Node name [node1]: █
  Scan this host? [Y/n]: 
  Add remote nodes? [y/N]: n
  Alert destination: [telegram/webhook/email/none] telegram
  Telegram chat ID: YOUR_CHAT_ID
  Bot token (env var or literal) [$TELEGRAM_BOT_TOKEN]: 

  ✓ Config written to ~/.portkeep/config.yaml
  ✓ First scan complete — 18 ports found on node1
  ✓ 2 ports on 0.0.0.0 flagged for review

  Next steps:
    portkeep sync            — pull threat intel (6 sources, no key needed)
    portkeep audit           — full security review
    portkeep drift           — check declared vs actual
    portkeep claim next      — find an open port
```

---

## Daily Use — The Big Five

### 1. scan

> **Note on process names:** PortKeep resolves process names and PIDs on Linux by
> matching socket inodes in `/proc/PID/fd`. This requires read access to `/proc/PID/fd`
> for each process. Run as root for full visibility; non-root shows blanks for
> processes owned by other users.

```
$ portkeep scan

node1 — 18 ports (6 loopback · 1 LAN · 7 WAN · 2 wildcard · 2 tailscale)

PORT   PROTO   ADDRESS       SCOPE      PID    PROCESS
22     tcp     0.0.0.0       ⛔wildcard  1517   sshd
53     tcp     0.0.0.0       ⛔wildcard  1489   pihole-FTL
443    tcp     100.91.13.85  🔴tailscale 1503   nginx
3000   tcp     ::            ⛔wildcard  1498   node
3200   tcp     0.0.0.0       🔴wan       0      
9090   tcp     127.0.0.1     🟢loopback  1490   prometheus
9100   tcp     *             ⛔wildcard  1499   node_exporter
18789  tcp     127.0.0.1     🟢loopback  1497   openclaw
...

⚠ 2 unclaimed ports: 3200, 44707
⚠ 3 wildcard binds: 22, 3000, 9100
```

Remote node:
```
$ portkeep scan --node node2

node2 — 6 ports (1 loopback · 2 LAN · 3 WAN)

PORT   PROTO   ADDRESS       SCOPE   PID   PROCESS
22     tcp     0.0.0.0       🔴wan    892   sshd
3000   tcp     0.0.0.0       🔴wan    901   netdata
5678   tcp     0.0.0.0       🔴wan    912   node
8080   tcp     0.0.0.0       🔴wan    920   node
9100   tcp     *             ⛔wildcard 905  node_exporter

⚠ 1 unclaimed port: 9100
```

### 2. sync

```
$ portkeep sync
Syncing threat intelligence...
  ℹ  ABUSE_CH_AUTH_KEY not set
     ThreatFox, URLhaus, MalwareBazaar will be skipped
     Get a free key at: https://auth.abuse.ch

  ✓ cisa-kev          1192 entries
  ✓ epss              1000 entries
  ✓ feodo              5 entries
  ✓ emerging-threats  892 entries
  ✓ blocklist.de      37841 entries
  ✓ dshield-sans      20 entries
  ℹ threatfox         skipped — ABUSE_CH_AUTH_KEY not set
  ℹ urlhaus           skipped — ABUSE_CH_AUTH_KEY not set
  ℹ malwarebazaar     skipped — ABUSE_CH_AUTH_KEY not set

6 sources synced · 3 skipped · 41005 total entries cached

Tip: set ABUSE_CH_AUTH_KEY to enable ThreatFox, URLhaus, MalwareBazaar
     Get a free key at: https://auth.abuse.ch

$ ABUSE_CH_AUTH_KEY=your-key portkeep sync
Syncing threat intelligence...

  ✓ cisa-kev          1192 entries
  ✓ epss              1000 entries
  ✓ feodo              5 entries
  ✓ threatfox         447 entries
  ✓ urlhaus           284 entries
  ✓ malwarebazaar     100 entries — hash metadata cached (no direct port data — process correlation planned for v0.2)
  ✓ emerging-threats  892 entries
  ✓ blocklist.de      37841 entries
  ✓ dshield-sans      20 entries

9 sources synced · 0 skipped · 41826 total entries cached
```

### 3. audit

```
$ portkeep audit

╔══════════════════════════════════════════════════╗
║  PortKeep — Security Audit  ·  node1             ║
║  Exposure Score:  38/100  ████████░░░░░░░░░░░░ MODERATE ║
╚══════════════════════════════════════════════════╝

THREAT INTEL  synced 2m ago
  ✓ no C2 port or KEV CVE matches

BIND SCOPE BREAKDOWN
  🟢 loopback     6 ports
  🔴 wan          7 ports
  ⛔ wildcard     2 ports

FINDINGS
  ⛔ port 3000/tcp (node) — wildcard bind (0.0.0.0/::), unclaimed
  ⛔ port 9100/tcp (node_exporter) — wildcard bind (0.0.0.0/::)
  🔴 port 3200/tcp (unknown) — WAN reachable, unclaimed

FIREWALL (ufw)
  ⚠ port 3200 — no firewall rule
  ✗ port 3000 — rule too permissive (from Anywhere)

SUMMARY
  2 critical · 1 high · 3 warnings
  Exposure score: 38/100
```

Quick score only:
```
$ portkeep audit --score
38
```

With threat intel active (C2 hit example):
```
$ portkeep audit

THREAT INTEL  synced 5m ago
  ⛔ 1 C2 port match found

FINDINGS
  ⛔ port 4444/tcp (unknown) — THREAT: C2 port (feodo/Emotet), wildcard bind, unclaimed
```

### 4. claim / drift

```
$ portkeep claim 3200 --service python-monitor --note "Prometheus python exporter"

✓ Port 3200 claimed by python-monitor on node1
  Bind: 0.0.0.0 (WAN) — ⚠ consider restricting to loopback or LAN

$ portkeep claim next --range reserved

Next available port in reserved range (1024–4999): 1024

$ portkeep drift

node1 — 2 drift events

  ⛔ ROGUE  port 44707/tcp listening on 127.0.0.1, not claimed
  🟡 BIND   port 3000/tcp declared loopback, actually :: (wildcard)

2 total drift events · exit 1

$ portkeep drift --quiet && echo "clean" || echo "DRIFT DETECTED"
DRIFT DETECTED
```

### 5. history

```
$ portkeep history

Jun 5 10:22  +port 44707 (unknown) appeared on node1, loopback
Jun 4 18:01  -port 8081 (lfit-quick) disappeared on node1
Jun 4 17:45  ~port 3000 bind changed 127.0.0.1 → :: on node1
Jun 3 14:22  +port 3200 (python3) appeared on node1, WAN
Jun 2 09:00  +claim 8799 dig-agent on node1
```

---

## Threat Intel Workflow

```
$ portkeep sync               # pull all 9 sources
$ portkeep audit              # see C2 matches + KEV hits in findings
```

When the audit detects a C2 port match:
```
THREAT INTEL  synced 5m ago
  ⛔ 1 C2 port match found

FINDINGS
  ⛔ port 4444/tcp (—) — THREAT: C2 port (feodo/Emotet), wildcard bind, unclaimed
     Fix: close this port immediately or identify the process
```

When a KEV CVE hit is found:
```
THREAT INTEL  synced 5m ago
  🔴 1 port running software with active CISA-KEV CVEs

FINDINGS
  🔴 port 22/tcp (sshd) — SSH exposed, THREAT: 3 active KEV CVE(s) for sshd
```

---

## Alerting

```
$ portkeep alert add --trigger rogue --destination telegram \
    --config '{"chat_id":"YOUR_CHAT_ID","bot_token":"YOUR_TOKEN"}'

✓ Telegram alert destination added

$ portkeep alert list

ID  TRIGGER       DESTINATION  ENABLED
1   rogue          telegram     yes
2   bind-change    telegram     yes
```

Telegram message format:
```
⚠ PORTKEEP ALERT — rogue port

node1: port 44707 appeared on 127.0.0.1
Process: unknown
No claim found for this port.

Investigate: portkeep scan
Claim it:    portkeep claim 44707 --service <name>
```

---

## Multi-Node

```
$ portkeep node add node2 --host 192.168.1.86 --ssh-key ~/.ssh/id_ed25519 --label dev

✓ Node node2 registered

$ portkeep node list

NODE    HOST             PORTS  LAST SCAN         STATUS
node1   127.0.0.1        18     5 min ago          ✓ online
node2   192.168.1.86     6      2 min ago          ✓ online
```

---

## Daemon Mode

```
$ portkeep daemon install

✓ systemd unit written to ~/.config/systemd/user/portkeep.service
  Start: systemctl --user enable --now portkeep

$ portkeep daemon status

daemon: running (PID 2891)
interval: 300s
last scan: 10:51:02 — no drift
```

---

## Help Output

```
$ portkeep --help

PortKeep — port management + security for self-hosted infra

Usage: portkeep <command> [flags]

Commands:
  scan     Discover listening ports
  sync     Pull threat intel from 9 sources
  claim    Register/unregister ports
  unclaim  Remove a port registration
  list     List claimed ports
  drift    Check declared vs actual (exits 1 on drift)
  audit    Security scoring + risk flags + threat intel
  history  Change timeline + diffs
  node     Manage remote nodes
  alert    Configure alerts + rules
  daemon   Background service mode
  config   Settings + initialization
  version  Print version info

Flags:
  --node    Target node name (default: localhost)
  --json    Machine-readable output
  --quiet   Errors only
  --help    Help for any command

Examples:
  portkeep scan                    # scan this host
  portkeep sync                    # pull threat intel
  portkeep audit                   # security score + findings
  portkeep drift --quiet           # CI/cron drift check
  portkeep claim next --range dev  # find open port

Docs: https://github.com/jchandler187/portkeep
```

---

## Output Color Convention

- 🟢 Green — safe (loopback, claimed, passed)
- 🟡 Yellow — moderate (LAN, warning)
- 🔴 Red — needs attention (WAN, unclaimed, drift)
- ⛔ Bold red — critical (wildcard, C2 match, CVE hit)

---

## Roadmap (not yet implemented)

These features are in the specification but not implemented in v0.1:

- **Interactive terminal UI** (`portkeep` with no arguments — planned for v0.2)
- **CVE lookup** (`portkeep cve` — cross-reference running services against KEV/EPSS)
- **Service fingerprinting** (`portkeep fingerprint` — nmap -sV integration)
- **Compliance templates** (`portkeep compliance` — CIS, CISA SMB baseline)
- **Prometheus/Grafana export** (`portkeep export`)
- **Snapshot compare** (`portkeep snapshot`)
