# PortKeep — OpenClaw Plugin

Port management and security auditing for self-hosted infrastructure.

Discover, claim, and audit every listening port across local and remote nodes. Detect drift, score attack surface, and cross-reference against live threat intelligence.

## Tools

| Tool | Description |
|------|-------------|
| `portkeep_scan` | Discover all listening ports (local or remote nodes via SSH) |
| `portkeep_audit` | Full security audit — exposure score, risk flags, C2/KEV matches |
| `portkeep_drift` | Compare declared vs actual ports, report rogue/ghost/mismatch |
| `portkeep_claim` | Register a port as expected/owned |
| `portkeep_list` | List claimed ports with filters (node, state, bind, service) |
| `portkeep_sync` | Pull threat intel from CISA KEV, Feodo, EPSS, etc. |

## Requirements

- **PortKeep binary** must be installed and on PATH. Download from [GitHub Releases](https://github.com/jchandler187/portkeep/releases).

```bash
# Linux amd64
curl -sL https://github.com/jchandler187/portkeep/releases/latest/download/portkeep_linux_amd64 -o portkeep
chmod +x portkeep && sudo mv portkeep /usr/local/bin/

# macOS Apple Silicon
curl -sL https://github.com/jchandler187/portkeep/releases/latest/download/portkeep_darwin_arm64 -o portkeep
chmod +x portkeep && sudo mv portkeep /usr/local/bin/
```

## Install

```bash
openclaw plugins install clawhub:portkeep
```

## Configuration

Set `binaryPath` in plugin config to pin the exact binary location. If unset, the plugin uses `$PORTKEEP_BIN` or falls back to `/usr/local/bin/portkeep` — **not** bare PATH resolution, to prevent PATH hijacking.

```json
{
  "portkeep": {
    "binaryPath": "/usr/local/bin/portkeep"
  }
}
```

## ⚠️ Network & Privacy Disclosures

- **Remote node scanning** (`scan --node`, `audit --node`, `drift --node`) connects to remote hosts via SSH key auth. Only scan hosts you own and are authorized to access.
- **Threat intel sync** (`sync`) connects to external feeds (CISA KEV, Feodo, EPSS, etc.) over the internet. Review the source list in your portkeep config before running.
- **Binary execution** — the plugin runs a `portkeep` binary resolved from `config.binaryPath` → `$PORTKEEP_BIN` → `/usr/local/bin/portkeep`. Verify the binary integrity if you install from an untrusted source.

## Multi-node support

PortKeep scans remote nodes via SSH key auth. No agent needed on remotes.

```bash
portkeep node add myserver 10.0.0.50 --user admin
portkeep scan --node myserver
portkeep audit --all
```

## Links

- **GitHub**: https://github.com/jchandler187/portkeep
- **ClawHub**: https://clawhub.ai/jchandler187/portkeep
- **CLI docs**: https://github.com/jchandler187/portkeep#readme

## License

MIT