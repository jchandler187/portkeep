# PortKeep

Port management and security auditing for self-hosted infrastructure.

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

- PortKeep binary: download from [GitHub Releases](https://github.com/jchandler187/portkeep/releases)
- Default binary path: `/usr/local/bin/portkeep` (override with `binaryPath` config or `$PORTKEEP_BIN`)

## Network Disclosures

- Remote node scanning connects to hosts via SSH. Only scan hosts you own.
- Threat intel sync connects to external feeds over the internet.
- Binary is resolved from absolute path, not PATH, to prevent hijacking.
