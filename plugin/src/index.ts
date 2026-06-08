import { Type } from "typebox";
import { defineToolPlugin } from "openclaw/plugin-sdk/tool-plugin";
import { execFile } from "node:child_process";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

/** Commands that access remote nodes via SSH or external threat intel feeds.
 *  Blocked unless the user has explicitly enabled remote operations in config. */
const REMOTE_COMMANDS = new Set(["sync"]);
const REMOTE_FLAGS = new Set(["--node", "--all"]);

/** Check whether the given args will trigger a remote operation.
 *  Throws if remote access is attempted without allowRemote enabled. */
function checkRemoteAccess(args: string[], allowRemote: boolean): void {
  const hasRemoteFlag = args.some(a => REMOTE_FLAGS.has(a));
  const isRemoteCommand = REMOTE_COMMANDS.has(args[0]);

  if (!hasRemoteFlag && !isRemoteCommand) return; // local-only, no guard needed

  if (!allowRemote) {
    const isNodeArg = args.some((a, i) => a === "--node" && i + 1 < args.length);
    const nodeName = isNodeArg ? args[args.indexOf("--node") + 1] : null;
    const isAll = args.includes("--all");
    const target = isRemoteCommand
      ? "external threat intel feeds over the internet"
      : isAll
        ? "all registered remote nodes via SSH"
        : nodeName
          ? `remote node \"${nodeName}\" via SSH`
          : "a remote node via SSH";
    throw new Error(
      `Blocked: this operation would access ${target}. ` +
      `Set allowRemote: true in plugin config to enable remote operations. ` +
      `Only enable if you trust the agent to scan remote hosts and contact external feeds.`
    );
  }
}

/** Resolve the portkeep binary path.
 *  Priority: config.binaryPath > PORTKEEP_BIN env > /usr/local/bin/portkeep (default absolute path).
 *  Avoids bare PATH resolution to prevent PATH hijacking (SkillSpector finding).
 */
function resolveBinary(configBinary?: string): string {
  if (configBinary) return configBinary;
  if (process.env.PORTKEEP_BIN) return process.env.PORTKEEP_BIN;
  return "/usr/local/bin/portkeep";
}

/** Extract JSON from mixed output. Some portkeep commands (drift) emit
 *  human-readable text before the JSON when --json is set. This finds
 *  and parses just the JSON portion.
 */
function extractJSON(output: string): Record<string, unknown> | string {
  const trimmed = output.trim();
  // Try parsing the whole output as JSON first
  try {
    return JSON.parse(trimmed);
  } catch {
    // Look for the start of a JSON array or object (last occurrence for nested)
    const arrStart = trimmed.lastIndexOf("[");
    const objStart = trimmed.lastIndexOf("{");
    const jsonStart = Math.max(arrStart, objStart);
    if (jsonStart >= 0) {
      const jsonStr = trimmed.substring(jsonStart);
      try {
        return JSON.parse(jsonStr);
      } catch {
        // JSON parse failed — return raw
      }
    }
    return trimmed;
  }
}

/** Run a portkeep command with --json and return parsed output.
 *  Handles non-zero exit codes gracefully — drift returns exit 1 when
 *  drift is found, which is intentional (useful for cron). We still want
 *  the JSON output in that case.
 */
type PortkeepConfig = { binaryPath?: string; allowRemote?: boolean };
async function runPortkeep(args: string[], config?: PortkeepConfig, timeoutMs = 30000): Promise<Record<string, unknown> | string> {
  checkRemoteAccess(args, config?.allowRemote === true);
  const bin = resolveBinary(config?.binaryPath);
  const allArgs = [...args, "--json"];
  try {
    const { stdout, stderr } = await execFileAsync(bin, allArgs, { timeout: timeoutMs, maxBuffer: 1024 * 1024 });
    return extractJSON(stdout || stderr);
  } catch (err: unknown) {
    // Node's execFile rejects on non-zero exit codes. For commands like
    // `drift` that intentionally exit 1 when drift is found, stdout still
    // contains valid JSON. Extract it.
    const error = err as { stdout?: string; stderr?: string; message?: string; code?: string };
    const stdout = error.stdout || "";
    const stderr = error.stderr || "";
    const output = stdout || stderr;
    if (output.trim()) {
      const parsed = extractJSON(output);
      if (typeof parsed === "object") return parsed;
    }
    const detail = stderr || error.message || String(err);
    throw new Error(`portkeep ${args.join(" ")} failed: ${detail}`);
  }
}

export default defineToolPlugin({
  id: "portkeep",
  name: "PortKeep",
  description:
    "Port management and security auditing for self-hosted infrastructure. Discover, claim, and audit every listening port across local and remote nodes. Detect drift, score attack surface, and cross-reference against live threat intelligence.",
  configSchema: Type.Object({
    binaryPath: Type.Optional(
      Type.String({
        description:
          "Absolute path to the portkeep binary. Defaults to /usr/local/bin/portkeep (not PATH-resolved).",
      })
    ),
    allowRemote: Type.Optional(
      Type.Boolean({
        description:
          "Allow remote operations: SSH scanning of remote nodes and external threat intel sync. Default: false. Enable only if you trust the agent to access remote hosts and contact external feeds.",
      })
    ),
  }),
  tools: (tool) => [
    tool({
      name: "portkeep_scan",
      label: "PortKeep Scan",
      description:
        "Discover all listening ports on this host or a remote node. Returns port, protocol, address, scope, PID, process name, and bind address for every listener.",
      parameters: Type.Object({
        node: Type.Optional(
          Type.String({ description: "Remote node name (from portkeep node list) to scan via SSH." })
        ),
        all: Type.Optional(
          Type.Boolean({ description: "Scan all registered nodes." })
        ),
        docker: Type.Optional(
          Type.Boolean({ description: "Include Docker container port mappings." })
        ),
      }),
      async execute({ node, all, docker }, config) {
        const args = ["scan"];
        if (node) args.push("--node", node);
        if (all) args.push("--all");
        if (docker) args.push("--docker");
        return runPortkeep(args, config);
      },
    }),

    tool({
      name: "portkeep_audit",
      label: "PortKeep Audit",
      description:
        "Run a full security audit. Returns an exposure score (0-100), risk flags for each port (wildcard binds, unclaimed ports, C2 port matches), threat intel status, and firewall cross-reference.",
      parameters: Type.Object({
        node: Type.Optional(
          Type.String({ description: "Remote node name to audit." })
        ),
      }),
      async execute({ node }, config) {
        const args = ["audit"];
        if (node) args.push("--node", node);
        return runPortkeep(args, config, 60000);
      },
    }),

    tool({
      name: "portkeep_drift",
      label: "PortKeep Drift",
      description:
        "Compare declared ports against actual listening ports. Reports rogue ports (listening but unclaimed), ghost ports (declared but not listening), and bind scope mismatches. Returns structured JSON with drift_found, total_events, and events array.",
      parameters: Type.Object({
        node: Type.Optional(
          Type.String({ description: "Remote node name to check." })
        ),
        all: Type.Optional(
          Type.Boolean({ description: "Check all registered nodes." })
        ),
      }),
      async execute({ node, all }, config) {
        const args = ["drift"];
        if (node) args.push("--node", node);
        if (all) args.push("--all");
        return runPortkeep(args, config);
      },
    }),

    tool({
      name: "portkeep_claim",
      label: "PortKeep Claim",
      description:
        "Register a port as expected/owned. Prevents drift alerts for known services and tracks ownership.",
      parameters: Type.Object({
        port: Type.Integer({ description: "Port number to claim." }),
        service: Type.String({ description: "Service name for this port (e.g. 'ssh', 'openclaw-gateway')." }),
        bind: Type.Optional(Type.String({ description: "Intended bind address (e.g. '127.0.0.1', '0.0.0.0')." })),
        note: Type.Optional(Type.String({ description: "Free-form note about this port." })),
        node: Type.Optional(Type.String({ description: "Node name if claiming a remote port." })),
      }),
      async execute({ port, service, bind, note, node }, config) {
        const args = ["claim", String(port), service];
        if (bind) args.push("--bind", bind);
        if (note) args.push("--note", note);
        if (node) args.push("--node", node);
        return runPortkeep(args, config);
      },
    }),

    tool({
      name: "portkeep_list",
      label: "PortKeep List",
      description:
        "List all registered port claims. Filter by node, state, bind scope, or service name.",
      parameters: Type.Object({
        node: Type.Optional(Type.String({ description: "Filter by node name." })),
        state: Type.Optional(
          Type.String({ description: "Filter by state: open, closed, declared, rogue." })
        ),
        bind: Type.Optional(
          Type.String({ description: "Filter by bind scope: loopback, lan, wan, wildcard." })
        ),
        service: Type.Optional(Type.String({ description: "Filter by service name." })),
      }),
      async execute({ node, state, bind, service }, config) {
        const args = ["list"];
        if (node) args.push("--node", node);
        if (state) args.push("--state", state);
        if (bind) args.push("--bind", bind);
        if (service) args.push("--service", service);
        return runPortkeep(args, config);
      },
    }),

    tool({
      name: "portkeep_sync",
      label: "PortKeep Sync",
      description:
        "Pull threat intelligence from all configured sources (CISA KEV, Feodo, EPSS, etc.). Updates the local threat intel database used by audit. Requires internet access for most sources.",
      parameters: Type.Object({}),
      async execute(_params, config) {
        return runPortkeep(["sync"], config, 120000);
      },
    }),
  ],
});