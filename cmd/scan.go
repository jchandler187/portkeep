package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/jchandler187/portkeep/internal/portscanner"
	"github.com/spf13/cobra"
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan listening ports on this host (or a remote node)",
	Long: `Discover all listening TCP and UDP ports on the local host.
Uses /proc/net/tcp on Linux for fast, zero-dependency scanning.`,
	Example: `  portkeep scan
  portkeep scan --node node2
  portkeep scan --json`,
	RunE: func(cmd *cobra.Command, args []string) error {
		nodeName := nodeFlag

		var ports []portscanner.OpenPort
		var err error

		if nodeName == "localhost" {
			ports, err = portscanner.Scan()
		} else {
			// Remote scan via SSH
			var host, sshKey string
			err = db.QueryRow(`SELECT host, ssh_key FROM nodes WHERE name = ?`, nodeName).Scan(&host, &sshKey)
			if err != nil {
				return fmt.Errorf("node %q not found — add it with: portkeep node add %s --host <addr>", nodeName, nodeName)
			}
			ports, err = remoteScan(host, sshKey)
		}

		if err != nil {
			return fmt.Errorf("scan failed: %w", err)
		}

		now := time.Now().UTC()

		// Upsert all discovered ports into DB
		for _, p := range ports {
			scope := classifyBind(p.Address)
			_, err := db.Exec(`INSERT INTO ports (node_name, port, protocol, bind_addr, scope, process_name, first_seen, last_seen)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?)
				ON CONFLICT(node_name, port, protocol, bind_addr) DO UPDATE SET
					scope=excluded.scope, process_name=excluded.process_name, last_seen=excluded.last_seen`,
				nodeName, p.Port, p.Protocol, p.Address, scope, p.Process, now, now)
			if err != nil {
				fmt.Fprintf(os.Stderr, "warn: upsert port %d: %v\n", p.Port, err)
			}
		}

		// Find ports that disappeared (were in DB but not in this scan)
		currentPorts := make(map[string]bool)
		for _, p := range ports {
			currentPorts[fmt.Sprintf("%d/%s/%s", p.Port, p.Protocol, p.Address)] = true
		}

		rows, _ := db.Query(`SELECT port, protocol, bind_addr FROM ports WHERE node_name = ?`, nodeName)
		if rows != nil {
			defer rows.Close()
			for rows.Next() {
				var portNum int
				var proto, bind string
				if rows.Scan(&portNum, &proto, &bind) == nil {
					key := fmt.Sprintf("%d/%s/%s", portNum, proto, bind)
					if !currentPorts[key] {
						// Port disappeared — log it and remove
						db.Exec(`DELETE FROM ports WHERE node_name = ? AND port = ? AND protocol = ? AND bind_addr = ?`,
							nodeName, portNum, proto, bind)
						db.Exec(`INSERT INTO history (node_name, event_type, port, protocol, detail, timestamp)
							VALUES (?, 'disappear', ?, ?, ?, ?)`,
							nodeName, portNum, proto, fmt.Sprintf(`{"bind":"%s"}`, bind), now)
					}
				}
			}
		}

		// Log appeared ports (check if they were new since last scan)
		for _, p := range ports {
			var firstSeen time.Time
			err := db.QueryRow(`SELECT first_seen FROM ports WHERE node_name = ? AND port = ? AND protocol = ? AND bind_addr = ?`,
				nodeName, p.Port, p.Protocol, p.Address).Scan(&firstSeen)
			if err == nil && firstSeen.Add(2*time.Second).After(now) {
				// New port — log history
				db.Exec(`INSERT INTO history (node_name, event_type, port, protocol, detail, timestamp)
					VALUES (?, 'appear', ?, ?, ?, ?)`,
					nodeName, p.Port, p.Protocol,
					fmt.Sprintf(`{"bind":"%s","process":"%s","pid":%d}`, p.Address, p.Process, p.PID),
					now)
			}
		}

		// Update node's last scan time
		db.Exec(`UPDATE nodes SET last_scan_at = ? WHERE name = ?`, now, nodeName)

		if jsonOutput {
			data, _ := json.MarshalIndent(ports, "", "  ")
			fmt.Println(string(data))
			return nil
		}

		if quietMode {
			return nil
		}

		// Table output
		scopeCounts := map[string]int{}
		for _, p := range ports {
			scopeCounts[classifyBind(p.Address)]++
		}

		fmt.Printf("\n%s — %d ports", nodeName, len(ports))
		if len(scopeCounts) > 0 {
			fmt.Printf(" (%s", formatScopeCounts(scopeCounts))
			fmt.Print(")")
		}
		fmt.Println()

		fmt.Printf("\n%-8s %-8s %-20s %-10s %-6s %s\n", "PORT", "PROTO", "ADDRESS", "SCOPE", "PID", "PROCESS")
		for _, p := range ports {
			scope := classifyBind(p.Address)
			scopeIcon := scopeIcon(scope)
			fmt.Printf("%-8d %-8s %-20s %-10s %-6d %s\n", p.Port, p.Protocol, p.Address, scopeIcon+scope, p.PID, p.Process)
		}

		// Warnings
		var rogueCount, wildcardCount int
		for _, p := range ports {
			var cnt int
			db.QueryRow(`SELECT COUNT(*) FROM claims WHERE node_name = ? AND port = ? AND protocol = ?`,
				nodeName, p.Port, p.Protocol).Scan(&cnt)
			if cnt == 0 {
				rogueCount++
			}
			if classifyBind(p.Address) == "wildcard" {
				wildcardCount++
			}
		}

		fmt.Println()
		if rogueCount > 0 {
			fmt.Printf("⚠ %d unclaimed ports\n", rogueCount)
		}
		if wildcardCount > 0 {
			fmt.Printf("⚠ %d wildcard binds\n", wildcardCount)
		}
		if rogueCount == 0 && wildcardCount == 0 {
			fmt.Println("✓ All ports claimed, no wildcard binds")
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(scanCmd)
}

func classifyBind(addr string) string {
	switch {
	case addr == "127.0.0.1" || addr == "::1" || addr == "127.0.0.53" || addr == "127.0.0.54":
		return "loopback"
	case addr == "0.0.0.0" || addr == "*" || addr == "::":
		return "wildcard"
	case startsWith(addr, "192.168.") || startsWith(addr, "10.") || startsWith(addr, "172."):
		return "lan"
	case startsWith(addr, "100."):
		return "tailscale"
	default:
		return "wan"
	}
}

func startsWith(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}

func formatScopeCounts(m map[string]int) string {
	parts := []string{}
	for _, scope := range []string{"loopback", "lan", "tailscale", "wan", "wildcard"} {
		if c, ok := m[scope]; ok {
			parts = append(parts, fmt.Sprintf("%d %s", c, scope))
		}
	}
	return joinStrings(parts, " · ")
}

func joinStrings(ss []string, sep string) string {
	result := ""
	for i, s := range ss {
		if i > 0 {
			result += sep
		}
		result += s
	}
	return result
}

func scopeIcon(scope string) string {
	switch scope {
	case "loopback":
		return "🟢"
	case "lan":
		return "🟡"
	case "tailscale":
		return "🔴"
	case "wan":
		return "🔴"
	case "wildcard":
		return "⛔"
	default:
		return "⚪"
	}
}

func remoteScan(host, sshKey string) ([]portscanner.OpenPort, error) {
	// TODO: implement SSH remote scan via sshclient package
	return nil, fmt.Errorf("remote scan not yet implemented (use --node localhost)")
}