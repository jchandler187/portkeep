package cmd

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/spf13/cobra"
)

var claimCmd = &cobra.Command{
	Use:   "claim <port> <service>",
	Short: "Register a port as claimed/expected",
	Long: `Register a port in the registry so it is considered expected.
Ports not in the registry are flagged as unregistered during scoring and drift checks.`,
	Example: `  portkeep claim 22 sshd --note "system SSH"
  portkeep claim 3000 dashboard --note "homelab dash" --range dashboard
  portkeep claim next --range reserved`,
	Args: cobra.MinimumNArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		portNum, err := parsePort(args[0])
		if err != nil {
			return err
		}
		service := args[1]

		note, _ := cmd.Flags().GetString("note")
		proto, _ := cmd.Flags().GetString("proto")
		portRange, _ := cmd.Flags().GetString("range")
		owner, _ := cmd.Flags().GetString("owner")
		declaredBind, _ := cmd.Flags().GetString("bind")

		// Check for conflict
		var existing string
		err = db.QueryRow(`SELECT service_name FROM claims WHERE node_name = ? AND port = ? AND protocol = ?`,
			nodeFlag, portNum, proto).Scan(&existing)
		if err == nil && existing != "" {
			force, _ := cmd.Flags().GetBool("force")
			if !force {
				return fmt.Errorf("port %d/%s already claimed by %q — use --force to override, or pick another port", portNum, proto, existing)
			}
		}

		_, err = db.Exec(`INSERT OR REPLACE INTO claims (node_name, port, protocol, service_name, declared_bind, port_range, owner, note, created_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			nodeFlag, portNum, proto, service, declaredBind, portRange, owner, note, time.Now().UTC())
		if err != nil {
			return err
		}

		// Log history
		db.Exec(`INSERT INTO history (node_name, event_type, port, protocol, detail, timestamp)
			VALUES (?, 'claim', ?, ?, ?, ?)`,
			nodeFlag, portNum, proto,
			fmt.Sprintf(`{"service":"%s","note":"%s"}`, service, note),
			time.Now().UTC())

		if jsonOutput {
			fmt.Printf(`{"port":%d,"service":"%s","node":"%s","status":"claimed"}`, portNum, service, nodeFlag)
			return nil
		}

		fmt.Printf("✓ Port %d/%s claimed by %s on %s\n", portNum, proto, service, nodeFlag)
		if declaredBind != "" {
			scope := classifyBind(declaredBind)
			if scope == "wildcard" || scope == "wan" {
				fmt.Printf("  ⚠ Bind %s (%s) — consider restricting to loopback or LAN\n", declaredBind, scope)
			}
		}
		return nil
	},
}

var claimNextCmd = &cobra.Command{
	Use:   "next",
	Short: "Suggest the next available port in a range",
	Example: `  portkeep claim next
  portkeep claim next --range reserved
  portkeep claim next --range dashboard`,
	RunE: func(cmd *cobra.Command, args []string) error {
		portRange, _ := cmd.Flags().GetString("range")
		if portRange == "" {
			portRange = "reserved"
		}

		low, high := rangeBounds(portRange)

		// Find claimed ports in range
		rows, err := db.Query(`SELECT port FROM claims WHERE node_name = ? AND port BETWEEN ? AND ? ORDER BY port`,
			nodeFlag, low, high)
		if err != nil {
			return err
		}
		defer rows.Close()

		claimed := make(map[int]bool)
		for rows.Next() {
			var p int
			rows.Scan(&p)
			claimed[p] = true
		}

		var available []int
		for i := low; i <= high && len(available) < 3; i++ {
			if !claimed[i] {
				available = append(available, i)
			}
		}

		if len(available) == 0 {
			return fmt.Errorf("no available ports in %s range (%d-%d)", portRange, low, high)
		}

		if jsonOutput {
			data, _ := json.Marshal(map[string]interface{}{
				"range":     portRange,
				"suggested": available[0],
				"available": available,
			})
			fmt.Println(string(data))
			return nil
		}

		fmt.Printf("\nNext available port in %s range (%d-%d):\n", portRange, low, high)
		for i, p := range available {
			suffix := ""
			if i == 0 {
				suffix = "  ← suggested"
			}
			fmt.Printf("  %d%s\n", p, suffix)
		}
		fmt.Printf("\n  portkeep claim %d <service>\n", available[0])
		return nil
	},
}

func init() {
	claimCmd.Flags().StringP("note", "", "", "human-readable description")
	claimCmd.Flags().StringP("proto", "", "tcp", "protocol (tcp or udp)")
	claimCmd.Flags().StringP("range", "", "", "port range (system/reserved/dashboard/ephemeral)")
	claimCmd.Flags().StringP("owner", "", "", "owner of this port")
	claimCmd.Flags().StringP("bind", "", "", "declared bind address")
	claimCmd.Flags().Bool("force", false, "override existing claim")

	claimNextCmd.Flags().StringP("range", "", "reserved", "port range to search")

	claimCmd.AddCommand(claimNextCmd)
	rootCmd.AddCommand(claimCmd)
}

func parsePort(s string) (int, error) {
	var p int
	_, err := fmt.Sscanf(s, "%d", &p)
	if err != nil || p < 1 || p > 65535 {
		return 0, fmt.Errorf("invalid port: %s (must be 1-65535)", s)
	}
	return p, nil
}

func rangeBounds(name string) (int, int) {
	switch name {
	case "system":
		return 1, 1023
	case "reserved":
		return 1024, 4999
	case "dashboard":
		return 5000, 9999
	case "ephemeral":
		return 10000, 65535
	default:
		return 1024, 4999
	}
}