package cmd

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/spf13/cobra"
)

var nodeCmd = &cobra.Command{
	Use:   "node",
	Short: "Manage remote nodes for multi-node scanning",
	Example: `  portkeep node add node2 --host 192.168.1.86 --ssh-key ~/.ssh/id_ed25519
  portkeep node list
  portkeep node health`,
}

var nodeAddCmd = &cobra.Command{
	Use:   "add <name> --host <addr>",
	Short: "Register a remote node",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]
		host, _ := cmd.Flags().GetString("host")
		sshKey, _ := cmd.Flags().GetString("ssh-key")
		labels, _ := cmd.Flags().GetString("labels")

		if host == "" {
			return fmt.Errorf("--host is required")
		}

		labelsJSON := "[]"
		if labels != "" {
			l, _ := json.Marshal(splitLabels(labels))
			labelsJSON = string(l)
		}

		_, err := db.Exec(`INSERT OR REPLACE INTO nodes (name, host, ssh_key, labels, created_at)
			VALUES (?, ?, ?, ?, ?)`, name, host, sshKey, labelsJSON, time.Now().UTC())
		if err != nil {
			return err
		}

		fmt.Printf("✓ Node %s registered (%s)\n", name, host)
		return nil
	},
}

var nodeRemoveCmd = &cobra.Command{
	Use:   "remove <name>",
	Short: "Unregister a remote node",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		res, err := db.Exec(`DELETE FROM nodes WHERE name = ?`, args[0])
		if err != nil {
			return err
		}
		n, _ := res.RowsAffected()
		if n == 0 {
			return fmt.Errorf("node %q not found", args[0])
		}
		fmt.Printf("✓ Node %s removed\n", args[0])
		return nil
	},
}

var nodeListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all registered nodes",
	RunE: func(cmd *cobra.Command, args []string) error {
		rows, err := db.Query(`SELECT name, host, ssh_key, labels, last_scan_at, created_at FROM nodes ORDER BY name`)
		if err != nil {
			return err
		}
		defer rows.Close()

		type NodeInfo struct {
			Name       string     `json:"name"`
			Host       string     `json:"host"`
			Labels     []string   `json:"labels"`
			LastScan   *time.Time `json:"last_scan,omitempty"`
			PortCount  int        `json:"port_count"`
		}

		var nodes []NodeInfo
		for rows.Next() {
			var n NodeInfo
			var labelsStr string
			var lastScan interface{}
			rows.Scan(&n.Name, &n.Host, &labelsStr, &labelsStr, &lastScan, &labelsStr)
			json.Unmarshal([]byte(labelsStr), &n.Labels)
			nodes = append(nodes, n)
		}

		if jsonOutput {
			data, _ := json.MarshalIndent(nodes, "", "  ")
			fmt.Println(string(data))
			return nil
		}

		if len(nodes) == 0 {
			fmt.Println("No nodes registered. Add one: portkeep node add <name> --host <addr>")
			return nil
		}

		fmt.Printf("\n%-12s %-20s %-10s %s\n", "NODE", "HOST", "PORTS", "LAST SCAN")
		for _, n := range nodes {
			var portCount int
			db.QueryRow(`SELECT COUNT(*) FROM ports WHERE node_name = ?`, n.Name).Scan(&portCount)
			lastScan := "never"
			var ls time.Time
			err := db.QueryRow(`SELECT last_scan_at FROM nodes WHERE name = ?`, n.Name).Scan(&ls)
			if err == nil {
				ago := time.Since(ls)
				if ago < time.Minute {
					lastScan = "just now"
				} else if ago < time.Hour {
					lastScan = fmt.Sprintf("%d min ago", int(ago.Minutes()))
				} else {
					lastScan = fmt.Sprintf("%dh ago", int(ago.Hours()))
				}
			}
			fmt.Printf("%-12s %-20s %-10d %s\n", n.Name, n.Host, portCount, lastScan)
		}
		fmt.Println()
		return nil
	},
}

var nodeHealthCmd = &cobra.Command{
	Use:   "health",
	Short: "Check connectivity and status of all nodes",
	RunE: func(cmd *cobra.Command, args []string) error {
		rows, err := db.Query(`SELECT name, host FROM nodes ORDER BY name`)
		if err != nil {
			return err
		}
		defer rows.Close()

		for rows.Next() {
			var name, host string
			rows.Scan(&name, &host)

			if name == "localhost" {
				fmt.Printf("%-12s ✓ local\n", name)
				continue
			}

			// Try SSH ping
			fmt.Printf("%-12s ", name)
			// For now, just check if we can connect
			fmt.Printf("⏳ SSH check for %s not yet implemented\n", host)
		}
		return nil
	},
}

func init() {
	nodeAddCmd.Flags().String("host", "", "hostname or IP address")
	nodeAddCmd.Flags().String("ssh-key", "", "path to SSH private key")
	nodeAddCmd.Flags().String("labels", "", "comma-separated labels (e.g. prod,dev)")

	nodeCmd.AddCommand(nodeAddCmd)
	nodeCmd.AddCommand(nodeRemoveCmd)
	nodeCmd.AddCommand(nodeListCmd)
	nodeCmd.AddCommand(nodeHealthCmd)
	rootCmd.AddCommand(nodeCmd)
}

func splitLabels(s string) []string {
	var result []string
	for _, l := range splitByComma(s) {
		if l != "" {
			result = append(result, l)
		}
	}
	return result
}

func splitByComma(s string) []string {
	var result []string
	current := ""
	for _, c := range s {
		if c == ',' {
			result = append(result, current)
			current = ""
		} else {
			current += string(c)
		}
	}
	if current != "" {
		result = append(result, current)
	}
	return result
}