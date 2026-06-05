package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
)

var driftCmd = &cobra.Command{
	Use:   "drift",
	Short: "Check declared vs actual ports — exits 1 on drift",
	Long: `Compare the port registry against actual listening ports.
Reports rogue ports (listening but unclaimed), ghost ports (claimed but not listening),
and bind mismatches (declared loopback, actually on wider scope).`,
	Example: `  portkeep drift
  portkeep drift --all
  portkeep drift --quiet && echo "clean" || echo "DRIFT"`,
	RunE: func(cmd *cobra.Command, args []string) error {
		nodes := []string{nodeFlag}
		allFlag, _ := cmd.Flags().GetBool("all")
		if allFlag {
			rows, err := db.Query(`SELECT name FROM nodes`)
			if err != nil {
				return err
			}
			defer rows.Close()
			nodes = nodes[:0]
			for rows.Next() {
				var n string
				rows.Scan(&n)
				nodes = append(nodes, n)
			}
		}

		totalDrift := 0
		type DriftEvent struct {
			Severity string `json:"severity"`
			Type     string `json:"type"`
			Port     int    `json:"port"`
			Protocol string `json:"protocol"`
			Detail   string `json:"detail"`
			Node     string `json:"node"`
		}
		var allEvents []DriftEvent

		for _, nodeName := range nodes {
			// Get actual ports
			actualRows, err := db.Query(`SELECT port, protocol, bind_addr, scope FROM ports WHERE node_name = ?`, nodeName)
			if err != nil {
				continue
			}
			type portInfo struct {
				port   int
				proto  string
				bind   string
				scope  string
			}
			actualMap := make(map[string]portInfo)
			for actualRows.Next() {
				var p portInfo
				actualRows.Scan(&p.port, &p.proto, &p.bind, &p.scope)
				key := fmt.Sprintf("%d/%s", p.port, p.proto)
				actualMap[key] = p
			}
			actualRows.Close()

			// Get claimed ports
			claimRows, err := db.Query(`SELECT port, protocol, service_name, declared_bind FROM claims WHERE node_name = ?`, nodeName)
			if err != nil {
				continue
			}
			type claimInfo struct {
				port     int
				proto    string
				service  string
				declBind string
			}
			claimMap := make(map[string]claimInfo)
			for claimRows.Next() {
				var c claimInfo
				claimRows.Scan(&c.port, &c.proto, &c.service, &c.declBind)
				key := fmt.Sprintf("%d/%s", c.port, c.proto)
				claimMap[key] = c
			}
			claimRows.Close()

			nodeDrift := 0

			// Rogue: actual but not claimed
			for key, p := range actualMap {
				if _, claimed := claimMap[key]; !claimed {
					severity := "🟡"
					if p.scope == "wan" || p.scope == "wildcard" {
						severity = "🔴"
					}
					allEvents = append(allEvents, DriftEvent{
						Severity: severity, Type: "rogue", Port: p.port, Protocol: p.proto,
						Detail: fmt.Sprintf("listening on %s (%s), not claimed", p.bind, p.scope), Node: nodeName,
					})
					nodeDrift++
				}
			}

			// Ghost: claimed but not actual
			for key, c := range claimMap {
				if _, actual := actualMap[key]; !actual {
					allEvents = append(allEvents, DriftEvent{
						Severity: "🟡", Type: "ghost", Port: c.port, Protocol: c.proto,
						Detail: fmt.Sprintf("claimed as %s but not listening", c.service), Node: nodeName,
					})
					nodeDrift++
				}
			}

			// Bind mismatch: declared safer than actual
			for key, c := range claimMap {
				if p, actual := actualMap[key]; actual && c.declBind != "" {
					declScope := classifyBind(c.declBind)
					if scopeRank(p.scope) > scopeRank(declScope) {
						allEvents = append(allEvents, DriftEvent{
							Severity: "🟡", Type: "bind-mismatch", Port: c.port, Protocol: c.proto,
							Detail: fmt.Sprintf("declared %s (%s), actually %s (%s)", c.declBind, declScope, p.bind, p.scope), Node: nodeName,
						})
						nodeDrift++
					}
				}
			}

			if !quietMode {
				if nodeDrift == 0 {
					fmt.Printf("%s — clean\n", nodeName)
				} else {
					fmt.Printf("%s — %d drift event(s)\n", nodeName, nodeDrift)
					for _, e := range allEvents {
						if e.Node == nodeName {
							fmt.Printf("  %s %-12s port %d/%s — %s\n", e.Severity, e.Type, e.Port, e.Protocol, e.Detail)
						}
					}
				}
			}

			totalDrift += nodeDrift
		}

		if jsonOutput {
			data, _ := json.MarshalIndent(allEvents, "", "  ")
			fmt.Println(string(data))
		}

		if !quietMode {
			fmt.Printf("\n%d total drift events", totalDrift)
			if totalDrift > 0 {
				fmt.Print(" · exit 1")
			}
			fmt.Println()
		}

		if totalDrift > 0 {
			os.Exit(1)
		}
		return nil
	},
}

func scopeRank(scope string) int {
	switch scope {
	case "loopback":
		return 0
	case "lan":
		return 1
	case "tailscale":
		return 2
	case "wan":
		return 3
	case "wildcard":
		return 4
	default:
		return 5
	}
}

func init() {
	driftCmd.Flags().Bool("all", false, "check all registered nodes")
	rootCmd.AddCommand(driftCmd)
}

var _ = time.Now // keep time import