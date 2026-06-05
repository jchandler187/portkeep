package cmd

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/spf13/cobra"
)

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List all registered port claims",
	Example: `  portkeep list
  portkeep list --node node2
  portkeep list --json`,
	RunE: func(cmd *cobra.Command, args []string) error {
		rows, err := db.Query(`SELECT port, protocol, service_name, declared_bind, port_range, owner, note, created_at
			FROM claims WHERE node_name = ? ORDER BY port`, nodeFlag)
		if err != nil {
			return err
		}
		defer rows.Close()

		type ClaimRow struct {
			Port         int       `json:"port"`
			Protocol     string    `json:"protocol"`
			Service      string    `json:"service"`
			DeclaredBind string   `json:"declared_bind,omitempty"`
			PortRange    string    `json:"range,omitempty"`
			Owner        string    `json:"owner,omitempty"`
			Note         string    `json:"note,omitempty"`
			CreatedAt    time.Time `json:"created_at"`
		}

		var claims []ClaimRow
		for rows.Next() {
			var c ClaimRow
			rows.Scan(&c.Port, &c.Protocol, &c.Service, &c.DeclaredBind, &c.PortRange, &c.Owner, &c.Note, &c.CreatedAt)
			claims = append(claims, c)
		}

		if jsonOutput {
			data, _ := json.MarshalIndent(claims, "", "  ")
			fmt.Println(string(data))
			return nil
		}

		if len(claims) == 0 {
			fmt.Printf("No ports claimed on %s. Start with: portkeep claim <port> <service>\n", nodeFlag)
			return nil
		}

		fmt.Printf("\n%s — %d claimed ports\n\n", nodeFlag, len(claims))
		fmt.Printf("%-8s %-6s %-20s %-15s %-10s %s\n", "PORT", "PROTO", "SERVICE", "BIND", "RANGE", "NOTE")
		for _, c := range claims {
			bind := c.DeclaredBind
			if bind == "" {
				bind = "—"
			}
			rng := c.PortRange
			if rng == "" {
				rng = "—"
			}
			note := c.Note
			if len(note) > 30 {
				note = note[:27] + "..."
			}
			fmt.Printf("%-8d %-6s %-20s %-15s %-10s %s\n", c.Port, c.Protocol, c.Service, bind, rng, note)
		}
		fmt.Println()
		return nil
	},
}

func init() {
	rootCmd.AddCommand(listCmd)
}