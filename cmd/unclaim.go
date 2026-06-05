package cmd

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"
)

var unclaimCmd = &cobra.Command{
	Use:   "unclaim <port>",
	Short: "Remove a port claim from the registry",
	Example: `  portkeep unclaim 3000
  portkeep unclaim 8080 --proto udp`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		portNum, err := parsePort(args[0])
		if err != nil {
			return err
		}
		proto, _ := cmd.Flags().GetString("proto")

		var service string
		db.QueryRow(`SELECT service_name FROM claims WHERE node_name = ? AND port = ? AND protocol = ?`,
			nodeFlag, portNum, proto).Scan(&service)

		res, err := db.Exec(`DELETE FROM claims WHERE node_name = ? AND port = ? AND protocol = ?`,
			nodeFlag, portNum, proto)
		if err != nil {
			return err
		}

		n, _ := res.RowsAffected()
		if n == 0 {
			return fmt.Errorf("no claim found for port %d/%s on %s", portNum, proto, nodeFlag)
		}

		db.Exec(`INSERT INTO history (node_name, event_type, port, protocol, detail, timestamp)
			VALUES (?, 'unclaim', ?, ?, ?, ?)`,
			nodeFlag, portNum, proto,
			fmt.Sprintf(`{"removed_service":"%s"}`, service),
			time.Now().UTC())

		fmt.Printf("✓ Port %d/%s unclaimed (was %s)\n", portNum, proto, service)
		return nil
	},
}

func init() {
	unclaimCmd.Flags().StringP("proto", "", "tcp", "protocol (tcp or udp)")
	rootCmd.AddCommand(unclaimCmd)
}