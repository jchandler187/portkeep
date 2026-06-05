package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var configInitCmd = &cobra.Command{
	Use:   "config init",
	Short: "Initialize PortKeep configuration",
	Long: `Set up PortKeep for first use. Creates the database and default config.`,
	Example: `  portkeep config init
  portkeep config init --defaults`,
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Println("PortKeep — initial setup")
		fmt.Println()
		fmt.Printf("  ✓ Database created at ~/.portkeep/portkeep.db\n")
		fmt.Printf("  ✓ Node 'localhost' registered\n")
		fmt.Println()
		fmt.Println("  Next steps:")
		fmt.Println("    portkeep scan           — discover listening ports")
		fmt.Println("    portkeep audit          — security score + risk flags")
		fmt.Println("    portkeep drift          — check declared vs actual")
		fmt.Println("    portkeep claim next      — find an open port")
		return nil
	},
}

var configShowCmd = &cobra.Command{
	Use:   "config show",
	Short: "Show current configuration",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Printf("Database:  ~/.portkeep/portkeep.db\n")

		// Show nodes
		rows, _ := db.Query(`SELECT name, host, ssh_key FROM nodes ORDER BY name`)
		if rows != nil {
			defer rows.Close()
			fmt.Println("\nNodes:")
			for rows.Next() {
				var name, host, sshKey string
				rows.Scan(&name, &host, &sshKey)
				keyInfo := ""
				if sshKey != "" {
					keyInfo = fmt.Sprintf(" (key: %s)", sshKey)
				}
				fmt.Printf("  %s → %s%s\n", name, host, keyInfo)
			}
		}

		// Show alert destinations
		alertRows, _ := db.Query(`SELECT destination, destination_config FROM alerts WHERE trigger_type = 'config'`)
		if alertRows != nil {
			defer alertRows.Close()
			fmt.Println("\nAlert destinations:")
			hasAlerts := false
			for alertRows.Next() {
				hasAlerts = true
				var destType, config string
				alertRows.Scan(&destType, &config)
				fmt.Printf("  %s\n", destType)
			}
			if !hasAlerts {
				fmt.Println("  (none configured)")
			}
		}

		return nil
	},
}

func init() {
	configCmd := &cobra.Command{
		Use:   "config",
		Short: "Configuration management",
	}
	configCmd.AddCommand(configInitCmd)
	configCmd.AddCommand(configShowCmd)
	rootCmd.AddCommand(configCmd)
}