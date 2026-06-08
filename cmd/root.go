package cmd

import (
	"database/sql"
	"fmt"
	"os"

	"github.com/lowwattlabs/portkeep/internal/config"
	"github.com/spf13/cobra"
)

var (
	db         *sql.DB
	nodeFlag   string
	jsonOutput bool
	quietMode  bool
	version    = "dev"
	commit     = "none"
	buildDate  = "unknown"
)

var rootCmd = &cobra.Command{
	Use:   "portkeep",
	Short: "Port management + security for self-hosted infrastructure",
	Long: `PortKeep registers every port your machines expose, prevents conflicts,
and scores your attack surface against live threat intelligence.

No cloud account. No agent. One binary.`,
	// RunE prints a short usage hint when portkeep is invoked with no subcommand.
	// Interactive mode is planned for v0.2.
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Println("PortKeep — port management + security for self-hosted infrastructure")
		fmt.Println()
		fmt.Println("Run 'portkeep --help' to see available commands.")
		fmt.Println("Interactive mode is planned for v0.2.")
		return nil
	},
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		// Skip DB open for the root "no-op" invocation
		if cmd.Name() == "portkeep" {
			return nil
		}
		var err error
		dbPath := config.DBPath()
		db, err = openDB(dbPath)
		if err != nil {
			return fmt.Errorf("open db: %w", err)
		}
		return nil
	},
	PersistentPostRunE: func(cmd *cobra.Command, args []string) error {
		if db != nil {
			return db.Close()
		}
		return nil
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&nodeFlag, "node", "n", "localhost", "node name")
	rootCmd.PersistentFlags().BoolVar(&jsonOutput, "json", false, "JSON output")
	rootCmd.PersistentFlags().BoolVarP(&quietMode, "quiet", "q", false, "errors only")

	versionCmd := &cobra.Command{
		Use:   "version",
		Short: "Print version info",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("portkeep %s (commit: %s, built: %s)\n", version, commit, buildDate)
		},
	}
	rootCmd.AddCommand(versionCmd)
}
