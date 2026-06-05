package cmd

import (
	"database/sql"
	"fmt"
	"os"

	"github.com/jchandler187/portkeep/internal/config"
	"github.com/spf13/cobra"
)

var (
	db         *sql.DB
	nodeFlag   string
	jsonOutput bool
	quietMode  bool
)

var rootCmd = &cobra.Command{
	Use:   "portkeep",
	Short: "Port management + security for self-hosted infrastructure",
	Long: `PortKeep registers every port your machines expose, prevents conflicts,
and scores your attack surface against threat intelligence.

No cloud account. No agent. One binary.`,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
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
}
