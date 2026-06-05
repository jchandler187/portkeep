package cmd

import (
	"encoding/json"
	"fmt"

	"github.com/jchandler187/portkeep/internal/config"
	"github.com/jchandler187/portkeep/internal/threatintel"
	"github.com/spf13/cobra"
)

var syncCmd = &cobra.Command{
	Use:   "sync",
	Short: "Sync threat intelligence from all 9 sources",
	Long: `Download and cache threat intelligence data from 9 sources.

  Sources (no authentication required):
    cisa-kev        CISA Known Exploited Vulnerabilities catalog
    epss            FIRST.org Exploit Prediction Scoring System (top 1000 by score)
    feodo           Feodo C2 botnet tracker (abuse.ch)
    emerging-threats Proofpoint/Emerging Threats compromised hosts
    blocklist.de    Blocklist.de attack IP list
    dshield-sans    SANS Internet Storm Center top attacking netblocks

  Sources (free Auth-Key required — set ABUSE_CH_AUTH_KEY):
    threatfox       ThreatFox IOC database (abuse.ch)
    urlhaus         URLhaus malicious URL database (abuse.ch)
    malwarebazaar   MalwareBazaar sample metadata (abuse.ch; no direct port data)

  Get your free abuse.ch Auth-Key at: https://auth.abuse.ch`,
	Example: `  portkeep sync
  ABUSE_CH_AUTH_KEY=your-key portkeep sync
  portkeep sync --json`,
	RunE: func(cmd *cobra.Command, args []string) error {
		authKey := config.AbuseChAuthKey()
		cacheDir := config.CacheDir()

		if !quietMode {
			fmt.Println("Syncing threat intelligence...")
			if authKey == "" {
				fmt.Println("  ℹ  ABUSE_CH_AUTH_KEY not set")
				fmt.Println("     ThreatFox, URLhaus, MalwareBazaar will be skipped")
				fmt.Println("     Get a free key at: https://auth.abuse.ch")
			}
			fmt.Println()
		}

		statuses, err := threatintel.SyncAll(cacheDir, authKey, 30)
		if err != nil {
			return fmt.Errorf("sync: %w", err)
		}

		if jsonOutput {
			data, _ := json.MarshalIndent(statuses, "", "  ")
			fmt.Println(string(data))
			return nil
		}

		okCount := 0
		skippedCount := 0
		errCount := 0
		totalEntries := 0

		for _, s := range statuses {
			switch s.Status {
			case "ok":
				okCount++
				totalEntries += s.Count
				detail := ""
				if s.Detail != "" {
					detail = " — " + s.Detail
				}
				fmt.Printf("  ✓ %-18s %d entries%s\n", s.Source, s.Count, detail)
			case "skipped":
				skippedCount++
				fmt.Printf("  ℹ %-18s skipped — %s\n", s.Source, s.Detail)
			case "error":
				errCount++
				fmt.Printf("  ✗ %-18s error — %s\n", s.Source, s.Detail)
			}
		}

		fmt.Printf("\n%d sources synced", okCount)
		if skippedCount > 0 {
			fmt.Printf(" · %d skipped", skippedCount)
		}
		if errCount > 0 {
			fmt.Printf(" · %d errors", errCount)
		}
		fmt.Printf(" · %d total entries cached\n", totalEntries)

		if skippedCount == 3 && authKey == "" {
			fmt.Printf("\nTip: set ABUSE_CH_AUTH_KEY to enable ThreatFox, URLhaus, MalwareBazaar\n")
			fmt.Printf("     Get a free key at: https://auth.abuse.ch\n")
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(syncCmd)
}
