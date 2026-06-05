package cmd

import (
	"encoding/json"
	"fmt"

	"github.com/jchandler187/portkeep/internal/alert"
	"github.com/spf13/cobra"
)

var alertCmd = &cobra.Command{
	Use:   "alert",
	Short: "Configure alerts and notification rules",
	Example: `  portkeep alert config add telegram --chat-id 123456 --bot-token $TOKEN
  portkeep alert rules add --on rogue --destination telegram
  portkeep alert test`,
}

var alertConfigAddCmd = &cobra.Command{
	Use:   "config add <type>",
	Short: "Add an alert destination (telegram/webhook/script)",
	Long: `Add a notification destination. Supported types: telegram, webhook, script.
For Telegram, provide --chat-id and --bot-token.
For webhook, provide --url.
For script, provide --command.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		destType := args[0]
		chatID, _ := cmd.Flags().GetString("chat-id")
		botToken, _ := cmd.Flags().GetString("bot-token")
		url, _ := cmd.Flags().GetString("url")
		command, _ := cmd.Flags().GetString("command")

		configMap := map[string]string{}
		if chatID != "" {
			configMap["chat_id"] = chatID
		}
		if botToken != "" {
			configMap["bot_token"] = botToken
		}
		if url != "" {
			configMap["url"] = url
		}
		if command != "" {
			configMap["command"] = command
		}

		configJSON, _ := json.Marshal(configMap)

		_, err := db.Exec(`INSERT INTO alerts (trigger_type, destination, destination_config, threshold, enabled)
			VALUES (?, ?, ?, 0, 1)`, "config", destType, string(configJSON))
		if err != nil {
			return err
		}

		fmt.Printf("✓ %s alert destination added\n", destType)
		return nil
	},
}

var alertRulesAddCmd = &cobra.Command{
	Use:   "rules add",
	Short: "Add an alert rule",
	Example: `  portkeep alert rules add --on rogue --destination telegram
  portkeep alert rules add --on bind-change --destination telegram
  portkeep alert rules add --on score-change --threshold 20 --destination telegram`,
	RunE: func(cmd *cobra.Command, args []string) error {
		on, _ := cmd.Flags().GetString("on")
		destination, _ := cmd.Flags().GetString("destination")
		threshold, _ := cmd.Flags().GetInt("threshold")

		if on == "" || destination == "" {
			return fmt.Errorf("--on and --destination are required")
		}

		// Look up the destination config
		var destConfig string
		err := db.QueryRow(`SELECT destination_config FROM alerts WHERE destination = ? AND trigger_type = 'config' LIMIT 1`, destination).Scan(&destConfig)
		if err != nil {
			return fmt.Errorf("destination %q not found — add it with: portkeep alert config add %s", destination, destination)
		}

		_, err = db.Exec(`INSERT INTO alerts (trigger_type, destination, destination_config, threshold, enabled)
			VALUES (?, ?, ?, ?, 1)`, on, destination, destConfig, threshold)
		if err != nil {
			return err
		}

		fmt.Printf("✓ Alert rule added: notify %s when %s\n", destination, on)
		return nil
	},
}

var alertRulesListCmd = &cobra.Command{
	Use:   "rules list",
	Short: "List active alert rules",
	RunE: func(cmd *cobra.Command, args []string) error {
		rows, err := db.Query(`SELECT id, trigger_type, destination, threshold, enabled FROM alerts WHERE trigger_type != 'config' ORDER BY id`)
		if err != nil {
			return err
		}
		defer rows.Close()

		type Rule struct {
			ID          int64  `json:"id"`
			TriggerType string `json:"on"`
			Destination string `json:"destination"`
			Threshold   int    `json:"threshold,omitempty"`
			Enabled     bool   `json:"enabled"`
		}

		var rules []Rule
		for rows.Next() {
			var r Rule
			var enabled int
			rows.Scan(&r.ID, &r.TriggerType, &r.Destination, &r.Threshold, &enabled)
			r.Enabled = enabled == 1
			rules = append(rules, r)
		}

		if jsonOutput {
			data, _ := json.MarshalIndent(rules, "", "  ")
			fmt.Println(string(data))
			return nil
		}

		if len(rules) == 0 {
			fmt.Println("No alert rules. Add one: portkeep alert rules add --on rogue --destination telegram")
			return nil
		}

		fmt.Printf("\n%-4s %-15s %-15s %s\n", "ID", "ON", "DESTINATION", "ENABLED")
		for _, r := range rules {
			enabled := "yes"
			if !r.Enabled {
				enabled = "no"
			}
			fmt.Printf("%-4d %-15s %-15s %s\n", r.ID, r.TriggerType, r.Destination, enabled)
		}
		fmt.Println()
		return nil
	},
}

var alertTestCmd = &cobra.Command{
	Use:   "test",
	Short: "Send a test alert to verify configuration",
	RunE: func(cmd *cobra.Command, args []string) error {
		// Find configured destinations
		rows, err := db.Query(`SELECT destination, destination_config FROM alerts WHERE trigger_type = 'config'`)
		if err != nil {
			return err
		}
		defer rows.Close()

		sent := false
		for rows.Next() {
			var destType, configJSON string
			rows.Scan(&destType, &configJSON)

			dest, err := alert.ParseDestinationConfig(destType, configJSON)
			if err != nil {
				fmt.Printf("⚠ Failed to parse %s config: %v\n", destType, err)
				continue
			}

			if err := alert.TestDestination(dest); err != nil {
				fmt.Printf("✗ %s test failed: %v\n", destType, err)
			} else {
				fmt.Printf("✓ %s test alert sent\n", destType)
				sent = true
			}
		}

		if !sent {
			return fmt.Errorf("no alert destinations configured — add one: portkeep alert config add telegram --chat-id <id> --bot-token <token>")
		}
		return nil
	},
}

func init() {
	alertConfigAddCmd.Flags().String("chat-id", "", "Telegram chat ID")
	alertConfigAddCmd.Flags().String("bot-token", "", "Telegram bot token")
	alertConfigAddCmd.Flags().String("url", "", "Webhook URL")
	alertConfigAddCmd.Flags().String("command", "", "Local script command")

	alertRulesAddCmd.Flags().String("on", "", "trigger type: rogue/bind-change/score-change/appear/disappear")
	alertRulesAddCmd.Flags().String("destination", "", "destination name (telegram/webhook/script)")
	alertRulesAddCmd.Flags().Int("threshold", 0, "score threshold (for score-change triggers)")

	alertCmd.AddCommand(alertConfigAddCmd)
	alertCmd.AddCommand(alertRulesAddCmd)
	alertCmd.AddCommand(alertRulesListCmd)
	alertCmd.AddCommand(alertTestCmd)
	rootCmd.AddCommand(alertCmd)
}