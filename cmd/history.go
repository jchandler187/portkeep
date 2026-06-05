package cmd

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/spf13/cobra"
)

var historyCmd = &cobra.Command{
	Use:   "history",
	Short: "Change timeline — git-log style port history",
	Example: `  portkeep history
  portkeep history --since "2 days ago"
  portkeep history --type appear
  portkeep history --port 3000`,
	RunE: func(cmd *cobra.Command, args []string) error {
		since, _ := cmd.Flags().GetString("since")
		portFilter, _ := cmd.Flags().GetInt("port")
		eventType, _ := cmd.Flags().GetString("type")
		limit, _ := cmd.Flags().GetInt("limit")

		if limit == 0 {
			limit = 50
		}

		sinceTime := parseSince(since)

		q := `SELECT node_name, event_type, port, protocol, detail, timestamp FROM history WHERE timestamp >= ?`
		qArgs := []interface{}{sinceTime}

		if nodeFlag != "" && nodeFlag != "localhost" {
			q += " AND node_name = ?"
			qArgs = append(qArgs, nodeFlag)
		}
		if portFilter > 0 {
			q += " AND port = ?"
			qArgs = append(qArgs, portFilter)
		}
		if eventType != "" {
			q += " AND event_type = ?"
			qArgs = append(qArgs, eventType)
		}
		q += " ORDER BY timestamp DESC LIMIT ?"
		qArgs = append(qArgs, limit)

		rows, err := db.Query(q, qArgs...)
		if err != nil {
			return err
		}
		defer rows.Close()

		type Event struct {
			NodeName  string    `json:"node"`
			EventType string    `json:"type"`
			Port      int       `json:"port"`
			Protocol  string    `json:"protocol"`
			Detail    string    `json:"detail"`
			Timestamp time.Time `json:"timestamp"`
		}

		var events []Event
		for rows.Next() {
			var e Event
			rows.Scan(&e.NodeName, &e.EventType, &e.Port, &e.Protocol, &e.Detail, &e.Timestamp)
			events = append(events, e)
		}

		if jsonOutput {
			data, _ := json.MarshalIndent(events, "", "  ")
			fmt.Println(string(data))
			return nil
		}

		if len(events) == 0 {
			fmt.Println("No history events found.")
			return nil
		}

		for _, e := range events {
			icon := eventIcon(e.EventType)
			fmt.Printf("%s  %s %-4d/%s  %s  on %s\n",
				e.Timestamp.Format("Jan 2 15:04"), icon, e.Port, e.Protocol,
				e.EventType, e.NodeName)
		}

		return nil
	},
}

func init() {
	historyCmd.Flags().String("since", "7 days ago", "show events since (e.g. '2 days ago', '2026-06-01')")
	historyCmd.Flags().Int("port", 0, "filter by port number")
	historyCmd.Flags().String("type", "", "filter by event type (appear/disappear/claim/unclaim/bind-change/rogue)")
	historyCmd.Flags().Int("limit", 50, "max events to show")
	rootCmd.AddCommand(historyCmd)
}

func parseSince(s string) time.Time {
	d, err := time.ParseDuration(s)
	if err == nil {
		return time.Now().Add(-d)
	}

	// Try "N days ago"
	var n int
	fmt.Sscanf(s, "%d days ago", &n)
	if n > 0 {
		return time.Now().AddDate(0, 0, -n)
	}

	// Try date
	t, err := time.Parse("2006-01-02", s)
	if err == nil {
		return t
	}

	// Default: 7 days
	return time.Now().AddDate(0, 0, -7)
}

func eventIcon(eventType string) string {
	switch eventType {
	case "appear":
		return "+port"
	case "disappear":
		return "-port"
	case "claim":
		return "+claim"
	case "unclaim":
		return "-claim"
	case "bind-change":
		return "~bind"
	case "rogue":
		return "!rogue"
	default:
		return "?"
	}
}