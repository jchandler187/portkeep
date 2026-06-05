// Package alert dispatches notifications via Telegram, webhook, email, or local script.
package alert

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"strings"
	"time"
)

// Destination is a configured alert target.
type Destination struct {
	Type     string // telegram, webhook, email, script
	ChatID   string
	BotToken string
	URL      string
	To       string
	Subject  string
	Command  string
}

// Message is the alert payload.
type Message struct {
	Title     string
	Body      string
	Severity  string // info, warning, critical
	Timestamp time.Time
	NodeName  string
	Port      int
	EventType string
}

// Send dispatches the message to the destination.
func (d *Destination) Send(msg Message) error {
	switch d.Type {
	case "telegram":
		return sendTelegram(d, msg)
	case "webhook":
		return sendWebhook(d, msg)
	case "script":
		return sendScript(d, msg)
	default:
		return fmt.Errorf("unknown destination type: %s", d.Type)
	}
}

func sendTelegram(d *Destination, msg Message) error {
	text := fmt.Sprintf("⚠ PortKeep Alert — %s\n\n%s\n\nNode: %s\nPort: %d\nTime: %s",
		msg.EventType, msg.Body, msg.NodeName, msg.Port, msg.Timestamp.Format("2006-01-02 15:04 MST"))

	payload := map[string]string{
		"chat_id": d.ChatID,
		"text":    text,
	}
	data, _ := json.Marshal(payload)

	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", d.BotToken)
	resp, err := http.Post(url, "application/json", bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("telegram POST: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("telegram returned %d", resp.StatusCode)
	}
	return nil
}

func sendWebhook(d *Destination, msg Message) error {
	payload := map[string]interface{}{
		"title":     msg.Title,
		"body":      msg.Body,
		"severity":  msg.Severity,
		"node":      msg.NodeName,
		"port":      msg.Port,
		"event":     msg.EventType,
		"timestamp": msg.Timestamp.Format(time.RFC3339),
	}
	data, _ := json.Marshal(payload)

	resp, err := http.Post(d.URL, "application/json", bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("webhook POST: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned %d", resp.StatusCode)
	}
	return nil
}

func sendScript(d *Destination, msg Message) error {
	args := []string{
		msg.Title,
		msg.Body,
		msg.Severity,
		msg.NodeName,
		fmt.Sprintf("%d", msg.Port),
		msg.EventType,
	}
	cmd := exec.Command("sh", "-c", d.Command)
	cmd.Args = append(cmd.Args, args...)
	return cmd.Run()
}

// FormatEvent formats a PortKeep event into a human-readable alert message.
func FormatEvent(eventType, nodeName string, port int, detail string) Message {
	severity := "info"
	title := eventType

	switch eventType {
	case "rogue":
		severity = "warning"
		title = "Rogue port detected"
	case "bind-change":
		severity = "warning"
		title = "Bind address changed"
	case "score-change":
		severity = "critical"
		title = "Exposure score changed"
	case "appear":
		severity = "info"
		title = "New port appeared"
	case "disappear":
		severity = "info"
		title = "Port disappeared"
	}

	return Message{
		Title:     title,
		Body:      detail,
		Severity:  severity,
		Timestamp: time.Now().UTC(),
		NodeName:  nodeName,
		Port:      port,
		EventType: eventType,
	}
}

// TestDestination sends a test alert to verify configuration.
func TestDestination(d *Destination) error {
	msg := Message{
		Title:     "PortKeep test alert",
		Body:      "If you see this, alerting is working correctly.",
		Severity:  "info",
		Timestamp: time.Now().UTC(),
		NodeName:  "localhost",
		Port:      0,
		EventType: "test",
	}
	return d.Send(msg)
}

// ParseDestinationConfig creates a Destination from a JSON config string.
func ParseDestinationConfig(destType, configJSON string) (*Destination, error) {
	d := &Destination{Type: destType}

	var cfg map[string]string
	if err := json.Unmarshal([]byte(configJSON), &cfg); err != nil {
		// Try simple key=value format
		for _, pair := range strings.Split(configJSON, ",") {
			kv := strings.SplitN(pair, "=", 2)
			if len(kv) == 2 {
				if cfg == nil {
					cfg = make(map[string]string)
				}
				cfg[strings.TrimSpace(kv[0])] = strings.TrimSpace(kv[1])
			}
		}
	}

	if cfg != nil {
		d.ChatID = cfg["chat_id"]
		d.BotToken = cfg["bot_token"]
		d.URL = cfg["url"]
		d.To = cfg["to"]
		d.Command = cfg["command"]
	}

	return d, nil
}