package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/lowwattlabs/portkeep/internal/alert"
	"github.com/lowwattlabs/portkeep/internal/config"
	"github.com/lowwattlabs/portkeep/internal/portscanner"
	"github.com/spf13/cobra"
)

var daemonCmd = &cobra.Command{
	Use:   "daemon",
	Short: "Run as a background service",
	Example: `  portkeep daemon start
  portkeep daemon install
  portkeep daemon status`,
}

var daemonStartCmd = &cobra.Command{
	Use:   "start",
	Short: "Start the background service",
	RunE: func(cmd *cobra.Command, args []string) error {
		interval, _ := cmd.Flags().GetInt("interval")
		if interval == 0 {
			interval = 300
		}

		if isDaemonRunning() {
			return fmt.Errorf("daemon already running (PID %d)", getDaemonPID())
		}

		pid := os.Getpid()
		pidFile := filepath.Join(config.DefaultDir(), "portkeep.pid")
		if err := os.WriteFile(pidFile, []byte(fmt.Sprintf("%d", pid)), 0600); err != nil {
			return fmt.Errorf("write pid file: %w", err)
		}
		defer os.Remove(pidFile)

		fmt.Printf("PortKeep daemon started (PID %d, interval %ds)\n", pid, interval)

		scanAllNodes()

		ticker := time.NewTicker(time.Duration(interval) * time.Second)
		defer ticker.Stop()

		for range ticker.C {
			scanAllNodes()
			checkAlerts()
		}

		return nil
	},
}

var daemonInstallCmd = &cobra.Command{
	Use:   "install",
	Short: "Install as a systemd user service",
	RunE: func(cmd *cobra.Command, args []string) error {
		serviceFile := `[Unit]
Description=PortKeep — port management + security daemon
After=network.target

[Service]
ExecStart=%s daemon start
Restart=always
RestartSec=30
Environment=PORTKEEP_DB=%s

[Install]
WantedBy=default.target`

		exePath, err := os.Executable()
		if err != nil {
			return fmt.Errorf("find executable: %w", err)
		}
		dbPath := config.DBPath()

		unitPath := filepath.Join(os.Getenv("HOME"), ".config", "systemd", "user", "portkeep.service")
		if err := os.MkdirAll(filepath.Dir(unitPath), 0755); err != nil {
			return fmt.Errorf("create systemd dir: %w", err)
		}

		content := fmt.Sprintf(serviceFile, exePath, dbPath)
		if err := os.WriteFile(unitPath, []byte(content), 0644); err != nil {
			return fmt.Errorf("write service file: %w", err)
		}

		fmt.Printf("✓ systemd unit written to %s\n", unitPath)
		fmt.Printf("  Start: systemctl --user enable --now portkeep\n")
		fmt.Printf("  Logs: journalctl --user -u portkeep -f\n")
		return nil
	},
}

var daemonStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Check daemon status",
	RunE: func(cmd *cobra.Command, args []string) error {
		if !isDaemonRunning() {
			fmt.Println("daemon: not running")
			return nil
		}

		pid := getDaemonPID()
		fmt.Printf("daemon: running (PID %d)\n", pid)

		// Show last scan time
		var lastScan string
		err := db.QueryRow(`SELECT last_scan_at FROM nodes WHERE name = 'localhost'`).Scan(&lastScan)
		if err == nil {
			fmt.Printf("  last scan: %s\n", lastScan)
		}
		return nil
	},
}

var daemonStopCmd = &cobra.Command{
	Use:   "stop",
	Short: "Stop the background service",
	RunE: func(cmd *cobra.Command, args []string) error {
		if !isDaemonRunning() {
			return fmt.Errorf("daemon not running")
		}

		pid := getDaemonPID()
		process, err := os.FindProcess(pid)
		if err != nil {
			return fmt.Errorf("find process: %w", err)
		}

		if err := process.Signal(syscall.SIGTERM); err != nil {
			return fmt.Errorf("signal process: %w", err)
		}

		pidFile := filepath.Join(config.DefaultDir(), "portkeep.pid")
		os.Remove(pidFile)

		fmt.Printf("✓ Daemon stopped (PID %d)\n", pid)
		return nil
	},
}

func init() {
	daemonStartCmd.Flags().Int("interval", 300, "scan interval in seconds")
	daemonCmd.AddCommand(daemonStartCmd)
	daemonCmd.AddCommand(daemonInstallCmd)
	daemonCmd.AddCommand(daemonStatusCmd)
	daemonCmd.AddCommand(daemonStopCmd)
	rootCmd.AddCommand(daemonCmd)
}

func isDaemonRunning() bool {
	pidFile := filepath.Join(config.DefaultDir(), "portkeep.pid")
	data, err := os.ReadFile(pidFile)
	if err != nil {
		return false
	}

	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return false
	}

	process, err := os.FindProcess(pid)
	if err != nil {
		return false
	}

	if err := process.Signal(syscall.Signal(0)); err != nil {
		os.Remove(pidFile)
		return false
	}

	return true
}

func getDaemonPID() int {
	pidFile := filepath.Join(config.DefaultDir(), "portkeep.pid")
	data, _ := os.ReadFile(pidFile)
	pid, _ := strconv.Atoi(strings.TrimSpace(string(data)))
	return pid
}

func scanAllNodes() {
	rows, err := db.Query(`SELECT name, host, ssh_key FROM nodes`)
	if err != nil {
		return
	}
	defer rows.Close()

	for rows.Next() {
		var name, host, sshKey string
		rows.Scan(&name, &host, &sshKey)
		if name == "localhost" {
			ports, err := portscanner.Scan()
			if err == nil {
				upsertPorts(name, ports)
			}
		} else {
			ports, err := remoteScan(host, sshKey)
			if err == nil {
				upsertPorts(name, ports)
			}
		}
	}
}

func upsertPorts(nodeName string, ports []portscanner.OpenPort) {
	now := time.Now().UTC()
	for _, p := range ports {
		scope := classifyBind(p.Address)
		db.Exec(`INSERT INTO ports (node_name, port, protocol, bind_addr, scope, process_name, first_seen, last_seen)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT(node_name, port, protocol, bind_addr) DO UPDATE SET
				scope=excluded.scope, process_name=excluded.process_name, last_seen=excluded.last_seen`,
			nodeName, p.Port, p.Protocol, p.Address, scope, p.Process, now, now)
	}
	db.Exec(`UPDATE nodes SET last_scan_at = ? WHERE name = ?`, now, nodeName)
}

func checkAlerts() {
	rows, err := db.Query(`SELECT node_name, port, protocol FROM ports p
		WHERE NOT EXISTS (SELECT 1 FROM claims c WHERE c.node_name = p.node_name AND c.port = p.port AND c.protocol = p.protocol)`)
	if err != nil {
		return
	}
	defer rows.Close()

	for rows.Next() {
		var node string
		var port int
		var proto string
		rows.Scan(&node, &port, &proto)
		triggerAlert("rogue", node, port, proto, fmt.Sprintf("rogue port %d/%s appeared", port, proto))
	}
}

func triggerAlert(triggerType, node string, port int, proto, detail string) {
	rows, err := db.Query(`SELECT destination, destination_config FROM alerts WHERE trigger_type = ? AND enabled = 1`, triggerType)
	if err != nil {
		return
	}
	defer rows.Close()

	for rows.Next() {
		var destType, configJSON string
		rows.Scan(&destType, &configJSON)

		dest, err := alert.ParseDestinationConfig(destType, configJSON)
		if err != nil {
			continue
		}

		msg := alert.FormatEvent(triggerType, node, port, detail)
		if err := dest.Send(msg); err != nil {
			fmt.Fprintf(os.Stderr, "warn: alert failed (%s): %v\n", destType, err)
		}
	}
}