// Package sshclient provides key-only SSH access for remote port scanning.
package sshclient

import (
	"bytes"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"
)

// Client wraps an SSH connection for running scan commands on remote nodes.
type Client struct {
	host    string
	port    int
	keyPath string
	client  *ssh.Client
}

// NewClient creates a new SSH client. keyPath can be empty (defaults to ~/.ssh/id_ed25519).
func NewClient(host string, port int, keyPath string) *Client {
	if port == 0 {
		port = 22
	}
	if keyPath == "" {
		usr, _ := user.Current()
		keyPath = filepath.Join(usr.HomeDir, ".ssh", "id_ed25519")
	}
	return &Client{host: host, port: port, keyPath: keyPath}
}

// Connect establishes the SSH connection using key-only auth.
func (c *Client) Connect() error {
	key, err := os.ReadFile(c.keyPath)
	if err != nil {
		// Try RSA as fallback
		usr, _ := user.Current()
		rsaPath := filepath.Join(usr.HomeDir, ".ssh", "id_rsa")
		key, err = os.ReadFile(rsaPath)
		if err != nil {
			return fmt.Errorf("read SSH key %s: %w", c.keyPath, err)
		}
		c.keyPath = rsaPath
	}

	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		return fmt.Errorf("parse SSH key: %w", err)
	}

	config := &ssh.ClientConfig{
		User:            "root",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // TODO: add known_hosts support
		Timeout:         0, // use context for timeout
	}

	// Try common usernames
	for _, user := range []string{"root", os.Getenv("USER")} {
		config.User = user
		addr := fmt.Sprintf("%s:%d", c.host, c.port)
		client, err := ssh.Dial("tcp", addr, config)
		if err == nil {
			c.client = client
			return nil
		}
	}

	return fmt.Errorf("SSH connection to %s:%d failed (tried root and current user)", c.host, c.port)
}

// Close closes the SSH connection.
func (c *Client) Close() error {
	if c.client != nil {
		return c.client.Close()
	}
	return nil
}

// Run executes a command on the remote host and returns stdout.
func (c *Client) Run(cmd string) (string, error) {
	if c.client == nil {
		return "", fmt.Errorf("not connected")
	}

	session, err := c.client.NewSession()
	if err != nil {
		return "", fmt.Errorf("SSH session: %w", err)
	}
	defer session.Close()

	var stdout, stderr bytes.Buffer
	session.Stdout = &stdout
	session.Stderr = &stderr

	if err := session.Run(cmd); err != nil {
		return "", fmt.Errorf("SSH command failed: %w\nstderr: %s", err, stderr.String())
	}

	return stdout.String(), nil
}

// ScanPorts runs `ss -tlnup` on the remote host and returns raw output.
func (c *Client) ScanPorts() (string, error) {
	return c.Run("ss -tlnup 2>/dev/null || netstat -tlnp 2>/dev/null")
}

// Ping checks if the host is reachable via SSH.
func (c *Client) Ping() error {
	if c.client == nil {
		if err := c.Connect(); err != nil {
			return err
		}
	}
	_, err := c.Run("true")
	return err
}

// HealthCheck returns system info from the remote host.
func (c *Client) HealthCheck() (map[string]string, error) {
	commands := map[string]string{
		"load":    "cat /proc/loadavg | awk '{print $1}'",
		"uptime":  "uptime -p 2>/dev/null || cat /proc/uptime",
		"temp":    "sensors 2>/dev/null | grep 'temp1' | head -1 | awk '{print $2}' || echo 'N/A'",
		"memory":  "free -m | awk '/Mem:/{print $3\"/\"$2\" MB\"}'",
		"disk":    "df -h / | tail -1 | awk '{print $5\" used\"}'",
	}

	info := make(map[string]string)
	for key, cmd := range commands {
		out, err := c.Run(cmd)
		if err == nil {
			info[key] = strings.TrimSpace(out)
		} else {
			info[key] = "N/A"
		}
	}
	return info, nil
}