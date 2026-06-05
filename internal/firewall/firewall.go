// Package firewall analyzes local firewall rules and cross-references against open ports.
package firewall

import (
	"bufio"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

// Rule represents a single firewall allow rule.
type Rule struct {
	Port      int
	Proto     string
	From      string // source CIDR or "Anywhere"
	Direction string // "in" or "out"
	Raw       string
}

// PortStatus describes the firewall status for a single port.
type PortStatus struct {
	Port        int
	Proto       string
	HasRule     bool
	TooOpen     bool   // rule allows from 0.0.0.0/Anywhere for a non-public service
	Rules       []Rule
	RiskNote   string
}

// CheckUFW parses `ufw status` output and cross-references against the given open ports.
func CheckUFW(openPorts []int) ([]PortStatus, error) {
	rules, err := parseUFWStatus()
	if err != nil {
		return nil, fmt.Errorf("parse UFW: %w", err)
	}
	return matchPorts(openPorts, rules), nil
}

// CheckIPTables parses `iptables -L -n` output.
func CheckIPTables(openPorts []int) ([]PortStatus, error) {
	rules, err := parseIPTables()
	if err != nil {
		return nil, fmt.Errorf("parse iptables: %w", err)
	}
	return matchPorts(openPorts, rules), nil
}

// DetectFirewall returns which firewall is active on this system.
func DetectFirewall() string {
	// Check UFW first
	if path, _ := exec.LookPath("ufw"); path != "" {
		out, err := exec.Command("ufw", "status").Output()
		if err == nil && strings.Contains(string(out), "active") {
			return "ufw"
		}
	}
	// Check iptables
	if path, _ := exec.LookPath("iptables"); path != "" {
		return "iptables"
	}
	// Check nftables
	if path, _ := exec.LookPath("nft"); path != "" {
		return "nftables"
	}
	// Check firewalld
	if path, _ := exec.LookPath("firewall-cmd"); path != "" {
		return "firewalld"
	}
	return "none"
}

// Check auto-detects the firewall and runs the appropriate check.
func Check(openPorts []int) ([]PortStatus, error) {
	fw := DetectFirewall()
	switch fw {
	case "ufw":
		return CheckUFW(openPorts)
	case "iptables":
		return CheckIPTables(openPorts)
	default:
		return nil, fmt.Errorf("no supported firewall detected (found: %s)", fw)
	}
}

func parseUFWStatus() ([]Rule, error) {
	out, err := exec.Command("ufw", "status", "verbose").Output()
	if err != nil {
		return nil, err
	}

	var rules []Rule
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "Status:") || strings.HasPrefix(line, "To") || strings.HasPrefix(line, "--") {
			continue
		}
		// Parse lines like: "22/tcp                     ALLOW IN    Anywhere"
		// Or: "8080/tcp                   ALLOW IN    192.168.1.0/24"
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}

		portProto := fields[0]
		parts := strings.SplitN(portProto, "/", 2)
		port, err := strconv.Atoi(parts[0])
		if err != nil {
			continue
		}
		proto := "tcp"
		if len(parts) > 1 {
			proto = parts[1]
		}

		from := "Anywhere"
		if len(fields) >= 4 {
			from = fields[3]
		}

		rules = append(rules, Rule{
			Port:      port,
			Proto:     proto,
			From:      from,
			Direction: "in",
			Raw:       line,
		})
	}
	return rules, nil
}

var iptablesPortRe = regexp.MustCompile(`dpt:(\d+)`)

func parseIPTables() ([]Rule, error) {
	out, err := exec.Command("iptables", "-L", "-n").Output()
	if err != nil {
		return nil, err
	}

	var rules []Rule
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(line, "ACCEPT") && !strings.HasPrefix(line, "DROP") && !strings.HasPrefix(line, "REJECT") {
			continue
		}

		match := iptablesPortRe.FindStringSubmatch(line)
		if match == nil {
			continue
		}
		port, err := strconv.Atoi(match[1])
		if err != nil {
			continue
		}

		fields := strings.Fields(line)
		proto := "tcp"
		from := "0.0.0.0/0"
		if len(fields) > 3 {
			proto = fields[2]
		}
		if len(fields) > 7 {
			from = fields[7]
		}

		rules = append(rules, Rule{
			Port:      port,
			Proto:     proto,
			From:      from,
			Direction: "in",
			Raw:       line,
		})
	}
	return rules, nil
}

func matchPorts(openPorts []int, rules []Rule) []PortStatus {
	ruleMap := make(map[int][]Rule)
	for _, r := range rules {
		ruleMap[r.Port] = append(ruleMap[r.Port], r)
	}

	var results []PortStatus
	for _, p := range openPorts {
		status := PortStatus{Port: p, Proto: "tcp"}
		if portRules, ok := ruleMap[p]; ok {
			status.HasRule = true
			status.Rules = portRules
			for _, r := range portRules {
				if r.From == "Anywhere" || r.From == "0.0.0.0/0" || r.From == "::/0" {
					status.TooOpen = true
					status.RiskNote = "firewall allows from Anywhere — consider restricting source"
					break
				}
			}
		} else {
			status.HasRule = false
			status.RiskNote = "no firewall rule found for this open port"
		}
		results = append(results, status)
	}
	return results
}