package cmd

import (
	"encoding/json"
	"fmt"

	"github.com/jchandler187/portkeep/internal/firewall"
	"github.com/jchandler187/portkeep/internal/portscanner"
	"github.com/spf13/cobra"
)

var auditCmd = &cobra.Command{
	Use:   "audit",
	Short: "Full security audit — score + risk flags + firewall check",
	Long: `Run a complete security audit of all listening ports.
Produces per-port risk flags, an overall exposure score, and firewall cross-reference.`,
	Example: `  portkeep audit
  portkeep audit --score
  portkeep audit --fix`,
	RunE: func(cmd *cobra.Command, args []string) error {
		scoreOnly, _ := cmd.Flags().GetBool("score")
		showFix, _ := cmd.Flags().GetBool("fix")

		// Scan current ports
		ports, err := portscanner.Scan()
		if err != nil {
			return fmt.Errorf("scan: %w", err)
		}

		// Get claims from DB
		claimRows, _ := db.Query(`SELECT port, protocol, service_name, declared_bind FROM claims WHERE node_name = ?`, nodeFlag)
		type claimInfo struct {
			port     int
			proto    string
			service  string
			declBind string
		}
		claimMap := make(map[string]claimInfo)
		if claimRows != nil {
			defer claimRows.Close()
			for claimRows.Next() {
				var c claimInfo
				claimRows.Scan(&c.port, &c.proto, &c.service, &c.declBind)
				claimMap[fmt.Sprintf("%d/%s", c.port, c.proto)] = c
			}
		}

		// Score each port
		type PortAudit struct {
			Port      int    `json:"port"`
			Protocol  string `json:"protocol"`
			BindAddr  string `json:"bind_addr"`
			Scope     string `json:"scope"`
			Score     int    `json:"score"`
			RiskLevel string `json:"risk_level"`
			Claimed   bool   `json:"claimed"`
			Service   string `json:"service,omitempty"`
			Flags     []string `json:"flags"`
		}

		var audits []PortAudit
		totalScore := 0
		scopeCounts := map[string]int{"loopback": 0, "lan": 0, "tailscale": 0, "wan": 0, "wildcard": 0}
		criticalCount, highCount, warningCount := 0, 0, 0

		for _, p := range ports {
			scope := classifyBind(p.Address)
			scopeCounts[scope]++

			key := fmt.Sprintf("%d/%s", p.Port, p.Protocol)
			claim, claimed := claimMap[key]
			service := p.Process
			if claimed {
				service = claim.service
			}

			var flags []string
			score := 0

			// Bind scope scoring
			switch scope {
			case "loopback":
				score += 0
			case "lan":
				score += 5
				flags = append(flags, "LAN bind")
			case "tailscale":
				score += 10
				flags = append(flags, "Tailscale reachable")
			case "wan":
				score += 15
				flags = append(flags, "WAN reachable")
			case "wildcard":
				score += 25
				flags = append(flags, "wildcard bind (0.0.0.0/::)")
			}

			// Unclaimed penalty
			if !claimed {
				score += 5
				flags = append(flags, "unclaimed")
			}

			// Well-known port danger
			if p.Port < 1024 && scope != "loopback" {
				score += 5
				flags = append(flags, "privileged port exposed")
			}

			// Specific dangerous ports
			dangerPorts := map[int]string{
				22:   "SSH exposed",
				23:   "Telnet (!)",
				3389: "RDP exposed",
				445:  "SMB exposed",
				135:  "DCOM exposed",
			}
			if note, ok := dangerPorts[p.Port]; ok && scope != "loopback" {
				score += 10
				flags = append(flags, note)
			}

			// Risk level
			riskLevel := "info"
			switch {
			case score >= 25:
				riskLevel = "critical"
				criticalCount++
			case score >= 15:
				riskLevel = "high"
				highCount++
			case score >= 5:
				riskLevel = "warning"
				warningCount++
			}

			totalScore += score
			audits = append(audits, PortAudit{
				Port: p.Port, Protocol: p.Protocol, BindAddr: p.Address,
				Scope: scope, Score: score, RiskLevel: riskLevel,
				Claimed: claimed, Service: service, Flags: flags,
			})
		}

		// Normalize score to 0-100
		maxScore := len(ports) * 50 // theoretical max
		exposureScore := 0
		if maxScore > 0 {
			exposureScore = (totalScore * 100) / maxScore
			if exposureScore > 100 {
				exposureScore = 100
			}
		}

		if scoreOnly {
			fmt.Println(exposureScore)
			return nil
		}

		if jsonOutput {
			data, _ := json.MarshalIndent(map[string]interface{}{
				"exposure_score": exposureScore,
				"ports":          audits,
				"scope_counts":   scopeCounts,
				"summary": map[string]int{
					"critical": criticalCount,
					"high":     highCount,
					"warning":  warningCount,
				},
			}, "", "  ")
			fmt.Println(string(data))
			return nil
		}

		// Display
		scoreBar := scoreBar(exposureScore)
		fmt.Printf("\n╔══════════════════════════════════════════════════╗\n")
		fmt.Printf("║  PortKeep — Security Audit  ·  %s        ║\n", nodeFlag)
		fmt.Printf("║  Exposure Score: %d/100  %s  ║\n", exposureScore, scoreBar)
		fmt.Printf("╚══════════════════════════════════════════════════╝\n\n")

		// Scope breakdown
		fmt.Println("BIND SCOPE BREAKDOWN")
		for _, scope := range []string{"loopback", "lan", "tailscale", "wan", "wildcard"} {
			if c, ok := scopeCounts[scope]; ok && c > 0 {
				icon := scopeIcon(scope)
				fmt.Printf("  %s %-12s %d ports\n", icon, scope, c)
			}
		}

		// Critical findings
		if criticalCount > 0 || highCount > 0 {
			fmt.Println("\nCRITICAL FINDINGS")
			for _, a := range audits {
				if a.RiskLevel == "critical" || a.RiskLevel == "high" {
					icon := "🔴"
					if a.RiskLevel == "critical" && a.Scope == "wildcard" {
						icon = "⛔"
					}
					fmt.Printf("  %s port %d (%s) — %s\n", icon, a.Port, a.Service, joinFlags(a.Flags))
					if showFix {
						fmt.Printf("     Fix: bind to 127.0.0.1 or restrict via firewall\n")
					}
				}
			}
		}

		// Firewall check
		fwType := firewall.DetectFirewall()
		if fwType != "none" {
			fmt.Printf("\nFIREWALL (%s)\n", fwType)
			openPortNums := make([]int, len(ports))
			for i, p := range ports {
				openPortNums[i] = p.Port
			}
			statuses, err := firewall.Check(openPortNums)
			if err == nil {
				for _, s := range statuses {
					if !s.HasRule {
						fmt.Printf("  ⚠ port %d — no firewall rule\n", s.Port)
					} else if s.TooOpen {
						fmt.Printf("  ✗ port %d — rule too permissive (from Anywhere)\n", s.Port)
					}
				}
			}
		} else {
			fmt.Println("\n⚠ NO FIREWALL DETECTED")
		}

		fmt.Printf("\nSUMMARY\n")
		fmt.Printf("  %d critical · %d high · %d warnings\n", criticalCount, highCount, warningCount)
		fmt.Printf("  Score: %d/100\n\n", exposureScore)

		return nil
	},
}

func init() {
	auditCmd.Flags().Bool("score", false, "output only the numeric exposure score")
	auditCmd.Flags().Bool("fix", false, "show remediation suggestions for each finding")
	rootCmd.AddCommand(auditCmd)
}

func scoreBar(score int) string {
	filled := score / 5
	bar := ""
	for i := 0; i < 20; i++ {
		if i < filled {
			bar += "█"
		} else {
			bar += "░"
		}
	}

	label := "LOW"
	if score >= 60 {
		label = "CRITICAL"
	} else if score >= 40 {
		label = "HIGH"
	} else if score >= 20 {
		label = "MODERATE"
	}

	return fmt.Sprintf("%s %s", bar, label)
}

func joinFlags(flags []string) string {
	result := ""
	for i, f := range flags {
		if i > 0 {
			result += ", "
		}
		result += f
	}
	return result
}