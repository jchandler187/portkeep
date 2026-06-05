// Package scoring computes per-port and aggregate attack surface scores.
// NOTE: The primary scoring logic has moved into cmd/audit.go for the SQLite-based flow.
// This package is preserved for the report command and programmatic API use.
package scoring

import (
	"sort"
	"time"

	"github.com/jchandler187/portkeep/internal/portscanner"
)

// PortScore holds the scored result for a single open port.
type PortScore struct {
	Port        int      `json:"port"`
	Protocol    string   `json:"protocol"`
	Score       int      `json:"score"`
	ThreatLevel string   `json:"threat_level"`
	Registered  bool     `json:"registered"`
	Reasons     []string `json:"reasons"`
}

// SurfaceReport is the top-level output of a full scoring run.
type SurfaceReport struct {
	Timestamp    string      `json:"timestamp"`
	TotalScore  int         `json:"total_score"`
	OpenPorts    int         `json:"open_ports"`
	Unregistered int         `json:"unregistered"`
	Scores       []PortScore `json:"scores"`
}

// Score computes a PortScore for each open port.
func Score(ports []portscanner.OpenPort, registered func(int, string) bool) []PortScore {
	scores := make([]PortScore, 0, len(ports))
	for _, p := range ports {
		ps := PortScore{
			Port:       p.Port,
			Protocol:   p.Protocol,
			Registered: registered(p.Port, p.Protocol),
		}
		if !ps.Registered {
			ps.Score += 15
			ps.Reasons = append(ps.Reasons, "unregistered")
		}
		if ps.Score > 100 {
			ps.Score = 100
		}
		ps.ThreatLevel = ScoreLevel(ps.Score)
		scores = append(scores, ps)
	}
	sort.Slice(scores, func(i, j int) bool {
		return scores[i].Score > scores[j].Score
	})
	return scores
}

// ScoreLevel maps a 0-100 score to a named threat level.
func ScoreLevel(score int) string {
	switch {
	case score >= 90:
		return "critical"
	case score >= 75:
		return "high"
	case score >= 50:
		return "medium"
	case score >= 25:
		return "low"
	default:
		return "info"
	}
}

// BuildReport assembles a SurfaceReport from port scores.
func BuildReport(scores []PortScore) SurfaceReport {
	unreg := 0
	for _, s := range scores {
		if !s.Registered {
			unreg++
		}
	}
	return SurfaceReport{
		Timestamp:    time.Now().UTC().Format(time.RFC3339),
		TotalScore:   0,
		OpenPorts:    len(scores),
		Unregistered: unreg,
		Scores:       scores,
	}
}