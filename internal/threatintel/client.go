// Package threatintel provides threat intelligence data for port scoring.
// Full implementation (9 sources) coming in v0.2.
package threatintel

import (
	"fmt"
)

// DB is the aggregated threat intelligence database.
type DB struct {
	LastSync string   `json:"last_sync"`
	C2Ports  []C2Port `json:"c2_ports"`
}

// C2Port is a port known to be used as a command-and-control endpoint.
type C2Port struct {
	Port    int    `json:"port"`
	Source  string `json:"source"`
	Malware string `json:"malware,omitempty"`
}

// EmptyDB returns a zero-value DB for use when no cache exists.
func EmptyDB() *DB {
	return &DB{}
}

// AgeString returns a human-readable description of how old the threat intel is.
func (db *DB) AgeString() string {
	if db.LastSync == "" {
		return "not synced (run portkeep sync)"
	}
	return fmt.Sprintf("synced %s", db.LastSync)
}

// C2Entries returns all C2Port entries matching the given port number.
func (db *DB) C2Entries(port int) []C2Port {
	return nil
}

// SyncAll stubs — full implementation in v0.2.
func SyncAll(cacheDir string, timeoutSec int) error {
	return fmt.Errorf("threat intel sync not yet implemented (v0.2)")
}
