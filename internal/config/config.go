// Package config provides path helpers and environment-based configuration for PortKeep.
package config

import (
	"os"
	"path/filepath"
)

// DefaultDir is the base directory for all PortKeep data (~/.portkeep).
func DefaultDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".portkeep")
}

// DBPath returns the path to the SQLite database.
// Override with the PORTKEEP_DB environment variable.
func DBPath() string {
	if p := os.Getenv("PORTKEEP_DB"); p != "" {
		return p
	}
	return filepath.Join(DefaultDir(), "portkeep.db")
}

// CacheDir returns the directory for threat intel cache files.
func CacheDir() string {
	return filepath.Join(DefaultDir(), "cache")
}

// AbuseChAuthKey returns the abuse.ch Auth-Key for threat intel sources.
// Read from the ABUSE_CH_AUTH_KEY environment variable.
//
// Required for ThreatFox, URLhaus, and MalwareBazaar (mandatory since 2025-06-30).
// The other six threat intel sources (CISA-KEV, EPSS, Feodo, Emerging Threats,
// Blocklist.de, DShield/SANS) work without a key.
//
// Obtain a free key at: https://auth.abuse.ch
func AbuseChAuthKey() string {
	return os.Getenv("ABUSE_CH_AUTH_KEY")
}
