// Package config provides paths for PortKeep's local data store.
package config

import (
	"os"
	"path/filepath"
)

// DefaultDir is the base directory for all PortKeep data.
func DefaultDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".portkeep")
}

// DBPath returns the path to the SQLite database.
func DBPath() string {
	if p := os.Getenv("PORTKEEP_DB"); p != "" {
		return p
	}
	return filepath.Join(DefaultDir(), "portkeep.db")
}

// CacheDir returns the directory for threat intel cache.
func CacheDir() string {
	return filepath.Join(DefaultDir(), "cache")
}
