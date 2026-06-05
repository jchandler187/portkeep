package cmd

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"

	_ "modernc.org/sqlite"
)

// openDB opens the SQLite database with WAL mode.
func openDB(path string) (*sql.DB, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("create db dir: %w", err)
	}

	db, err := sql.Open("sqlite", path+"?_journal_mode=WAL&_busy_timeout=5000")
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}

	if err := migrateDB(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}

	return db, nil
}

func migrateDB(db *sql.DB) error {
	schema := []string{
		`CREATE TABLE IF NOT EXISTS nodes (
			name TEXT PRIMARY KEY,
			host TEXT NOT NULL,
			ssh_key TEXT DEFAULT '',
			labels TEXT DEFAULT '[]',
			last_scan_at DATETIME,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);`,
		`CREATE TABLE IF NOT EXISTS ports (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			node_name TEXT NOT NULL DEFAULT 'localhost' REFERENCES nodes(name),
			port INTEGER NOT NULL,
			protocol TEXT NOT NULL DEFAULT 'tcp',
			bind_addr TEXT NOT NULL,
			scope TEXT NOT NULL DEFAULT 'unknown',
			pid INTEGER DEFAULT 0,
			process_name TEXT DEFAULT '',
			binary_path TEXT DEFAULT '',
			systemd_unit TEXT DEFAULT '',
			docker_container TEXT DEFAULT '',
			first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
			last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
			UNIQUE(node_name, port, protocol, bind_addr)
		);`,
		`CREATE TABLE IF NOT EXISTS claims (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			node_name TEXT NOT NULL DEFAULT 'localhost' REFERENCES nodes(name),
			port INTEGER NOT NULL,
			protocol TEXT NOT NULL DEFAULT 'tcp',
			service_name TEXT NOT NULL,
			declared_bind TEXT DEFAULT '',
			port_range TEXT DEFAULT '',
			owner TEXT DEFAULT '',
			note TEXT DEFAULT '',
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			UNIQUE(node_name, port, protocol)
		);`,
		`CREATE TABLE IF NOT EXISTS history (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			node_name TEXT NOT NULL DEFAULT 'localhost',
			event_type TEXT NOT NULL,
			port INTEGER NOT NULL,
			protocol TEXT NOT NULL DEFAULT 'tcp',
			detail TEXT DEFAULT '{}',
			timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
		);`,
		`CREATE TABLE IF NOT EXISTS alerts (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			trigger_type TEXT NOT NULL,
			destination TEXT NOT NULL,
			destination_config TEXT DEFAULT '{}',
			threshold INTEGER DEFAULT 0,
			enabled INTEGER DEFAULT 1,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);`,
		`CREATE TABLE IF NOT EXISTS snapshots (
			name TEXT PRIMARY KEY,
			node_name TEXT NOT NULL DEFAULT 'localhost',
			data TEXT NOT NULL DEFAULT '{}',
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);`,
		`CREATE INDEX IF NOT EXISTS idx_ports_node ON ports(node_name);`,
		`CREATE INDEX IF NOT EXISTS idx_ports_port ON ports(port);`,
		`CREATE INDEX IF NOT EXISTS idx_claims_node ON claims(node_name);`,
		`CREATE INDEX IF NOT EXISTS idx_history_node ON history(node_name);`,
		`CREATE INDEX IF NOT EXISTS idx_history_ts ON history(timestamp);`,
	}

	for _, stmt := range schema {
		if _, err := db.Exec(stmt); err != nil {
			return fmt.Errorf("exec schema: %w\nstmt: %s", err, stmt)
		}
	}

	// Seed localhost node
	db.Exec(`INSERT OR IGNORE INTO nodes (name, host) VALUES ('localhost', '127.0.0.1')`)

	return nil
}