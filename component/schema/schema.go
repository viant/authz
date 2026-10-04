// Package schema owns the portable durable policy tables.
package schema

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"strings"
)

//go:embed *.sql
var files embed.FS

type Migration struct{ driver string }

func New(driver string) (*Migration, error) {
	switch driver {
	case "sqlite", "sqlite3":
		return &Migration{driver: "sqlite"}, nil
	case "mysql":
		return &Migration{driver: driver}, nil
	}
	return nil, fmt.Errorf("unsupported policy database driver %q", driver)
}

// Up creates missing tables without changing or deleting existing policy data.
func (m *Migration) Up(ctx context.Context, db *sql.DB) error {
	query := "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'resource_policy_heads'"
	if m.driver == "mysql" {
		query = "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = 'resource_policy_heads'"
	}
	var legacyTables int
	if err := db.QueryRowContext(ctx, query).Scan(&legacyTables); err != nil {
		return fmt.Errorf("check legacy policy schema: %w", err)
	}
	if legacyTables != 0 {
		return fmt.Errorf("policy schema migration required: stop writers, back up the database, and run ALTER TABLE resource_policy_heads RENAME TO resource_policies before initialization")
	}
	raw, err := files.ReadFile(m.driver + ".sql")
	if err != nil {
		return err
	}
	for _, statement := range strings.Split(string(raw), ";") {
		if strings.TrimSpace(statement) == "" {
			continue
		}
		if _, err = db.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("initialize policy schema: %w", err)
		}
	}
	return nil
}
