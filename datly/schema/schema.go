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
