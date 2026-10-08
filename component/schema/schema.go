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

// Up creates the canonical Authz tables on a fresh schema. Its CREATE IF NOT
// EXISTS statements do not transform or import any previous table layout.
func (m *Migration) Up(ctx context.Context, db *sql.DB) error {
	if m == nil || db == nil {
		return fmt.Errorf("authorization schema database is required")
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
			return fmt.Errorf("create authorization schema: %w", err)
		}
	}
	return nil
}
