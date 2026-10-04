package schema

import (
	"context"
	"database/sql"
	"strings"
	"testing"

	_ "modernc.org/sqlite"
)

func TestUpRequiresLegacyTableMigration(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	ctx := context.Background()
	if _, err = db.ExecContext(ctx, "CREATE TABLE resource_policy_heads (id INTEGER PRIMARY KEY); INSERT INTO resource_policy_heads VALUES (42)"); err != nil {
		t.Fatal(err)
	}
	m, err := New("sqlite")
	if err != nil {
		t.Fatal(err)
	}
	if err = m.Up(ctx, db); err == nil || !strings.Contains(err.Error(), "migration required") {
		t.Fatalf("expected migration error, got %v", err)
	}
	var id, tables int
	if err = db.QueryRowContext(ctx, "SELECT id FROM resource_policy_heads").Scan(&id); err != nil || id != 42 {
		t.Fatalf("legacy row changed: id=%d err=%v", id, err)
	}
	if err = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM sqlite_master WHERE type='table'").Scan(&tables); err != nil || tables != 1 {
		t.Fatalf("initializer created tables before migration: tables=%d err=%v", tables, err)
	}
	if _, err = db.ExecContext(ctx, "ALTER TABLE resource_policy_heads RENAME TO resource_policies"); err != nil {
		t.Fatal(err)
	}
	if err = m.Up(ctx, db); err != nil {
		t.Fatal(err)
	}
	if err = db.QueryRowContext(ctx, "SELECT id FROM resource_policies").Scan(&id); err != nil || id != 42 {
		t.Fatalf("renamed row changed: id=%d err=%v", id, err)
	}
}
