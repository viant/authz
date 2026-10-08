package schema

import (
	"context"
	"database/sql"
	"testing"

	_ "modernc.org/sqlite"
)

func TestUpCreatesFreshAuthorizationSchema(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	m, err := New("sqlite")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := m.Up(ctx, db); err != nil {
		t.Fatal(err)
	}
	if err := m.Up(ctx, db); err != nil {
		t.Fatalf("fresh schema initializer should be idempotent: %v", err)
	}
	for _, table := range []string{"resource_policies", "resource_policy_revisions", "authz_gate_heads", "authz_gate_revisions"} {
		var count int
		if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?`, table).Scan(&count); err != nil || count != 1 {
			t.Fatalf("fresh authorization table %s exists=%d err=%v", table, count, err)
		}
	}
	for _, table := range []string{"resource_policy_heads", "authz_schema_versions"} {
		var count int
		if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?`, table).Scan(&count); err != nil || count != 0 {
			t.Fatalf("fresh schema created legacy/upgrade table %s count=%d err=%v", table, count, err)
		}
	}
}
