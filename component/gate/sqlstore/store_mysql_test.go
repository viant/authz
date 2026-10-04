package sqlstore

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"testing"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/viant/authz"
	"github.com/viant/authz/component/schema"
	"github.com/viant/authz/gating"
)

func TestSQLStoreMySQLCASAndAudit(t *testing.T) {
	dsn := os.Getenv("AUTHZ_TEST_MYSQL_DSN")
	if dsn == "" {
		t.Skip("AUTHZ_TEST_MYSQL_DSN is unset")
	}
	ctx := context.Background()
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := db.PingContext(ctx); err != nil {
		t.Fatal(err)
	}
	migration, err := schema.New("mysql")
	if err != nil {
		t.Fatal(err)
	}
	if err := migration.Up(ctx, db); err != nil {
		t.Fatal(err)
	}
	resource := authz.Resource{Kind: "window", ID: fmt.Sprintf("orders-%d", time.Now().UnixNano()), Version: "1", Tenant: "tenant"}
	binding := gating.Binding{Resource: resource, Action: "execute", Document: gating.RequirementsDocument{Revision: "r1", Requirements: gating.Requirements{SchemaVersion: 1}}}
	store, err := New(ctx, db, []gating.Binding{binding})
	if err != nil {
		t.Fatal(err)
	}
	updated, err := store.ReplaceRequirementsAs(ctx, resource, "execute", "r1", gating.Requirements{SchemaVersion: 1, AllowedRoles: []string{"reader"}}, "alice")
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := store.GetRequirements(ctx, resource, "execute")
	if err != nil || loaded.Revision != updated.Revision || loaded.Requirements.AllowedRoles[0] != "reader" {
		t.Fatalf("mysql current gate=%+v err=%v", loaded, err)
	}
	var actor string
	if err := db.QueryRowContext(ctx, "SELECT actor_id FROM authz_gate_revisions WHERE binding_key = ? AND revision = ?", bindingKey(resource, "execute"), updated.Revision).Scan(&actor); err != nil || actor != "alice" {
		t.Fatalf("mysql audited actor=%q err=%v", actor, err)
	}
}
