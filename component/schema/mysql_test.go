package schema

import (
	"context"
	"database/sql"
	"os"
	"strings"
	"testing"

	"github.com/go-sql-driver/mysql"
)

// This opt-in test initializes only a guarded empty local disposable schema.
// It is intentionally a fresh-create test; it never attempts an upgrade.
func TestMySQLCreatePoliciesOnEmptySchema(t *testing.T) {
	rawDSN := strings.TrimSpace(os.Getenv("AUTHZ_POLICY_SCHEMA_MYSQL_DSN"))
	if rawDSN == "" {
		t.Skip("set AUTHZ_POLICY_SCHEMA_MYSQL_DSN to a disposable authz_schema_test database on 127.0.0.1:23309")
	}
	config, err := mysql.ParseDSN(rawDSN)
	if err != nil || config.Net != "tcp" || config.Addr != "127.0.0.1:23309" || !strings.HasPrefix(config.DBName, "authz_schema_test") {
		t.Skip("MySQL schema test requires guarded local disposable endpoint and authz_schema_test database")
	}
	db, err := sql.Open("mysql", config.FormatDSN())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	if err := db.PingContext(ctx); err != nil {
		t.Fatal(err)
	}
	var existingTables int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=DATABASE()`).Scan(&existingTables); err != nil {
		t.Fatal(err)
	}
	if existingTables != 0 {
		t.Skip("guarded MySQL database is not empty; use a fresh authz_schema_test database")
	}
	defer func() {
		_, _ = db.ExecContext(context.Background(), "DROP TABLE IF EXISTS resource_policy_revisions")
		_, _ = db.ExecContext(context.Background(), "DROP TABLE IF EXISTS resource_policies")
	}()
	if err := CreatePolicies(ctx, db, "mysql"); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"resource_policies", "resource_policy_revisions"} {
		for _, item := range []struct {
			name string
			want int
		}{{"tenant_id", 512}, {"resource_kind", 256}, {"resource_id", 800}, {"resource_version", 256}} {
			var dataType string
			var length int
			if err := db.QueryRowContext(ctx, `SELECT data_type,character_maximum_length FROM information_schema.columns WHERE table_schema=DATABASE() AND table_name=? AND column_name=?`, table, item.name).Scan(&dataType, &length); err != nil || dataType != "varbinary" || length != item.want {
				t.Fatalf("fresh MySQL key %s.%s=%s(%d), want varbinary(%d), err=%v", table, item.name, dataType, length, item.want, err)
			}
		}
		var namespaceColumns int
		if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM information_schema.columns WHERE table_schema=DATABASE() AND table_name=? AND column_name='namespace_id'`, table).Scan(&namespaceColumns); err != nil || namespaceColumns != 0 {
			t.Fatalf("Authz policy table %s unexpectedly owns namespace_id: count=%d err=%v", table, namespaceColumns, err)
		}
	}
	insert := `INSERT INTO resource_policies(tenant_id,resource_kind,resource_id,resource_version,revision) VALUES(?,?,?,?,1)`
	for _, key := range [][]any{{"Tenant", "Report", "window://platform/deliver/orders", "V1"}, {"tenant", "Report", "window://platform/deliver/orders", "V1"}, {"Tenant", "Report", "window://platform/deliver/orders ", "V1"}, {"Tenant", "Report", "window://platform/deliver/orders", "v1"}} {
		if _, err := db.ExecContext(ctx, insert, key...); err != nil {
			t.Fatalf("byte-distinct MySQL key %v was rejected: %v", key, err)
		}
	}
	var count int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM resource_policies`).Scan(&count); err != nil || count != 4 {
		t.Fatalf("byte-exact MySQL policy rows=%d err=%v", count, err)
	}
}

func TestFreshMySQLPolicyDDLUsesCompleteByteExactCompositeKeys(t *testing.T) {
	ddl, err := PolicyDDL("mysql")
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range []struct {
		statement string
		count     int
	}{
		{"CREATE TABLE IF NOT EXISTS resource_policies", 1},
		{"CREATE TABLE IF NOT EXISTS resource_policy_revisions", 1},
		{"tenant_id VARBINARY(512) NOT NULL", 2},
		{"resource_kind VARBINARY(256) NOT NULL", 2},
		{"resource_id VARBINARY(800) NOT NULL", 2},
		{"resource_version VARBINARY(256) NOT NULL", 2},
		{"PRIMARY KEY (tenant_id, resource_kind, resource_id, resource_version)", 1},
		{"PRIMARY KEY (tenant_id, resource_kind, resource_id, resource_version, revision)", 1},
	} {
		if actual := strings.Count(ddl, item.statement); actual != item.count {
			t.Fatalf("fresh MySQL DDL %q count=%d want=%d", item.statement, actual, item.count)
		}
	}
	if strings.Contains(ddl, "PRIMARY KEY (tenant_id(") || strings.Contains(ddl, "resource_id(") {
		t.Fatal("fresh MySQL policy schema must not use prefix keys")
	}
	if strings.Contains(ddl, "namespace_id") || strings.Contains(ddl, "authz_schema_versions") || strings.Contains(ddl, "resource_policy_heads") {
		t.Fatal("fresh MySQL Authz policy schema contains consumer ownership or migration metadata")
	}
}
