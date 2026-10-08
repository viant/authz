package schema

import (
	"context"
	"database/sql"
	"strings"
	"testing"

	_ "modernc.org/sqlite"
)

func TestCreatePoliciesBuildsEmptySQLiteSchemaWithExactCompositeKeys(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	ctx := context.Background()
	if err := CreatePolicies(ctx, db, "sqlite"); err != nil {
		t.Fatal(err)
	}
	if err := CreatePolicies(ctx, db, "sqlite"); err != nil {
		t.Fatalf("fresh initializer should be idempotent: %v", err)
	}

	for _, table := range []string{"resource_policies", "resource_policy_revisions"} {
		var count int
		if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?`, table).Scan(&count); err != nil || count != 1 {
			t.Fatalf("fresh policy table %s exists=%d err=%v", table, count, err)
		}
	}
	for _, table := range []string{"resource_policy_heads", "authz_schema_versions"} {
		var count int
		if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?`, table).Scan(&count); err != nil || count != 0 {
			t.Fatalf("fresh authz schema must not create legacy/upgrade table %s: count=%d err=%v", table, count, err)
		}
	}

	assertSQLitePrimaryKey(t, db, "resource_policies", []string{"tenant_id", "resource_kind", "resource_id", "resource_version"})
	assertSQLitePrimaryKey(t, db, "resource_policy_revisions", []string{"tenant_id", "resource_kind", "resource_id", "resource_version", "revision"})
	for _, table := range []string{"resource_policies", "resource_policy_revisions"} {
		for _, column := range []string{"created_at", "created_by", "updated_at", "updated_by"} {
			if _, err := PolicyColumnDefinition("sqlite", table, column); err != nil {
				t.Fatalf("canonical audit field %s.%s missing: %v", table, column, err)
			}
		}
	}

	insert := `INSERT INTO resource_policies(tenant_id,resource_kind,resource_id,resource_version,revision) VALUES(?,?,?,?,1)`
	for _, key := range [][]any{
		{"Tenant", "Report", "window://platform/deliver/orders", "V1"},
		{"tenant", "Report", "window://platform/deliver/orders", "V1"},
		{"Tenant", "Report", "window://platform/deliver/orders ", "V1"},
		{"Tenant", "Report", "window://platform/deliver/orders", "v1"},
	} {
		if _, err := db.ExecContext(ctx, insert, key...); err != nil {
			t.Fatalf("exact-distinct text key rejected %v: %v", key, err)
		}
	}
	if _, err := db.ExecContext(ctx, insert, "Tenant", "Report", "window://platform/deliver/orders", "V1"); err == nil {
		t.Fatal("exact duplicate composite policy key was accepted")
	}
	var count int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM resource_policies`).Scan(&count); err != nil || count != 4 {
		t.Fatalf("exact composite key rows=%d err=%v", count, err)
	}
}

func TestPolicyDDLIsCanonicalForFreshSQLiteAndMySQLTables(t *testing.T) {
	for _, driver := range []string{"sqlite", "mysql"} {
		ddl, err := PolicyDDL(driver)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Count(ddl, "CREATE TABLE IF NOT EXISTS") != 2 || strings.Contains(ddl, "namespace_id") || strings.Contains(ddl, "resource_policy_heads") || strings.Contains(ddl, "authz_schema_versions") {
			t.Fatalf("unexpected non-policy or upgrade schema in %s DDL: %s", driver, ddl)
		}
		for _, table := range []string{"resource_policies", "resource_policy_revisions"} {
			for _, column := range []string{"tenant_id", "resource_kind", "resource_id", "resource_version"} {
				if _, err := PolicyColumnDefinition(driver, table, column); err != nil {
					t.Fatalf("canonical key %s.%s missing for %s: %v", table, column, driver, err)
				}
			}
		}
	}
	mysqlDDL, err := PolicyDDL("mysql")
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{
		"tenant_id VARBINARY(512) NOT NULL",
		"resource_kind VARBINARY(256) NOT NULL",
		"resource_id VARBINARY(800) NOT NULL",
		"resource_version VARBINARY(256) NOT NULL",
		"PRIMARY KEY (tenant_id, resource_kind, resource_id, resource_version)",
		"PRIMARY KEY (tenant_id, resource_kind, resource_id, resource_version, revision)",
	} {
		if !strings.Contains(mysqlDDL, expected) {
			t.Fatalf("fresh MySQL policy DDL missing %q", expected)
		}
	}
	if strings.Contains(mysqlDDL, "PRIMARY KEY (tenant_id(") || strings.Contains(mysqlDDL, "resource_id(") {
		t.Fatal("MySQL policy schema must use complete, non-prefix keys")
	}
}

func assertSQLitePrimaryKey(t *testing.T, db *sql.DB, table string, expected []string) {
	t.Helper()
	rows, err := db.Query(`PRAGMA table_info(` + table + `)`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	keys := map[int]string{}
	for rows.Next() {
		var cid, notNull, primary int
		var name, typ string
		var defaultValue any
		if err := rows.Scan(&cid, &name, &typ, &notNull, &defaultValue, &primary); err != nil {
			t.Fatal(err)
		}
		if primary > 0 {
			keys[primary] = name
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	actual := make([]string, len(keys))
	for index := 1; index <= len(keys); index++ {
		actual[index-1] = keys[index]
	}
	if strings.Join(actual, ",") != strings.Join(expected, ",") {
		t.Fatalf("%s primary key=%v want=%v", table, actual, expected)
	}
}
