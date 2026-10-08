package schema

import (
	"strings"
	"testing"
)

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
