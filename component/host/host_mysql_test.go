package host

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"testing"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/viant/authz"
	"github.com/viant/authz/gating"
)

func TestWritableHostMySQLSharesManagedPolicyAndGate(t *testing.T) {
	dsn := os.Getenv("AUTHZ_TEST_MYSQL_DSN")
	if dsn == "" {
		t.Skip("AUTHZ_TEST_MYSQL_DSN is unset")
	}
	ctx := context.Background()
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.PingContext(ctx); err != nil {
		t.Fatal(err)
	}
	resource := authz.Resource{Kind: "window", ID: fmt.Sprintf("orders-%d", time.Now().UnixNano()), Version: "1", Tenant: "tenant"}
	manager := &authz.Rule{Kind: "role", Value: "manager"}
	seed := authz.Document{Resource: resource, Revision: 1, Policies: map[string]authz.Policy{
		"execute":      {Mode: "protected", Rule: manager},
		"viewAccess":   {Mode: "protected", Rule: manager},
		"manageAccess": {Mode: "protected", Rule: manager},
	}}
	binding := gating.Binding{Resource: resource, Action: "execute", Document: gating.RequirementsDocument{Revision: "r1", Requirements: gating.Requirements{SchemaVersion: 1}}}
	identity := testIdentity{authz.Facts{Subject: "alice", Issuer: "issuer", Tenant: "tenant", Roles: []string{"manager"}, ValidUntil: time.Now().Add(time.Hour)}}
	config := Config{DB: db, Driver: "mysql", Identity: identity, Policies: []authz.Document{seed}, Requirements: []gating.Binding{binding}, PolicyReplaceRule: "manage-access"}
	first, err := New(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close(ctx)
	second, err := New(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close(ctx)
	if decision, err := second.Services.Gates.Evaluate(ctx, gating.Request{RequestID: "before", Resource: resource, Action: "execute"}); err != nil || decision.Effect != "allow" {
		t.Fatalf("mysql seeded authority=%+v %v", decision, err)
	}
	updated := seed
	updated.Policies = map[string]authz.Policy{
		"execute":      {Mode: "protected", Rule: &authz.Rule{Kind: "role", Value: "reader"}},
		"viewAccess":   seed.Policies["viewAccess"],
		"manageAccess": seed.Policies["manageAccess"],
	}
	if result, err := first.Services.Policies.Replace(ctx, updated); err != nil || result.Revision != 2 {
		t.Fatalf("mysql managed policy edit=%+v %v", result, err)
	}
	if decision, err := second.Services.Gates.Evaluate(ctx, gating.Request{RequestID: "after", Resource: resource, Action: "execute"}); err != nil || decision.Effect != "deny" || decision.ReasonCode != "policyDenied" {
		t.Fatalf("mysql second host missed edit=%+v %v", decision, err)
	}
}
