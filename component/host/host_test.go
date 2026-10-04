package host

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/viant/authz"
	"github.com/viant/authz/gating"
	_ "modernc.org/sqlite"
)

type testIdentity struct{ facts authz.Facts }

func (p testIdentity) Resolve(context.Context) (authz.Facts, error) { return p.facts, nil }
func (p testIdentity) ResolvePrincipal(context.Context) (gating.Principal, error) {
	return gating.Principal{Facts: p.facts, AccountID: "account-1", IdentityRevision: "identity-1"}, nil
}

type testDirectory func(context.Context, authz.Resource, authz.Facts) (authz.Choices, error)

func (f testDirectory) Choices(ctx context.Context, resource authz.Resource, facts authz.Facts) (authz.Choices, error) {
	return f(ctx, resource, facts)
}

func TestWritableHostSharesPolicyAndGateEditsAcrossInstances(t *testing.T) {
	ctx := context.Background()
	db, err := sql.Open("sqlite", "file:"+filepath.Join(t.TempDir(), "authz.db")+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	resource := authz.Resource{Kind: "window", ID: "orders", Version: "1", Tenant: "tenant"}
	manager := &authz.Rule{Kind: "role", Value: "manager"}
	seed := authz.Document{Resource: resource, Revision: 1, Policies: map[string]authz.Policy{
		"execute":      {Mode: "protected", Rule: manager},
		"viewAccess":   {Mode: "protected", Rule: manager},
		"manageAccess": {Mode: "protected", Rule: manager},
	}}
	binding := gating.Binding{Resource: resource, Action: "execute", Document: gating.RequirementsDocument{Revision: "r1", Requirements: gating.Requirements{SchemaVersion: 1}}}
	identity := testIdentity{authz.Facts{Subject: "alice", Issuer: "issuer", Tenant: "tenant", Roles: []string{"manager"}, Exposures: []string{"FEATURE"}, ValidUntil: time.Now().Add(time.Hour)}}
	config := Config{DB: db, Driver: "sqlite", Identity: identity, Policies: []authz.Document{seed}, Requirements: []gating.Binding{binding}, PolicyReplaceRule: "manage-access",
		Directory: testDirectory(func(_ context.Context, candidate authz.Resource, facts authz.Facts) (authz.Choices, error) {
			if candidate != resource || facts.Subject != "alice" || facts.Tenant != "tenant" {
				t.Fatal("policy directory received an unverified resource or identity")
			}
			return authz.Choices{Roles: []authz.Choice{{ID: "manager", Label: "Manager"}, {ID: "analyst", Label: "Analyst"}}}, nil
		})}
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
	if editor, err := second.Services.Authorization.EditorContextWithStatus(ctx, resource); err != nil || editor.Source != "provider-directory" || len(editor.Choices.Roles) != 2 || editor.Choices.Roles[1].ID != "analyst" {
		t.Fatalf("trusted policy directory context=%+v err=%v", editor, err)
	}
	if decision, err := second.Services.Gates.Evaluate(ctx, gating.Request{RequestID: "first", Resource: resource, Action: "execute"}); err != nil || decision.Effect != "allow" {
		t.Fatalf("seeded gate=%+v err=%v", decision, err)
	}
	changedGate, err := first.Services.Requirements.Replace(ctx, resource, "execute", "r1", gating.Requirements{SchemaVersion: 1, RequiredExposures: []string{"FEATURE"}})
	if err != nil || changedGate.Revision == "r1" {
		t.Fatalf("gate edit=%+v err=%v", changedGate, err)
	}
	if decision, err := second.Services.Gates.Evaluate(ctx, gating.Request{RequestID: "second", Resource: resource, Action: "execute"}); err != nil || decision.Effect != "allow" || decision.RequirementsRevision != changedGate.Revision {
		t.Fatalf("second host missed gate edit=%+v err=%v", decision, err)
	}
	updatedPolicy := seed
	updatedPolicy.Policies = map[string]authz.Policy{
		"execute":      {Mode: "protected", Rule: &authz.Rule{Kind: "role", Value: "reader"}},
		"viewAccess":   seed.Policies["viewAccess"],
		"manageAccess": seed.Policies["manageAccess"],
	}
	storedPolicy, err := first.Services.Policies.Replace(ctx, updatedPolicy)
	if err != nil || storedPolicy.Revision != 2 {
		t.Fatalf("policy edit=%+v err=%v", storedPolicy, err)
	}
	if decision, err := second.Services.Gates.Evaluate(ctx, gating.Request{RequestID: "third", Resource: resource, Action: "execute"}); err != nil || decision.Effect != "deny" || decision.ReasonCode != "policyDenied" {
		t.Fatalf("second host missed policy edit=%+v err=%v", decision, err)
	}
	config.Directory = nil
	config.PolicyChoices = []authz.PolicyChoiceBinding{{Resource: resource, Choices: authz.Choices{Roles: []authz.Choice{{ID: "manager", Label: "Manager"}, {ID: "reviewer", Label: "Reviewer"}}}}}
	third, err := New(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer third.Close(ctx)
	if doc, err := third.PolicyStore.Get(ctx, resource); err != nil || doc.Revision != 2 {
		t.Fatalf("bootstrap overwrote edited policy=%+v err=%v", doc, err)
	}
	if editor, err := third.Services.Authorization.EditorContextWithStatus(ctx, resource); err != nil || editor.Source != "provider-directory" || len(editor.Choices.Roles) != 2 || editor.Choices.Roles[1].ID != "reviewer" {
		t.Fatalf("configured policy choices=%+v err=%v", editor, err)
	}
}
