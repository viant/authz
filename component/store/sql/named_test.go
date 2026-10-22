package access

import (
	"context"
	"database/sql"
	"encoding/json"
	"github.com/viant/authz"
	migrate "github.com/viant/authz/component/schema"
	"path/filepath"
	"testing"
)

func TestNamedDefinitionAndAssignmentRoundTripExistingVersionedJSON(t *testing.T) {
	ctx := context.Background()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "named.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	fixture, _ := migrate.New("sqlite")
	if err = fixture.Up(ctx, db); err != nil {
		t.Fatal(err)
	}
	store := &Store{DB: db}
	defer store.Close(ctx)
	resource := authz.Resource{Kind: "policy", ID: "stable-id", Version: "logical", Tenant: "tenant"}
	doc := authz.Document{Resource: resource, Policies: map[string]authz.Policy{authz.NamedDefinitionAction: {Mode: "definition", Definition: &authz.NamedDefinition{DisplayName: "Viant users", Policies: map[string]authz.Policy{"open": {Mode: "protected", Rule: &authz.Rule{Kind: "group", Value: "Viant internal"}}}}}, "manageAccess": {Mode: "protected", Rule: &authz.Rule{Kind: "subject", Value: "operator"}}, "viewAccess": {Mode: "protected", Rule: &authz.Rule{Kind: "subject", Value: "*"}}}}
	saved, err := store.Provision(ctx, doc, "operator")
	if err != nil {
		t.Fatal(err)
	}
	asset := authz.Document{Resource: authz.Resource{Kind: "window", ID: "window://example/one", Version: "1", Tenant: "tenant"}, Policies: map[string]authz.Policy{"open": {Mode: "named", Named: &authz.NamedReference{Resource: resource, Revision: saved.Revision}}}}
	if _, err = store.Provision(ctx, asset, "operator"); err != nil {
		t.Fatal(err)
	}
	roundtrip, err := store.Get(ctx, resource)
	if err != nil {
		t.Fatal(err)
	}
	definition, err := authz.Definition(roundtrip)
	if err != nil || definition.DisplayName != "Viant users" {
		t.Fatalf("definition=%v err=%v", definition, err)
	}
	definition.DisplayName = "Updated users"
	roundtrip.Policies[authz.NamedDefinitionAction] = authz.Policy{Mode: "definition", Definition: &definition}
	if _, err = store.Replace(ctx, roundtrip, 1, "operator"); err != nil {
		t.Fatal(err)
	}
	loaded, err := store.Get(ctx, asset.Resource)
	if err != nil {
		t.Fatal(err)
	}
	compiled, deps, err := authz.ResolveNamedDocument(ctx, store, loaded)
	if err != nil || len(deps) != 1 || deps[0].Revision != 2 || compiled.Policies["open"].Rule.Kind != "group" {
		t.Fatalf("compiled=%v deps=%v err=%v", compiled, deps, err)
	}
	resources, err := store.PolicyResources(ctx, "tenant")
	if err != nil || len(resources) != 2 {
		t.Fatalf("resources=%v err=%v", resources, err)
	}
	var raw []byte
	if err = db.QueryRowContext(ctx, `SELECT policies_json FROM resource_policy_revisions WHERE tenant_id=? AND resource_kind=? AND resource_id=? AND resource_version=? AND revision=2`, "tenant", "policy", "stable-id", "logical").Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var persisted map[string]authz.Policy
	if json.Unmarshal(raw, &persisted) != nil || persisted[authz.NamedDefinitionAction].Definition.DisplayName != "Updated users" {
		t.Fatalf("versioned JSON lost metadata: %s", raw)
	}
}
