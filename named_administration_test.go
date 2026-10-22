package authz

import (
	"context"
	"errors"
	"testing"
)

func (s namedFixtureStore) Create(_ context.Context, d Document, _ string) (Document, error) {
	if _, ok := s[d.Resource]; ok {
		return Document{}, ErrConflict
	}
	d.Revision = 1
	s[d.Resource] = cloneStaticDocument(d)
	return d, nil
}
func (s namedFixtureStore) PolicyResources(_ context.Context, tenant string) ([]Resource, error) {
	var out []Resource
	for r := range s {
		if r.Tenant == tenant {
			out = append(out, r)
		}
	}
	return out, nil
}

type namedFacts struct{ facts Facts }

func (p namedFacts) Resolve(context.Context) (Facts, error) { return p.facts, nil }
func TestNamedAdministrationCRUDReferencesImpactAndManagementBoundary(t *testing.T) {
	ctx := context.Background()
	store, _, first, facts := namedFixture()
	store[first.Resource] = first
	second := cloneStaticDocument(first)
	second.Resource.ID = "window://example/second"
	store[second.Resource] = second
	facts.Roles = []string{"policy_admin"}
	admin := &Administration{Store: store, Provider: namedFacts{facts}, EditorRoles: []string{"policy_admin"}}
	manager := &NamedAdministration{Policies: admin, Inventory: store}
	created, err := manager.Create(ctx, "stable-policy-id", NamedDefinition{DisplayName: "Viant users", Policies: map[string]Policy{"open": {Mode: "protected", Rule: &Rule{Kind: "group", Value: "Viant internal"}}}})
	if err != nil {
		t.Fatal(err)
	}
	ref := NamedReference{Resource: created.Resource, Revision: created.Revision}
	for _, r := range []Resource{first.Resource, second.Resource} {
		if _, err = manager.Assign(ctx, r, 1, []string{"open"}, ref); err != nil {
			t.Fatal(err)
		}
	}
	impacts, err := manager.Impact(ctx, created.Resource)
	if err != nil || len(impacts) != 2 {
		t.Fatalf("impacts=%v err=%v", impacts, err)
	}
	updated, impacts, err := manager.Update(ctx, ref, NamedDefinition{DisplayName: "Renamed users", Policies: map[string]Policy{"open": {Mode: "protected", Rule: &Rule{Kind: "group", Value: "Different membership"}}}})
	if err != nil || len(impacts) != 2 || updated.Resource != created.Resource || updated.Revision != 2 {
		t.Fatalf("update=%v impacts=%v err=%v", updated, impacts, err)
	}
	if _, _, err = manager.Update(ctx, ref, NamedDefinition{DisplayName: "stale", Policies: updated.Policies}); !errors.Is(err, ErrConflict) {
		t.Fatal("stale named update accepted")
	}
	if _, err = manager.Archive(ctx, NamedReference{Resource: created.Resource, Revision: 2}); !errors.Is(err, ErrDenied) {
		t.Fatal("assigned policy deleted")
	}
	for _, r := range []Resource{first.Resource, second.Resource} {
		compiled, _, err := ResolveNamedDocument(ctx, store, store[r])
		if err != nil {
			t.Fatal(err)
		}
		if _, err = Evaluate(Request{Resource: r, Action: "open"}, compiled.Policies, facts, facts.ValidUntil.Add(-1)); !errors.Is(err, ErrDenied) {
			t.Fatal("assignment copied original rule")
		}
	}
	// Reusable group membership cannot administer the named resource itself.
	outsider := facts
	outsider.Subject = "member"
	outsider.Roles = nil
	checked := &Service{Store: store, Provider: namedFacts{outsider}}
	if _, err = checked.Authorize(ctx, Request{Resource: created.Resource, Action: "manageAccess"}); !errors.Is(err, ErrDenied) {
		t.Fatal("reusable rule granted management")
	}
	list, err := manager.List(ctx)
	if err != nil || len(list) != 2 {
		t.Fatalf("list=%v err=%v", list, err)
	}
}
func TestDefinitionMetadataOnlyAllowedOnPolicyResources(t *testing.T) {
	_, r, _, _ := namedFixture()
	entry := Policy{Mode: "definition", Definition: &NamedDefinition{DisplayName: "users", Policies: map[string]Policy{"open": {Mode: "protected", Rule: &Rule{Kind: "group", Value: "internal"}}}}}
	for _, kind := range []string{"window", "component", "skill"} {
		r.Kind = kind
		if ValidateDocument(Document{Resource: r, Policies: map[string]Policy{NamedDefinitionAction: entry}}) == nil {
			t.Fatal("definition accepted outside policy resource")
		}
	}
	if ValidatePolicy("open", entry) == nil {
		t.Fatal("definition accepted as executable action")
	}
	entry.Definition.Policies["open"] = entry
	if entry.Definition.Validate() == nil {
		t.Fatal("nested definition accepted")
	}
}

func TestNamedAdministrationAssignNamespaceConsumptionPolicy(t *testing.T) {
	ctx := context.Background()
	store, _, first, facts := namedFixture()
	facts.Roles = []string{"policy_admin"}
	asset := first
	asset.Resource = Resource{Kind: "namespace", ID: "supply", Version: "1", Tenant: facts.Tenant}
	asset.Policies = map[string]Policy{"viewAccess": {Mode: "protected", Rule: &Rule{Kind: "subject", Value: facts.Subject}}, "manageAccess": {Mode: "protected", Rule: &Rule{Kind: "subject", Value: facts.Subject}}}
	store[asset.Resource] = asset
	manager := &NamedAdministration{Policies: &Administration{Store: store, Provider: namedFacts{facts}, EditorRoles: []string{"policy_admin"}}, Inventory: store}
	created, err := manager.Create(ctx, "supply", NamedDefinition{DisplayName: "Supply", Policies: map[string]Policy{"*": {Mode: "protected", Rule: &Rule{Kind: "role", Value: "ROLE_STEWARD_SUPER_USER"}}}})
	if err != nil {
		t.Fatal(err)
	}
	ref := NamedReference{Resource: created.Resource, Revision: created.Revision}
	assigned, err := manager.Assign(ctx, asset.Resource, asset.Revision, []string{"discover", "describe", "execute"}, ref)
	if err != nil {
		t.Fatal(err)
	}
	if assigned.Policies["manageAccess"].Named != nil {
		t.Fatal("consumption assignment changed management")
	}
	compiled, _, err := ResolveNamedDocument(ctx, store, assigned)
	if err != nil {
		t.Fatal(err)
	}
	member := facts
	member.Subject = "member"
	member.Roles = []string{"ROLE_STEWARD_SUPER_USER"}
	for _, action := range []string{"discover", "describe", "execute"} {
		if _, err = Evaluate(Request{Resource: asset.Resource, Action: action}, compiled.Policies, member, facts.ValidUntil.Add(-1)); err != nil {
			t.Fatalf("role member %s: %v", action, err)
		}
	}
	if _, err = Evaluate(Request{Resource: asset.Resource, Action: "manageAccess"}, compiled.Policies, member, facts.ValidUntil.Add(-1)); !errors.Is(err, ErrDenied) {
		t.Fatal("role member gained management")
	}
	member.Roles = nil
	if _, err = Evaluate(Request{Resource: asset.Resource, Action: "execute"}, compiled.Policies, member, facts.ValidUntil.Add(-1)); !errors.Is(err, ErrDenied) {
		t.Fatal("nonmember was allowed")
	}
}
