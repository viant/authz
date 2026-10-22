package authz

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

type namedFixtureStore map[Resource]Document

func (s namedFixtureStore) Get(_ context.Context, r Resource) (Document, error) {
	d, ok := s[r]
	if !ok {
		return Document{}, ErrDenied
	}
	return cloneStaticDocument(d), nil
}
func (s namedFixtureStore) Replace(_ context.Context, d Document, revision int64, _ string) (Document, error) {
	if s[d.Resource].Revision != revision {
		return Document{}, ErrConflict
	}
	d.Revision = revision + 1
	s[d.Resource] = cloneStaticDocument(d)
	return d, nil
}
func namedFixture() (namedFixtureStore, Resource, Document, Facts) {
	r := Resource{Kind: "policy", ID: "viant-users", Version: "logical", Tenant: "tenant"}
	s := namedFixtureStore{r: {Resource: r, Revision: 1, Policies: map[string]Policy{NamedDefinitionAction: {Mode: "definition", Definition: &NamedDefinition{DisplayName: "Viant users", Policies: map[string]Policy{"*": {Mode: "protected", Rule: &Rule{Kind: "group", Value: "Viant internal"}}, "manageAccess": {Mode: "deny"}}}}, "manageAccess": {Mode: "deny"}, "viewAccess": {Mode: "protected", Rule: &Rule{Kind: "subject", Value: "*"}}}}}
	d := Document{Resource: Resource{Kind: "window", ID: "window://example/first", Version: "1", Tenant: "tenant"}, Revision: 1, Policies: map[string]Policy{"*": {Mode: "named", Named: &NamedReference{Resource: r, Revision: 1}}}}
	f := Facts{Subject: "alice", Tenant: "tenant", Issuer: "verified", MembershipGroups: []string{"Viant internal"}, ValidUntil: time.Now().Add(time.Hour)}
	return s, r, d, f
}
func TestNamedPolicyLiveUpdateAffectsTwoAssetsAndKeepsRolesDistinct(t *testing.T) {
	ctx := context.Background()
	s, r, first, facts := namedFixture()
	second := cloneStaticDocument(first)
	second.Resource.ID = "window://example/second"
	check := func(doc Document, f Facts, allowed bool) {
		t.Helper()
		compiled, deps, err := ResolveNamedDocument(ctx, s, doc)
		if err != nil {
			t.Fatal(err)
		}
		if len(deps) != 1 || deps[0].Revision != s[r].Revision {
			t.Fatal("missing exact named head fence")
		}
		_, err = Evaluate(Request{Resource: doc.Resource, Action: "open"}, compiled.Policies, f, time.Now())
		if (err == nil) != allowed {
			t.Fatalf("allowed=%v err=%v", allowed, err)
		}
	}
	for _, doc := range []Document{first, second} {
		check(doc, facts, true)
		nonmember := facts
		nonmember.MembershipGroups = nil
		nonmember.Roles = []string{"Viant internal"}
		check(doc, nonmember, false)
		if _, err := Evaluate(Request{Resource: doc.Resource, Action: "open"}, doc.Policies, facts, time.Now()); !errors.Is(err, ErrDenied) {
			t.Fatal("unresolved named reference executed")
		}
	}
	changed := s[r]
	changed.Policies[NamedDefinitionAction].Definition.Policies["*"] = Policy{Mode: "protected", Rule: &Rule{Kind: "group", Value: "Other membership"}}
	if _, err := s.Replace(ctx, changed, 1, "operator"); err != nil {
		t.Fatal(err)
	}
	for _, doc := range []Document{first, second} {
		check(doc, facts, false)
	}
	if _, err := s.Replace(ctx, changed, 1, "operator"); !errors.Is(err, ErrConflict) {
		t.Fatal("stale revision accepted")
	}
}
func TestNamedWildcardRetainsExactDenyAndLocalRestrictions(t *testing.T) {
	s, _, doc, facts := namedFixture()
	doc.Policies["open"] = Policy{Mode: "named", Named: doc.Policies["*"].Named, Rule: &Rule{Kind: "role", Value: "EDITOR"}, RequiredScopes: []string{"read"}}
	compiled, _, err := ResolveNamedDocument(context.Background(), s, doc)
	if err != nil {
		t.Fatal(err)
	}
	for _, action := range []string{"manageAccess", "open"} {
		if _, err := Evaluate(Request{Resource: doc.Resource, Action: action}, compiled.Policies, facts, time.Now()); !errors.Is(err, ErrDenied) {
			t.Fatalf("%s widened", action)
		}
	}
	facts.Roles = []string{"EDITOR"}
	facts.GrantedScopes = []string{"read"}
	if _, err := Evaluate(Request{Resource: doc.Resource, Action: "open"}, compiled.Policies, facts, time.Now()); err != nil {
		t.Fatal(err)
	}
}
func TestNamedReferenceRejectsDeletionRollbackCyclesAndCrossTenant(t *testing.T) {
	for _, change := range []string{"deleted", "rollback", "cycle", "tenant"} {
		t.Run(change, func(t *testing.T) {
			s, r, doc, _ := namedFixture()
			switch change {
			case "deleted":
				delete(s, r)
			case "rollback":
				ref := *doc.Policies["*"].Named
				ref.Revision = 2
				doc.Policies["*"] = Policy{Mode: "named", Named: &ref}
			case "cycle":
				d := s[r]
				d.Policies[NamedDefinitionAction].Definition.Policies["*"] = doc.Policies["*"]
				s[r] = d
			case "tenant":
				doc.Resource.Tenant = "other"
			}
			if _, _, err := ResolveNamedDocument(context.Background(), s, doc); err == nil {
				t.Fatal("unsafe reference compiled")
			}
		})
	}
}
func TestMembershipWildcardIsLiteral(t *testing.T) {
	s, r, doc, facts := namedFixture()
	d := s[r]
	d.Policies[NamedDefinitionAction].Definition.Policies["*"] = Policy{Mode: "protected", Rule: &Rule{Kind: "group", Value: "*"}}
	s[r] = d
	compiled, _, err := ResolveNamedDocument(context.Background(), s, doc)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Evaluate(Request{Resource: doc.Resource, Action: "open"}, compiled.Policies, facts, time.Now()); !errors.Is(err, ErrDenied) {
		t.Fatal("membership wildcard fabricated")
	}
	facts.MembershipGroups = []string{"*"}
	if _, err := Evaluate(Request{Resource: doc.Resource, Action: "open"}, compiled.Policies, facts, time.Now()); err != nil {
		t.Fatal(err)
	}
}

func TestNamedPolicyLegacyReaderCannotIgnoreReferenceAndAllow(t *testing.T) {
	_, _, doc, _ := namedFixture()
	policy := doc.Policies["*"]
	policy.Rule = &Rule{Kind: "subject", Value: "*"}
	raw, err := json.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	// This is the pre-reference wire shape. Dropping the new field must retain
	// an unknown mode, which all older validators/evaluators deny.
	var legacy struct {
		Mode string `json:"mode"`
		Rule *Rule  `json:"rule"`
	}
	if err = json.Unmarshal(raw, &legacy); err != nil {
		t.Fatal(err)
	}
	if legacy.Mode == "protected" || legacy.Mode == "public" {
		t.Fatalf("legacy reader could allow %s", raw)
	}
	if ValidatePolicy("open", Policy{Mode: legacy.Mode, Rule: legacy.Rule}) == nil {
		t.Fatal("legacy-shaped policy accepted without reference")
	}
}
