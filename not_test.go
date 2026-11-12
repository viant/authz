package authz

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func TestNotLimitedRoleUnion(t *testing.T) {
	now := time.Now()
	restricted := Rule{Kind: "any", Rules: []Rule{{Kind: "role", Value: "reviewer"}, {Kind: "role", Value: "reporter"}}}
	ordinary := Rule{Kind: "not", Rules: []Rule{restricted}}
	policy := Policy{Mode: "protected", Rule: &Rule{Kind: "any", Rules: []Rule{ordinary, {Kind: "role", Value: "reviewer"}}}}
	if err := ValidatePolicy("execute", policy); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name    string
		roles   []string
		subject string
		expired bool
		allowed bool
	}{
		{"ordinary", nil, "user", false, true},
		{"reviewer", []string{"reviewer"}, "user", false, true},
		{"reporter", []string{"reporter"}, "user", false, false},
		{"union", []string{"reporter", "reviewer"}, "user", false, true},
		{"admin does not bypass", []string{"reporter", "admin"}, "user", false, false},
		{"anonymous", nil, "", false, false},
		{"expired", nil, "user", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			facts := Facts{Subject: tc.subject, Tenant: "tenant", Issuer: "issuer", Roles: tc.roles, ValidUntil: now.Add(time.Minute)}
			if tc.expired {
				facts.ValidUntil = now
			}
			_, err := Evaluate(Request{Resource: Resource{Kind: "http", ID: "review", Tenant: "tenant"}, Action: "execute"}, map[string]Policy{"execute": policy}, facts, now)
			if (err == nil) != tc.allowed {
				t.Fatalf("allowed=%v error=%v", tc.allowed, err)
			}
			if err != nil && !errors.Is(err, ErrDenied) {
				t.Fatal(err)
			}
		})
	}
	for _, rule := range []Rule{{Kind: "not"}, {Kind: "not", Rules: []Rule{ordinary, ordinary}}, {Kind: "not", Rules: []Rule{{Kind: "unknown"}}}, {Kind: "not", Value: "x", Rules: []Rule{ordinary}}} {
		if err := ValidatePolicy("execute", Policy{Mode: "protected", Rule: &rule}); err == nil {
			t.Fatalf("accepted malformed negation: %+v", rule)
		}
	}
}

func TestNotPositiveAndNegativeDocument(t *testing.T) {
	// Exercise the public document format, including mandatory scope checks.
	var policy Policy
	if err := json.Unmarshal([]byte(`{"mode":"protected","requiredScopes":["write"],"rule":{"kind":"all","rules":[{"kind":"role","value":"editor"},{"kind":"not","rules":[{"kind":"role","value":"suspended"}]}]}}`), &policy); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	type useCase struct {
		description string
		roles       []string
		tenant      string
		scopes      []string
		allowed     bool
	}
	for _, tc := range []useCase{
		{"editor", []string{"editor"}, "tenant", []string{"write"}, true},
		{"both roles", []string{"editor", "suspended"}, "tenant", []string{"write"}, false},
		{"negative alone does not grant", nil, "tenant", []string{"write"}, false},
		{"scope remains mandatory", []string{"editor"}, "tenant", nil, false},
		{"tenant remains mandatory", []string{"editor"}, "other", []string{"write"}, false},
	} {
		t.Run(tc.description, func(t *testing.T) {
			facts := Facts{Subject: "user", Tenant: tc.tenant, Issuer: "issuer", Roles: tc.roles, GrantedScopes: tc.scopes, ValidUntil: now.Add(time.Minute)}
			policies := map[string]Policy{"execute": policy}
			req := Request{Resource: Resource{Kind: "component", ID: "edit", Tenant: "tenant"}, Action: "execute"}
			_, err := EvaluatePrepared(req, policies, PrepareFacts(facts), now)
			if (err == nil) != tc.allowed {
				t.Fatalf("allowed=%v error=%v", tc.allowed, err)
			}
		})
	}
}

func TestNotInvalidTreesFailClosed(t *testing.T) {
	leaf := Rule{Kind: "role", Value: "editor"}
	deep := leaf
	for i := 0; i < 33; i++ {
		deep = Rule{Kind: "not", Rules: []Rule{deep}}
	}
	type useCase struct {
		description string
		rule        Rule
	}
	for _, tc := range []useCase{
		{"no child", Rule{Kind: "not"}},
		{"two children", Rule{Kind: "not", Rules: []Rule{leaf, leaf}}},
		{"value forbidden", Rule{Kind: "not", Value: "editor", Rules: []Rule{leaf}}},
		{"entity forbidden", Rule{Kind: "not", Entity: &Entity{Type: "account", ID: "1"}, Rules: []Rule{leaf}}},
		{"unknown child", Rule{Kind: "not", Rules: []Rule{{Kind: "unknown"}}}},
		{"empty any child", Rule{Kind: "not", Rules: []Rule{{Kind: "any"}}}},
		{"depth limit", deep},
	} {
		t.Run(tc.description, func(t *testing.T) {
			policy := Policy{Mode: "protected", Rule: &tc.rule}
			if err := ValidatePolicy("execute", policy); !errors.Is(err, ErrDenied) {
				t.Fatalf("validation: %v", err)
			}
			if _, err := RuleContentHash(tc.rule); !errors.Is(err, ErrDenied) {
				t.Fatalf("hash: %v", err)
			}
			_, err := Evaluate(Request{Resource: Resource{Kind: "component", ID: "test", Tenant: "tenant"}, Action: "execute"}, map[string]Policy{"execute": policy}, Facts{Subject: "user", Tenant: "tenant", Issuer: "issuer", ValidUntil: time.Now().Add(time.Minute)}, time.Now())
			if !errors.Is(err, ErrDenied) {
				t.Fatalf("evaluation: %v", err)
			}
		})
	}
}

func TestNotNamedPolicyRoundTrip(t *testing.T) {
	store, ref, document, facts := namedFixture()
	definition := store[ref].Policies[NamedDefinitionAction].Definition
	definition.Policies["*"] = Policy{Mode: "protected", Rule: &Rule{Kind: "all", Rules: []Rule{
		{Kind: "group", Value: "Viant internal"},
		{Kind: "not", Rules: []Rule{{Kind: "role", Value: "suspended"}}},
	}}}
	raw, err := json.Marshal(store[ref])
	if err != nil {
		t.Fatal(err)
	}
	var decoded Document
	if err = json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	static, err := NewStaticStore([]Document{decoded})
	if err != nil {
		t.Fatal(err)
	}
	compiled, deps, err := ResolveNamedDocument(context.Background(), static, document)
	if err != nil {
		t.Fatal(err)
	}
	if len(deps) != 1 || deps[0].Revision != decoded.Revision {
		t.Fatal("lost named revision dependency")
	}
	for _, suspended := range []bool{false, true} {
		facts.Roles = nil
		if suspended {
			facts.Roles = []string{"suspended"}
		}
		_, err = Evaluate(Request{Resource: document.Resource, Action: "open"}, compiled.Policies, facts, time.Now())
		if (err == nil) == suspended {
			t.Fatalf("suspended=%v error=%v", suspended, err)
		}
	}
}
