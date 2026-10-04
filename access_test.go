package authz

import (
	"testing"
	"time"
)

func TestResourceKindsAndMandatoryScope(t *testing.T) {
	now := time.Now()
	facts := Facts{Subject: "alice", Tenant: "one", Issuer: "issuer", Roles: []string{"reader"}, Entities: []Entity{{"project", "101"}}, ValidUntil: now.Add(time.Minute)}
	for _, kind := range []string{"report", "skill", "component"} {
		t.Run(kind, func(t *testing.T) {
			policies := map[string]Policy{"retrieve": {Mode: "protected", EntityType: "project", Rule: &Rule{Kind: "any", Rules: []Rule{{Kind: "subject", Value: "alice"}, {Kind: "role", Value: "admin"}}}}}
			req := Request{Resource: Resource{Kind: kind, ID: "one", Tenant: "one"}, Action: "retrieve"}
			d, err := Evaluate(req, policies, facts, now)
			if err != nil || !d.Bounded || len(d.Entities) != 1 {
				t.Fatalf("expected bounded grant: %+v %v", d, err)
			}
			bad := []Entity{{"account", "101"}}
			req.Selection = &bad
			if _, err = Evaluate(req, policies, facts, now); err == nil {
				t.Fatal("OR bypassed entity type")
			}
			empty := []Entity{}
			req.Selection = &empty
			if _, err = Evaluate(req, policies, facts, now); err == nil {
				t.Fatal("empty selection expanded")
			}
			req.Selection = nil
			req.Resource.Tenant = "two"
			if _, err = Evaluate(req, policies, facts, now); err == nil {
				t.Fatal("cross tenant allowed")
			}
			req.Resource.Tenant = "one"
			if _, err = Evaluate(req, policies, facts, now.Add(time.Hour)); err == nil {
				t.Fatal("expired facts allowed")
			}
		})
	}
}

func TestMalformedOrAndPublicManagementDeny(t *testing.T) {
	now := time.Now()
	facts := Facts{Subject: "alice", Tenant: "one", Issuer: "issuer", ValidUntil: now.Add(time.Minute)}
	r := Request{Resource: Resource{Kind: "component", ID: "id", Tenant: "one"}, Action: "edit"}
	for _, p := range []Policy{
		{Mode: "public"},
		{Mode: "protected", Rule: &Rule{Kind: "any", Rules: []Rule{{Kind: "subject", Value: "alice"}, {Kind: "unknown"}}}},
		{Mode: "protected", Rule: &Rule{Kind: "all"}},
	} {
		if _, err := Evaluate(r, map[string]Policy{"edit": p}, facts, now); err == nil {
			t.Fatalf("allowed invalid policy: %+v", p)
		}
	}
}

func TestRequiredOAuthScopesStayOutsideRuleAndEntitySelection(t *testing.T) {
	now := time.Now()
	facts := Facts{Subject: "alice", Tenant: "one", Issuer: "issuer", Roles: []string{"reader"}, GrantedScopes: []string{"plan:read", "reports:read"}, Entities: []Entity{{Type: "project", ID: "101"}}, ValidUntil: now.Add(time.Minute)}
	policy := Policy{Mode: "protected", RequiredScopes: []string{"plan:read"}, EntityType: "project", Rule: &Rule{Kind: "any", Rules: []Rule{{Kind: "subject", Value: "alice"}, {Kind: "role", Value: "admin"}}}}
	req := Request{Resource: Resource{Kind: "component", ID: "plan", Tenant: "one"}, Action: "execute"}
	if decision, err := Evaluate(req, map[string]Policy{"execute": policy}, facts, now); err != nil || !decision.Bounded || len(decision.Entities) != 1 {
		t.Fatalf("scoped grant: %+v %v", decision, err)
	}
	policy.RequiredScopes = []string{"plan:read", "reports:read"}
	if _, err := Evaluate(req, map[string]Policy{"execute": policy}, facts, now); err != nil {
		t.Fatalf("all granted scopes rejected: %v", err)
	}
	policy.RequiredScopes = []string{"plan:read", "reports:write"}
	if _, err := Evaluate(req, map[string]Policy{"execute": policy}, facts, now); err == nil {
		t.Fatal("one matching scope satisfied a two-scope policy")
	}
	policy.RequiredScopes = []string{"plan:read"}
	for _, missing := range [][]string{nil, {"reports:read"}, {"plan:read", "plan:read"}, {" plan:read"}} {
		facts.GrantedScopes = missing
		if _, err := Evaluate(req, map[string]Policy{"execute": policy}, facts, now); err == nil {
			t.Fatalf("scope requirement bypassed by rule: %q", missing)
		}
	}
	facts.GrantedScopes = []string{"plan:read"}
	selection := []Entity{{Type: "project", ID: "102"}}
	req.Selection = &selection
	if _, err := Evaluate(req, map[string]Policy{"execute": policy}, facts, now); err == nil {
		t.Fatal("scope bypassed entity selection")
	}
	for _, bad := range [][]string{{""}, {"plan:read", "plan:read"}, {"plan:read extra"}} {
		policy.RequiredScopes = bad
		if err := ValidatePolicy("execute", policy); err == nil {
			t.Fatalf("malformed required scopes accepted: %q", bad)
		}
	}
	if err := ValidatePolicy("execute", Policy{Mode: "public", RequiredScopes: []string{"plan:read"}}); err == nil {
		t.Fatal("public policy accepted required OAuth scopes")
	}
}
