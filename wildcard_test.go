package authz

import (
	"context"
	"testing"
	"time"
)

func TestWildcardConditionsPreserveIdentityAndEntityBounds(t *testing.T) {
	now := time.Now()
	base := Facts{Subject: "alice", Tenant: "one", Issuer: "issuer", ValidUntil: now.Add(time.Minute)}
	request := Request{Resource: Resource{Kind: "component", ID: "reader", Tenant: "one"}, Action: "execute"}
	for _, kind := range []string{"subject", "role", "exposure", "entity"} {
		t.Run(kind, func(t *testing.T) {
			facts := base
			rule := Rule{Kind: kind, Value: "*"}
			if kind == "entity" {
				rule.Value = ""
				rule.Entity = &Entity{Type: "customer", ID: "*"}
			}
			policy := Policy{Mode: "protected", Rule: &rule}
			policies := map[string]Policy{"execute": policy}
			if _, err := Evaluate(request, policies, facts, now); (err == nil) != (kind == "subject") {
				t.Fatalf("empty condition: %v", err)
			}
			facts.Roles = []string{"XYZ"}
			facts.Exposures = []string{"EXPOSE_SALES"}
			facts.Entities = []Entity{{Type: "customer", ID: "10"}}
			policy.EntityType = "customer"
			policies["execute"] = policy
			decision, err := Evaluate(request, policies, facts, now)
			if err != nil || !decision.Bounded || len(decision.Entities) != 1 || decision.Entities[0].ID != "10" {
				t.Fatalf("bounded wildcard: %+v %v", decision, err)
			}
			selection := []Entity{{Type: "customer", ID: "20"}}
			denied := request
			denied.Selection = &selection
			if _, err := Evaluate(denied, policies, facts, now); err == nil {
				t.Fatal("wildcard broadened entity bounds")
			}
			for _, mutation := range []func(*Facts){func(f *Facts) { f.Subject = "" }, func(f *Facts) { f.Issuer = "" }, func(f *Facts) { f.Tenant = "other" }, func(f *Facts) { f.ValidUntil = now }} {
				invalid := facts
				mutation(&invalid)
				if _, err := Evaluate(request, policies, invalid, now); err == nil {
					t.Fatal("wildcard bypassed verified identity")
				}
			}
		})
	}
}

func TestWildcardActionsAndExplicitDeny(t *testing.T) {
	now := time.Now()
	facts := Facts{Subject: "alice", Tenant: "one", Issuer: "issuer", Roles: []string{"reader"}, ValidUntil: now.Add(time.Minute)}
	policies := map[string]Policy{"*": {Mode: "protected", Rule: &Rule{Kind: "role", Value: "*"}}, "execute": {Mode: "deny"}, "edit": {Mode: "protected", Rule: &Rule{Kind: "role", Value: "admin"}}}
	for _, action := range []string{"discover", "describe", "retrieve", "execute", "edit", "customAction"} {
		r := Request{Resource: Resource{Kind: "component", ID: "reader", Tenant: "one"}, Action: action}
		_, err := Evaluate(r, policies, facts, now)
		want := action != "execute" && action != "edit"
		if (err == nil) != want {
			t.Fatalf("%s: %v", action, err)
		}
	}
	if err := ValidatePolicy("execute", policies["execute"]); err != nil {
		t.Fatal(err)
	}
	if err := ValidatePolicy("*", policies["*"]); err != nil {
		t.Fatal(err)
	}
	if err := ValidatePolicy("*", Policy{Mode: "public"}); err == nil {
		t.Fatal("public wildcard may not grant management actions")
	}
	if err := ValidatePolicy("execute", Policy{Mode: "deny", Rule: &Rule{Kind: "subject", Value: "*"}}); err == nil {
		t.Fatal("deny must not have a rule")
	}
}

func TestServiceResolvesWildcardAndExactOverride(t *testing.T) {
	resource := Resource{Kind: "component", ID: "reader", Tenant: "one", Version: "1"}
	store := &testStore{doc: Document{Resource: resource, Revision: 1, Policies: map[string]Policy{"*": {Mode: "protected", Rule: &Rule{Kind: "role", Value: "*"}}, "execute": {Mode: "deny"}}}}
	service := Service{Store: store, Provider: testProvider{Facts{Subject: "alice", Issuer: "idp", Tenant: "one", Roles: []string{"reader"}, ValidUntil: time.Now().Add(time.Minute)}}}
	if _, _, _, err := service.AuthorizeWithRevision(context.Background(), Request{Resource: resource, Action: "discover"}); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := service.AuthorizeWithRevision(context.Background(), Request{Resource: resource, Action: "execute"}); err == nil {
		t.Fatal("explicit denial bypassed")
	}
}
