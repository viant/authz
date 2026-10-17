package authz

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestRevisionPoliciesUsePolicyPriorityAndAllowTies(t *testing.T) {
	family := ResourceFamily{Kind: "report", ID: "synthetic", Tenant: "studio"}
	mapping := SelectionDocument{Resource: family, Revision: 1, Revisions: []RevisionSelection{
		{Version: "1", Policy: Policy{Priority: 50, Mode: "protected", Rule: &Rule{Kind: "role", Value: "diagnostic"}}},
		{Version: "2", Policy: Policy{Priority: 100, Mode: "protected", Rule: &Rule{Kind: "role", Value: "internal"}}},
	}}
	mappings, err := NewStaticSelectionStore([]SelectionDocument{mapping})
	if err != nil {
		t.Fatal(err)
	}
	docs := []Document{}
	for _, version := range []string{"1", "2"} {
		docs = append(docs, Document{Resource: Resource{Kind: family.Kind, ID: family.ID, Tenant: family.Tenant, Version: version}, Revision: 1, Policies: map[string]Policy{"execute": {Mode: "protected", Rule: &Rule{Kind: "role", Value: "*"}}}})
	}
	policies, err := NewStaticStore(docs)
	if err != nil {
		t.Fatal(err)
	}
	provider := &selectionProvider{facts: Facts{Subject: "user", Tenant: "studio", Issuer: "synthetic-idp", ValidUntil: time.Now().Add(time.Hour)}}
	selector := Selector{Mappings: mappings, Service: &Service{Store: policies, Provider: provider}}
	for _, test := range []struct {
		roles   []string
		version string
	}{
		{[]string{"diagnostic"}, "1"}, {[]string{"internal"}, "2"}, {[]string{"diagnostic", "internal"}, "2"}, {[]string{"internal", "diagnostic"}, "2"},
	} {
		provider.facts.Roles = test.roles
		before := provider.calls
		selected, err := selector.Authorize(context.Background(), SelectionRequest{Resource: family, Action: "execute"})
		if err != nil || selected.Resource.Version != test.version {
			t.Fatalf("roles=%v selected=%+v err=%v", test.roles, selected, err)
		}
		if provider.calls != before+1 {
			t.Fatal("identity resolved more than once")
		}
	}
	provider.facts.Roles = []string{"unrelated"}
	if _, err := selector.Authorize(context.Background(), SelectionRequest{Resource: family, Action: "execute"}); !errors.Is(err, ErrDenied) {
		t.Fatal("unmatched revision policy granted access")
	}
	mapping.Revisions[1].Policy.Priority = 50
	ties, err := NewStaticSelectionStore([]SelectionDocument{mapping})
	if err != nil {
		t.Fatalf("equal priorities rejected: %v", err)
	}
	selector.Mappings = ties
	provider.facts.Roles = []string{"diagnostic", "internal"}
	selected, err := selector.Authorize(context.Background(), SelectionRequest{Resource: family, Action: "execute"})
	if err != nil || (selected.Resource.Version != "1" && selected.Resource.Version != "2") {
		t.Fatalf("tie selection: %+v %v", selected, err)
	}
	// An accepted mapping is detached from caller mutations.
	mapping.Revisions[0].Policy.Rule.Value = "tampered"
	selected, err = selector.Authorize(context.Background(), SelectionRequest{Resource: family, Action: "execute"})
	if err != nil {
		t.Fatal("caller mutated compiled policies", err)
	}
}

func TestRevisionPolicyDoesNotFallbackAfterSelectedResourceDenial(t *testing.T) {
	family := ResourceFamily{Kind: "report", ID: "synthetic", Tenant: "studio"}
	selection, _ := NewStaticSelectionStore([]SelectionDocument{{Resource: family, Revision: 1, Revisions: []RevisionSelection{
		{Version: "2", Policy: Policy{Priority: 100, Mode: "protected", Rule: &Rule{Kind: "role", Value: "internal"}}},
		{Version: "1", Policy: Policy{Priority: 50, Mode: "protected", Rule: &Rule{Kind: "role", Value: "diagnostic"}}},
	}}})
	policies, _ := NewStaticStore([]Document{
		{Resource: Resource{Kind: family.Kind, ID: family.ID, Tenant: family.Tenant, Version: "2"}, Revision: 1, Policies: map[string]Policy{"execute": {Mode: "protected", Rule: &Rule{Kind: "role", Value: "ungranted"}}}},
		{Resource: Resource{Kind: family.Kind, ID: family.ID, Tenant: family.Tenant, Version: "1"}, Revision: 1, Policies: map[string]Policy{"execute": {Mode: "protected", Rule: &Rule{Kind: "role", Value: "diagnostic"}}}},
	})
	provider := &selectionProvider{facts: Facts{Subject: "user", Tenant: "studio", Issuer: "synthetic", Roles: []string{"internal", "diagnostic"}, ValidUntil: time.Now().Add(time.Hour)}}
	selector := Selector{Mappings: selection, Service: &Service{Store: policies, Provider: provider}}
	if _, err := selector.Authorize(context.Background(), SelectionRequest{Resource: family, Action: "execute"}); !errors.Is(err, ErrDenied) {
		t.Fatalf("selected resource denial fell through: %v", err)
	}
}
