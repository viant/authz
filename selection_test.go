package authz

import (
	"context"
	"errors"
	"testing"
	"time"
)

type selectionProvider struct {
	facts Facts
	err   error
	calls int
}

func (p *selectionProvider) Resolve(context.Context) (Facts, error) { p.calls++; return p.facts, p.err }

func TestSelectorVersionAndPolicy(t *testing.T) {
	family := ResourceFamily{Kind: "mcp", ID: "studio", Tenant: "one"}
	mapping := SelectionDocument{Resource: family, Revision: 3, DefaultVersion: "v1", Overrides: []VersionOverride{
		{Version: "v2", RequiredExposures: []string{"beta"}, Priority: 10},
		{Version: "v3", RequiredExposures: []string{"beta", "canary"}, Priority: 20},
	}}
	mappings, err := NewStaticSelectionStore([]SelectionDocument{mapping})
	if err != nil {
		t.Fatal(err)
	}
	reader := Policy{Mode: "protected", Rule: &Rule{Kind: "role", Value: "reader"}}
	viewer := Policy{Mode: "protected", Rule: &Rule{Kind: "role", Value: "policy-viewer"}}
	var docs []Document
	for i, v := range []string{"v1", "v2", "v3"} {
		docs = append(docs, Document{Resource: Resource{Kind: "mcp", ID: "studio", Tenant: "one", Version: v}, Revision: int64(5 + i), Policies: map[string]Policy{"execute": reader, "discover": reader, "viewAccess": viewer}})
	}
	policies, err := NewStaticStore(docs)
	if err != nil {
		t.Fatal(err)
	}
	provider := &selectionProvider{facts: Facts{Subject: "alice", Issuer: "idp", Tenant: "one", Roles: []string{"reader"}, ValidUntil: time.Now().Add(time.Hour)}}
	selector := Selector{Mappings: mappings, Service: &Service{Store: policies, Provider: provider}}
	for _, tt := range []struct {
		exposures []string
		version   string
		revision  int64
	}{
		{nil, "v1", 5}, {[]string{"beta"}, "v2", 6}, {[]string{"canary"}, "v1", 5}, {[]string{"beta", "canary"}, "v3", 7},
	} {
		provider.facts.Exposures = tt.exposures
		before := provider.calls
		for _, action := range []string{"discover", "execute"} {
			selected, err := selector.Authorize(context.Background(), SelectionRequest{Resource: family, Action: action})
			if err != nil || selected.Resource.Version != tt.version || selected.MappingRevision != 3 || selected.PolicyRevision != tt.revision {
				t.Fatal(selected, err)
			}
		}
		if provider.calls != before+2 {
			t.Fatal("resolved more than once per operation")
		}
	}
	if _, _, err = selector.FindPolicy(context.Background(), family); !errors.Is(err, ErrDenied) {
		t.Fatal("execution granted policy inspection", err)
	}
	provider.facts.Roles = append(provider.facts.Roles, "policy-viewer")
	selected, doc, err := selector.FindPolicy(context.Background(), family)
	if err != nil || doc.Resource != selected.Resource || doc.Revision != selected.PolicyRevision || doc.Resource.Version != "v3" {
		t.Fatal(selected, doc, err)
	}
	provider.facts.Roles = nil
	if _, err = selector.Authorize(context.Background(), SelectionRequest{Resource: family, Action: "execute"}); !errors.Is(err, ErrDenied) {
		t.Fatal("denied override fell back", err)
	}
	provider.err = errors.New("provider offline")
	if _, err = selector.Authorize(context.Background(), SelectionRequest{Resource: family, Action: "execute"}); !errors.Is(err, ErrUnavailable) {
		t.Fatal("provider outage fell back", err)
	}
	provider.err = nil
	provider.facts.Tenant = "two"
	if _, err = selector.Authorize(context.Background(), SelectionRequest{Resource: family, Action: "execute"}); !errors.Is(err, ErrIdentityDenied) {
		t.Fatal("cross-tenant selection", err)
	}
	provider.facts.Tenant = "one"
	provider.facts.ValidUntil = time.Now().Add(-time.Second)
	if _, err = selector.Authorize(context.Background(), SelectionRequest{Resource: family, Action: "execute"}); !errors.Is(err, ErrIdentityDenied) {
		t.Fatal("expired exposures selected version", err)
	}
}

func TestStaticSelectionValidationAndIsolation(t *testing.T) {
	doc := SelectionDocument{Resource: ResourceFamily{Kind: "mcp", ID: "studio", Tenant: "*"}, Revision: 1, DefaultVersion: "1", Overrides: []VersionOverride{{Version: "2", RequiredExposures: []string{"beta"}, Priority: 1}}}
	store, err := NewStaticSelectionStore([]SelectionDocument{doc})
	if err != nil {
		t.Fatal(err)
	}
	doc.Overrides[0].RequiredExposures[0] = "changed"
	copy, err := store.GetSelection(context.Background(), doc.Resource)
	if err != nil || copy.Overrides[0].RequiredExposures[0] != "beta" {
		t.Fatal(copy, err)
	}
	copy.Overrides[0].RequiredExposures[0] = "changed-again"
	copy, _ = store.GetSelection(context.Background(), doc.Resource)
	if copy.Overrides[0].RequiredExposures[0] != "beta" {
		t.Fatal("mutable mapping returned")
	}
	for _, mutate := range []func(*SelectionDocument){
		func(d *SelectionDocument) { d.DefaultVersion = "" },
		func(d *SelectionDocument) { d.Overrides[0].RequiredExposures = nil },
		func(d *SelectionDocument) {
			d.Overrides = append(d.Overrides, VersionOverride{Version: "3", Priority: 1, RequiredExposures: []string{"canary"}})
		},
		func(d *SelectionDocument) { d.Overrides[0].Version = d.DefaultVersion },
	} {
		invalid := cloneSelection(copy)
		mutate(&invalid)
		if _, err = NewStaticSelectionStore([]SelectionDocument{invalid}); err == nil {
			t.Fatal("invalid selection accepted")
		}
	}
	if _, err = NewStaticSelectionStore([]SelectionDocument{copy, copy}); err == nil {
		t.Fatal("duplicate family accepted")
	}
}

func TestSelectorPublicDefaultAndMissingPolicy(t *testing.T) {
	family := ResourceFamily{Kind: "mcp", ID: "public", Tenant: "*"}
	mappings, _ := NewStaticSelectionStore([]SelectionDocument{{Resource: family, Revision: 1, DefaultVersion: "1"}})
	resource := Resource{Kind: family.Kind, ID: family.ID, Tenant: family.Tenant, Version: "1"}
	policies, _ := NewStaticStore([]Document{{Resource: resource, Revision: 1, Policies: map[string]Policy{"discover": {Mode: "public"}}}})
	selector := Selector{Mappings: mappings, Service: &Service{Store: policies}}
	if _, err := selector.Authorize(context.Background(), SelectionRequest{Resource: family, Action: "discover"}); err != nil {
		t.Fatal(err)
	}
	if _, err := selector.Authorize(context.Background(), SelectionRequest{Resource: family, Action: "execute"}); !errors.Is(err, ErrDenied) {
		t.Fatal("mapping implied policy grant", err)
	}
	selector.Service.Store = statusStore{err: errors.New("database offline")}
	if _, err := selector.Authorize(context.Background(), SelectionRequest{Resource: family, Action: "discover"}); !errors.Is(err, ErrUnavailable) {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := selector.Authorize(ctx, SelectionRequest{Resource: family, Action: "discover"}); !errors.Is(err, ErrUnavailable) {
		t.Fatal(err)
	}
}

func TestSelectorPreservesEntityBoundsAndProtectsPolicyRead(t *testing.T) {
	family := ResourceFamily{Kind: "component", ID: "inventory", Tenant: "one"}
	mappings, _ := NewStaticSelectionStore([]SelectionDocument{{Resource: family, Revision: 1, DefaultVersion: "1"}})
	bounded := Policy{Mode: "protected", Rule: &Rule{Kind: "role", Value: "reader"}, EntityType: "advertiser"}
	resource := Resource{Kind: family.Kind, ID: family.ID, Tenant: family.Tenant, Version: "1"}
	policies, _ := NewStaticStore([]Document{{Resource: resource, Revision: 1, Policies: map[string]Policy{"execute": bounded, "viewAccess": bounded}}})
	provider := testProvider{Facts{Subject: "alice", Issuer: "idp", Tenant: "one", Roles: []string{"reader"}, EntityGroups: EntityGroups{"advertiser": {"123", "456"}}, ValidUntil: time.Now().Add(time.Minute)}}
	selector := Selector{Mappings: mappings, Service: &Service{Store: policies, Provider: provider}}
	entities := []Entity{{Type: "advertiser", ID: "123"}}
	selected, err := selector.Authorize(context.Background(), SelectionRequest{Resource: family, Action: "execute", Selection: &entities})
	if err != nil || !selected.Decision.Bounded || len(selected.Decision.Entities) != 1 || selected.Decision.Entities[0].ID != "123" {
		t.Fatal(selected, err)
	}
	entities[0].ID = "789"
	if _, err = selector.Authorize(context.Background(), SelectionRequest{Resource: family, Action: "execute", Selection: &entities}); !errors.Is(err, ErrDenied) {
		t.Fatal("entity bounds widened", err)
	}
	if _, _, err = selector.FindPolicy(context.Background(), family); !errors.Is(err, ErrDenied) {
		t.Fatal("bounded decision exposed whole policy", err)
	}
}
