package gating

import (
	"context"
	"testing"

	"github.com/viant/authz"
)

func TestStaticStoreUsesExactVersionedBindings(t *testing.T) {
	resource := authz.Resource{Kind: "window", ID: "orders", Version: "v1", Tenant: "tenant"}
	binding := Binding{Resource: resource, Action: "execute", Document: RequirementsDocument{Revision: "r1", Requirements: Requirements{SchemaVersion: 1, RequiredExposures: []string{"FEATURE"}}}}
	store, err := NewStaticStore([]Binding{binding})
	if err != nil {
		t.Fatal(err)
	}
	binding.Document.Requirements.RequiredExposures[0] = "forged"
	doc, err := store.GetRequirements(context.Background(), resource, "execute")
	if err != nil || doc.Requirements.RequiredExposures[0] != "FEATURE" {
		t.Fatalf("binding changed after construction: %+v %v", doc, err)
	}
	doc.Requirements.RequiredExposures[0] = "other"
	doc, _ = store.GetRequirements(context.Background(), resource, "execute")
	if doc.Requirements.RequiredExposures[0] != "FEATURE" {
		t.Fatal("returned requirements alias store")
	}
	other := resource
	other.Version = "v2"
	if _, err := store.GetRequirements(context.Background(), other, "execute"); err != authz.ErrDenied {
		t.Fatalf("version fallback granted: %v", err)
	}
	if _, err := store.GetRequirements(context.Background(), resource, "retrieve"); err != authz.ErrDenied {
		t.Fatalf("action fallback granted: %v", err)
	}
	if _, err := NewStaticStore([]Binding{binding, binding}); err == nil {
		t.Fatal("duplicate binding accepted")
	}
}
