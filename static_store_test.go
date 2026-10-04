package authz

import (
	"context"
	"testing"
)

func TestStaticPolicyStoreRequiresExactVersionAndCopiesRules(t *testing.T) {
	resource := Resource{Kind: "window", ID: "orders", Version: "1", Tenant: "tenant"}
	doc := Document{Resource: resource, Revision: 1, Policies: map[string]Policy{"execute": {Mode: "protected", Rule: &Rule{Kind: "all", Rules: []Rule{{Kind: "role", Value: "reader"}, {Kind: "exposure", Value: "FEATURE"}}}}}}
	store, err := NewStaticStore([]Document{doc})
	if err != nil {
		t.Fatal(err)
	}
	doc.Policies["execute"].Rule.Rules[0].Value = "forged"
	loaded, err := store.Get(context.Background(), resource)
	if err != nil || loaded.Policies["execute"].Rule.Rules[0].Value != "reader" {
		t.Fatalf("source mutation changed policy: %+v %v", loaded, err)
	}
	loaded.Policies["execute"].Rule.Rules[0].Value = "other"
	loaded, _ = store.Get(context.Background(), resource)
	if loaded.Policies["execute"].Rule.Rules[0].Value != "reader" {
		t.Fatal("returned policy aliases store")
	}
	other := resource
	other.Version = "2"
	if _, err := store.Get(context.Background(), other); err != ErrDenied {
		t.Fatalf("version fallback: %v", err)
	}
	if _, err := store.Replace(context.Background(), doc, 1, "actor"); err != ErrDenied {
		t.Fatalf("static policy was editable: %v", err)
	}
	if _, err := NewStaticStore([]Document{doc, doc}); err == nil {
		t.Fatal("duplicate policy document accepted")
	}
}
