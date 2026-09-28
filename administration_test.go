package authz

import (
	"context"
	"testing"
	"time"
)

type creationStore struct {
	testStore
	creates int
	actor   string
}

func (s *creationStore) Create(_ context.Context, d Document, actor string) (Document, error) {
	if s.doc.Revision != 0 {
		return Document{}, ErrConflict
	}
	d.Revision = 1
	s.doc = d
	s.creates++
	s.actor = actor
	return d, nil
}
func TestAdministrativeReadsAndConfiguredEditorRoles(t *testing.T) {
	ctx := context.Background()
	resource := Resource{Kind: "api", ID: "records", Tenant: "one", Version: "1"}
	store := &creationStore{testStore: testStore{doc: Document{Resource: resource, Revision: 1, Policies: map[string]Policy{"execute": {Mode: "protected", Rule: &Rule{Kind: "role", Value: "analyst"}}}}}}
	facts := Facts{Subject: "reader", Tenant: "one", Issuer: "trusted", ValidUntil: time.Now().Add(time.Minute)}
	a := &Administration{Store: store, Provider: testProvider{facts}, EditorRoles: []string{"policy_admin"}}
	document, err := a.Get(ctx, resource)
	if err != nil || document.Revision != 1 {
		t.Fatalf("everyone's read: %+v %v", document, err)
	}
	if _, err = (&Service{Store: store, Provider: testProvider{facts}}).Authorize(ctx, Request{Resource: resource, Action: "execute"}); err == nil {
		t.Fatal("reading policy granted protected execution")
	}
	if _, err = a.Replace(ctx, document); err == nil || store.writes != 0 {
		t.Fatal("unlisted role edited policy")
	}
	facts.Roles = []string{"policy_admin"}
	a.Provider = testProvider{facts}
	a.EditorRoles = nil
	if _, err = a.Replace(ctx, document); err == nil {
		t.Fatal("empty predefined role set granted edits")
	}
	a.EditorRoles = []string{"policy_admin"}
	next, err := a.Replace(ctx, document)
	if err != nil || next.Revision != 2 {
		t.Fatalf("editor: %+v %v", next, err)
	}
	if _, err = a.Replace(ctx, document); err != ErrConflict {
		t.Fatal("stale editor overwrote revision")
	}
	other := resource
	other.Tenant = "two"
	if _, err = a.Get(ctx, other); err == nil {
		t.Fatal("policy read crossed tenant boundary")
	}
	facts.ValidUntil = time.Now().Add(-time.Second)
	a.Provider = testProvider{facts}
	if _, err = a.Get(ctx, resource); err == nil {
		t.Fatal("expired reader accepted")
	}
}
func TestOnlyConfiguredRolesCanCreatePolicy(t *testing.T) {
	store := &creationStore{}
	doc := Document{Resource: Resource{Kind: "skill", ID: "guide", Tenant: "one", Version: "1"}, Policies: map[string]Policy{"retrieve": {Mode: "public"}}}
	a := &Administration{Store: store, Provider: testProvider{Facts{Subject: "admin", Tenant: "one", Issuer: "trusted", ValidUntil: time.Now().Add(time.Minute), Roles: []string{"policy_admin"}}}}
	if _, err := a.Create(context.Background(), doc); err == nil || store.creates != 0 {
		t.Fatal("unconfigured creation allowed")
	}
	a.EditorRoles = []string{"policy_admin"}
	created, err := a.Create(context.Background(), doc)
	if err != nil || created.Revision != 1 || store.actor != "admin" {
		t.Fatalf("create: %+v %v", created, err)
	}
	if _, err = a.Create(context.Background(), doc); err != ErrConflict || store.creates != 1 {
		t.Fatal("creation overwrote existing policy")
	}
}
