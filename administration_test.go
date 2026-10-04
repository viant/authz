package authz

import (
	"context"
	"errors"
	"testing"
	"time"
)

type creationStore struct {
	testStore
	creates int
	actor   string
}

type changingPolicyAdminStore struct {
	first, second Document
	reads, writes int
}

func (s *changingPolicyAdminStore) Get(context.Context, Resource) (Document, error) {
	s.reads++
	if s.reads == 1 {
		return s.first, nil
	}
	return s.second, nil
}
func (s *changingPolicyAdminStore) Replace(context.Context, Document, int64, string) (Document, error) {
	s.writes++
	return s.second, nil
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

func TestPolicyAdministrationSelectsManagedReplacementRule(t *testing.T) {
	ctx := context.Background()
	resource := Resource{Kind: "report", ID: "orders", Version: "1", Tenant: "tenant"}
	store := &creationStore{testStore: testStore{doc: Document{Resource: resource, Revision: 1, Policies: map[string]Policy{
		"viewAccess":   {Mode: "protected", Rule: &Rule{Kind: "role", Value: "reader"}},
		"manageAccess": {Mode: "protected", Rule: &Rule{Kind: "role", Value: "manager"}},
	}}}}
	facts := Facts{Subject: "alice", Issuer: "issuer", Tenant: "tenant", Roles: []string{"reader"}, ValidUntil: time.Now().Add(time.Minute)}
	provider := testProvider{facts}
	management := &Service{Store: store, Provider: provider}
	admin := &Administration{Store: store, Provider: provider, EditorRoles: []string{"reader"}, Management: management}
	if allowed, err := admin.CanReplace(ctx, resource); err != nil || allowed {
		t.Fatalf("editor role bypassed manageAccess: allowed=%v err=%v", allowed, err)
	}
	if _, err := admin.Replace(ctx, store.doc); err != ErrDenied || store.writes != 0 {
		t.Fatalf("editor role wrote without manageAccess: err=%v writes=%d", err, store.writes)
	}
	facts.Roles = []string{"manager"}
	provider = testProvider{facts}
	admin.Provider, management.Provider = provider, provider
	if allowed, err := admin.CanReplace(ctx, resource); err != nil || !allowed {
		t.Fatalf("managed writer rejected: allowed=%v err=%v", allowed, err)
	}
	if _, err := admin.Replace(ctx, store.doc); err != nil || store.writes != 1 {
		t.Fatalf("managed replacement: err=%v writes=%d", err, store.writes)
	}
	management.Provider = testProvider{Facts{Subject: "other", Issuer: "issuer", Tenant: "tenant", Roles: []string{"manager"}, ValidUntil: time.Now().Add(time.Minute)}}
	if allowed, err := admin.CanReplace(ctx, resource); err != nil || allowed {
		t.Fatalf("cross-principal management check: allowed=%v err=%v", allowed, err)
	}
}

func TestManagedReplacementRejectsRevokedPolicyBetweenCheckAndCAS(t *testing.T) {
	resource := Resource{Kind: "report", ID: "orders", Version: "1", Tenant: "tenant"}
	first := Document{Resource: resource, Revision: 1, Policies: map[string]Policy{"manageAccess": {Mode: "protected", Rule: &Rule{Kind: "role", Value: "manager"}}}}
	second := Document{Resource: resource, Revision: 2, Policies: map[string]Policy{"manageAccess": {Mode: "protected", Rule: &Rule{Kind: "role", Value: "other"}}}}
	store := &changingPolicyAdminStore{first: first, second: second}
	provider := testProvider{Facts{Subject: "alice", Issuer: "issuer", Tenant: "tenant", Roles: []string{"manager"}, ValidUntil: time.Now().Add(time.Minute)}}
	admin := &Administration{Store: store, Provider: provider, Management: &Service{Store: store, Provider: provider}}
	if _, err := admin.Replace(context.Background(), second); err != ErrConflict || store.reads != 2 || store.writes != 0 {
		t.Fatalf("revoked management policy authorized write: reads=%d writes=%d err=%v", store.reads, store.writes, err)
	}
}

func TestPolicyAdministrationSeparatesDeniedFromUnavailable(t *testing.T) {
	resource := Resource{Kind: "report", ID: "orders", Version: "1", Tenant: "tenant"}
	doc := Document{Resource: resource, Revision: 1, Policies: map[string]Policy{"viewAccess": {Mode: "protected", Rule: &Rule{Kind: "role", Value: "reader"}}}}
	facts := Facts{Subject: "alice", Issuer: "issuer", Tenant: "tenant", Roles: []string{"editor"}, ValidUntil: time.Now().Add(time.Minute)}
	admin := &Administration{Store: statusStore{doc: doc}, Provider: statusProvider{facts: facts}, EditorRoles: []string{"editor"}}
	admin.Provider = statusProvider{err: errors.New("identity backend down")}
	if _, err := admin.Get(context.Background(), resource); err != ErrUnavailable {
		t.Fatalf("identity outage classified as denial: %v", err)
	}
	admin.Provider = statusProvider{err: ErrDenied}
	if _, err := admin.Get(context.Background(), resource); err != ErrDenied {
		t.Fatalf("identity rejection classified as outage: %v", err)
	}
	admin.Provider = statusProvider{facts: facts}
	admin.Store = statusStore{err: errors.New("policy database down")}
	if _, err := admin.Get(context.Background(), resource); err != ErrUnavailable {
		t.Fatalf("policy read outage classified as denial: %v", err)
	}
	if _, err := admin.Replace(context.Background(), doc); err != ErrUnavailable {
		t.Fatalf("policy write lookup outage classified as denial: %v", err)
	}
}
