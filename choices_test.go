package authz

import (
	"context"
	"errors"
	"testing"
	"time"
)

type editorDirectoryFunc func(context.Context, Resource, Facts) (Choices, error)

func (f editorDirectoryFunc) Choices(ctx context.Context, resource Resource, facts Facts) (Choices, error) {
	return f(ctx, resource, facts)
}

type changingDirectoryProvider struct{ facts Facts }

func (p *changingDirectoryProvider) Resolve(context.Context) (Facts, error) { return p.facts, nil }

func TestEditorContextRequiresViewAndSeparatesManagement(t *testing.T) {
	r := Resource{Kind: "skill", ID: "one", Tenant: "one", Version: "1"}
	p := Policy{Mode: "protected", Rule: &Rule{Kind: "role", Value: "reader"}}
	s := Service{Store: &testStore{doc: Document{Resource: r, Revision: 1, Policies: map[string]Policy{"viewAccess": p}}}, Provider: testProvider{Facts{Subject: "alice", Tenant: "one", Issuer: "issuer", Roles: []string{"reader"}, Exposures: []string{"analytics"}, Entities: []Entity{{"project", "101"}}, ValidUntil: time.Now().Add(time.Minute)}}}
	result, err := s.EditorContext(context.Background(), r)
	if err != nil || result.CanManage || len(result.Choices.Roles) != 1 || result.Choices.Entities[0].Entity.Type != "project" {
		t.Fatalf("unexpected context %+v %v", result, err)
	}
	r.Tenant = "two"
	if _, err = s.EditorContext(context.Background(), r); err == nil {
		t.Fatal("cross tenant directory disclosure")
	}
}

func TestEditorContextWithStatusRejectsRevisionDriftAndOutage(t *testing.T) {
	resource := Resource{Kind: "skill", ID: "one", Tenant: "tenant", Version: "1"}
	policies := map[string]Policy{
		"viewAccess":   {Mode: "protected", Rule: &Rule{Kind: "role", Value: "reader"}},
		"manageAccess": {Mode: "protected", Rule: &Rule{Kind: "role", Value: "manager"}},
	}
	first := Document{Resource: resource, Revision: 1, Policies: policies}
	second := Document{Resource: resource, Revision: 2, Policies: policies}
	facts := Facts{Subject: "alice", Issuer: "issuer", Tenant: "tenant", Roles: []string{"reader"}, ValidUntil: time.Now().Add(time.Minute)}
	store := &rotatingStatusStore{first: first, second: second}
	svc := &Service{Store: store, Provider: statusProvider{facts: facts}}
	if _, err := svc.EditorContextWithStatus(context.Background(), resource); err != ErrUnavailable {
		t.Fatalf("editor context mixed policy revisions: %v", err)
	}
	svc.Store = statusStore{doc: first}
	editorContext, err := svc.EditorContextWithStatus(context.Background(), resource)
	if err != nil || editorContext.CanManage || len(editorContext.Choices.Roles) != 1 {
		t.Fatalf("explicit manageAccess denial=%+v err=%v", editorContext, err)
	}
	svc.Provider = statusProvider{err: ErrUnavailable}
	if _, err := svc.EditorContextWithStatus(context.Background(), resource); err != ErrUnavailable {
		t.Fatalf("editor identity outage became denial: %v", err)
	}
}

func TestEditorContextWithStatusRejectsPolicyChangeDuringDirectoryLookup(t *testing.T) {
	resource := Resource{Kind: "window", ID: "orders", Version: "1", Tenant: "tenant"}
	manager := Policy{Mode: "protected", Rule: &Rule{Kind: "role", Value: "manager"}}
	store := &testStore{doc: Document{Resource: resource, Revision: 1, Policies: map[string]Policy{"viewAccess": manager, "manageAccess": manager}}}
	facts := Facts{Subject: "alice", Issuer: "issuer", Tenant: "tenant", Roles: []string{"manager"}, ValidUntil: time.Now().Add(time.Minute)}
	service := &Service{Store: store, Provider: testProvider{facts: facts}}
	service.Directory = editorDirectoryFunc(func(context.Context, Resource, Facts) (Choices, error) {
		store.doc.Revision = 2
		return Choices{Roles: []Choice{{ID: "manager", Label: "Manager"}}}, nil
	})
	if _, err := service.EditorContextWithStatus(context.Background(), resource); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("directory returned choices with stale management revision: %v", err)
	}
}

func TestEditorContextWithStatusRejectsFactChangeDuringDirectoryLookup(t *testing.T) {
	resource := Resource{Kind: "window", ID: "orders", Version: "1", Tenant: "tenant"}
	store := &testStore{doc: Document{Resource: resource, Revision: 1, Policies: map[string]Policy{
		"viewAccess":   {Mode: "protected", Rule: &Rule{Kind: "role", Value: "reader"}},
		"manageAccess": {Mode: "protected", Rule: &Rule{Kind: "role", Value: "manager"}},
	}}}
	provider := &changingDirectoryProvider{facts: Facts{Subject: "alice", Issuer: "issuer", Tenant: "tenant", Roles: []string{"reader", "manager"}, ValidUntil: time.Now().Add(time.Minute)}}
	service := &Service{Store: store, Provider: provider}
	service.Directory = editorDirectoryFunc(func(context.Context, Resource, Facts) (Choices, error) {
		provider.facts.Roles = []string{"reader"}
		return Choices{Roles: []Choice{{ID: "reader", Label: "Reader"}}}, nil
	})
	if _, err := service.EditorContextWithStatus(context.Background(), resource); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("directory returned canManage from revoked role facts: %v", err)
	}
}
