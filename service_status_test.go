package authz

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"
)

type statusStore struct {
	doc Document
	err error
}

type rotatingStatusStore struct {
	calls  int
	first  Document
	second Document
}

func (s *rotatingStatusStore) Get(context.Context, Resource) (Document, error) {
	s.calls++
	if s.calls == 1 {
		return s.first, nil
	}
	return s.second, nil
}
func (s *rotatingStatusStore) Replace(context.Context, Document, int64, string) (Document, error) {
	return Document{}, ErrDenied
}

func (s statusStore) Get(context.Context, Resource) (Document, error) { return s.doc, s.err }
func (s statusStore) Replace(context.Context, Document, int64, string) (Document, error) {
	return Document{}, ErrDenied
}

type statusProvider struct {
	facts Facts
	err   error
}

func (p statusProvider) Resolve(context.Context) (Facts, error) { return p.facts, p.err }

func TestAuthorizeWithStatusSeparatesDenialFromUnavailable(t *testing.T) {
	resource := Resource{Kind: "window", ID: "orders", Version: "1", Tenant: "tenant"}
	doc := Document{Resource: resource, Revision: 3, Policies: map[string]Policy{"execute": {Mode: "protected", Rule: &Rule{Kind: "role", Value: "reader"}}}}
	facts := Facts{Subject: "alice", Issuer: "issuer", Tenant: "tenant", Roles: []string{"reader"}, ValidUntil: time.Now().Add(time.Minute)}
	svc := &Service{Store: statusStore{doc: doc}, Provider: statusProvider{facts: facts}}
	if _, _, revision, err := svc.AuthorizeWithStatus(context.Background(), Request{Resource: resource, Action: "execute"}); err != nil || revision != 3 {
		t.Fatalf("allow revision=%d err=%v", revision, err)
	}
	svc.Store = statusStore{err: errors.New("database unavailable")}
	if _, _, _, err := svc.AuthorizeWithStatus(context.Background(), Request{Resource: resource, Action: "execute"}); err != ErrUnavailable {
		t.Fatalf("store outage=%v", err)
	}
	svc.Store = statusStore{err: sql.ErrNoRows}
	if _, _, _, err := svc.AuthorizeWithStatus(context.Background(), Request{Resource: resource, Action: "execute"}); err != ErrDenied {
		t.Fatalf("missing policy=%v", err)
	}
	svc.Store = statusStore{doc: doc}
	svc.Provider = statusProvider{err: ErrUnavailable}
	if _, _, _, err := svc.AuthorizeWithStatus(context.Background(), Request{Resource: resource, Action: "execute"}); err != ErrUnavailable {
		t.Fatalf("provider outage=%v", err)
	}
	svc.Provider = statusProvider{err: errors.New("network outage")}
	if _, _, _, err := svc.AuthorizeWithStatus(context.Background(), Request{Resource: resource, Action: "execute"}); err != ErrUnavailable {
		t.Fatalf("unknown provider outage=%v", err)
	}
	svc.Provider = statusProvider{err: ErrDenied}
	if _, _, revision, err := svc.AuthorizeWithStatus(context.Background(), Request{Resource: resource, Action: "execute"}); !errors.Is(err, ErrIdentityDenied) || !errors.Is(err, ErrDenied) || revision != 3 {
		t.Fatalf("verified identity rejection revision=%d err=%v", revision, err)
	}
	facts.Roles = []string{"guest"}
	svc.Provider = statusProvider{facts: facts}
	if _, _, revision, err := svc.AuthorizeWithStatus(context.Background(), Request{Resource: resource, Action: "execute"}); err != ErrDenied || revision != 3 {
		t.Fatalf("role denial revision=%d err=%v", revision, err)
	}
	if _, _, revision, err := svc.AuthorizeWithStatus(context.Background(), Request{Resource: resource, Action: "missing"}); err != ErrDenied || revision != 3 {
		t.Fatalf("missing action revision=%d err=%v", revision, err)
	}
}

func TestGetWithStatusReturnsOnlyTheAuthorizedDocumentRevision(t *testing.T) {
	resource := Resource{Kind: "window", ID: "orders", Version: "1", Tenant: "tenant"}
	first := Document{Resource: resource, Revision: 1, Policies: map[string]Policy{"viewAccess": {Mode: "protected", Rule: &Rule{Kind: "role", Value: "reader"}}}}
	second := Document{Resource: resource, Revision: 2, Policies: map[string]Policy{"viewAccess": {Mode: "protected", Rule: &Rule{Kind: "role", Value: "admin"}}}}
	store := &rotatingStatusStore{first: first, second: second}
	svc := &Service{Store: store, Provider: statusProvider{facts: Facts{Subject: "alice", Issuer: "issuer", Tenant: "tenant", Roles: []string{"reader"}, ValidUntil: time.Now().Add(time.Minute)}}}
	got, err := svc.GetWithStatus(context.Background(), resource)
	if err != nil || got.Revision != 1 || store.calls != 1 {
		t.Fatalf("policy read used another revision: doc=%+v calls=%d err=%v", got, store.calls, err)
	}
	store.calls = 1
	if _, err := svc.GetWithStatus(context.Background(), resource); err != ErrDenied || store.calls != 2 {
		t.Fatalf("new denied revision was returned: calls=%d err=%v", store.calls, err)
	}
}
