package authz

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"
)

type selectedAuthority struct {
	decision SelectedScopeDecision
	err      error
	calls    int
}

func (p *selectedAuthority) ResolveSelectedScope(_ context.Context, r Request, _ Document, f Facts) (SelectedScopeDecision, error) {
	p.calls++
	return p.decision, p.err
}
func TestSelectedScopeDoesNotSynthesizeGlobalFacts(t *testing.T) {
	resource := Resource{Kind: "dataSource", ID: "orders", Tenant: "one"}
	selection := []Entity{{Type: "advertiser", ID: "101"}, {Type: "advertiser", ID: "102"}}
	facts := Facts{Subject: "alice", Issuer: "issuer", Tenant: "one", Roles: []string{"reader"}, EntityGroups: EntityGroups{}, ValidUntil: time.Now().Add(time.Hour)}
	provider := &selectedAuthority{decision: SelectedScopeDecision{Entities: selection, ValidUntil: time.Now().Add(time.Minute)}}
	store := &testStore{doc: Document{Resource: resource, Revision: 3, Policies: map[string]Policy{"execute": {Mode: "protected", Rule: &Rule{Kind: "role", Value: "reader"}, EntityType: "advertiser"}}}}
	service := &Service{Store: store, Provider: testProvider{facts}, SelectedScopes: provider}
	got, used, revision, err := service.AuthorizeSelectionWithStatus(context.Background(), Request{Resource: resource, Action: "execute"}, selection)
	if err != nil || !got.Bounded || !reflect.DeepEqual(got.Entities, selection) || revision != 3 || !reflect.DeepEqual(used.EntityGroups, facts.EntityGroups) || len(used.Entities) != 0 || !used.ValidUntil.Equal(provider.decision.ValidUntil) {
		t.Fatalf("%+v %+v %d %v", got, used, revision, err)
	}
	// Ordinary whole-resource calls cannot turn provider selections into grants.
	if _, _, _, err = service.AuthorizeWithStatus(context.Background(), Request{Resource: resource, Action: "execute"}); !errors.Is(err, ErrDenied) {
		t.Fatal("whole-resource scope broadened")
	}
	if provider.calls != 1 {
		t.Fatal("provider called for an unselected operation")
	}
	// Original ACL is evaluated first, including entity leaves absent from Facts.
	for _, rule := range []*Rule{{Kind: "role", Value: "writer"}, {Kind: "entity", Entity: &Entity{Type: "advertiser", ID: "101"}}} {
		p := store.doc.Policies["execute"]
		p.Rule = rule
		store.doc.Policies["execute"] = p
		if _, _, _, err = service.AuthorizeSelectionWithStatus(context.Background(), Request{Resource: resource, Action: "execute"}, selection); !errors.Is(err, ErrDenied) {
			t.Fatal("remote selection satisfied original ACL")
		}
	}
	if provider.calls != 1 {
		t.Fatal("provider called before ACL admission")
	}
}
func TestSelectedScopeRejectsMalformedAndExpiredAuthority(t *testing.T) {
	resource := Resource{Kind: "report", ID: "r", Tenant: "one"}
	selection := []Entity{{Type: "advertiser", ID: "1"}}
	facts := Facts{Subject: "alice", Issuer: "issuer", Tenant: "one", Roles: []string{"reader"}, ValidUntil: time.Now().Add(time.Hour)}
	policy := Policy{Mode: "protected", Rule: &Rule{Kind: "role", Value: "reader"}, EntityType: "advertiser"}
	for _, tc := range []struct {
		name      string
		selection []Entity
		checked   []Entity
		expiry    time.Time
		err       error
		want      error
	}{
		{name: "missing selection", expiry: time.Now().Add(time.Minute), want: ErrSelectionRequired},
		{name: "wrong type", selection: []Entity{{Type: "agency", ID: "1"}}, expiry: time.Now().Add(time.Minute), want: ErrDenied},
		{name: "duplicate input", selection: []Entity{selection[0], selection[0]}, expiry: time.Now().Add(time.Minute), want: ErrDenied},
		{name: "subset", selection: selection, expiry: time.Now().Add(time.Minute), want: ErrDenied},
		{name: "other ID", selection: selection, checked: []Entity{{Type: "advertiser", ID: "2"}}, expiry: time.Now().Add(time.Minute), want: ErrDenied},
		{name: "expired", selection: selection, checked: selection, expiry: time.Now().Add(-time.Second), want: ErrDenied},
		{name: "outage", selection: selection, err: errors.New("network unavailable"), want: ErrUnavailable},
		{name: "identity rejected", selection: selection, err: ErrIdentityDenied, want: ErrIdentityDenied},
	} {
		t.Run(tc.name, func(t *testing.T) {
			provider := &selectedAuthority{decision: SelectedScopeDecision{Entities: tc.checked, ValidUntil: tc.expiry}, err: tc.err}
			s := &Service{Store: &testStore{doc: Document{Resource: resource, Revision: 1, Policies: map[string]Policy{"execute": policy}}}, Provider: testProvider{facts}, SelectedScopes: provider}
			_, _, _, err := s.AuthorizeSelectionWithStatus(context.Background(), Request{Resource: resource, Action: "execute"}, tc.selection)
			if !errors.Is(err, tc.want) {
				t.Fatalf("error=%v want %v", err, tc.want)
			}
		})
	}
}
func TestSelectedScopeUnboundedPoliciesIgnoreSelections(t *testing.T) {
	resource := Resource{Kind: "report", ID: "r", Tenant: "one"}
	facts := Facts{Subject: "alice", Issuer: "issuer", Tenant: "one", Roles: []string{"reader"}, ValidUntil: time.Now().Add(time.Hour)}
	provider := &selectedAuthority{}
	s := &Service{Store: &testStore{doc: Document{Resource: resource, Revision: 1, Policies: map[string]Policy{"execute": {Mode: "protected", Rule: &Rule{Kind: "role", Value: "reader"}}}}}, Provider: testProvider{facts}, SelectedScopes: provider}
	decision, _, _, err := s.AuthorizeSelectionWithStatus(context.Background(), Request{Resource: resource, Action: "execute"}, []Entity{{Type: "advertiser", ID: "1"}})
	if err != nil || decision.Bounded || provider.calls != 0 {
		t.Fatalf("%+v %v calls=%d", decision, err, provider.calls)
	}
}

type selectedIdentitySwitch struct {
	facts Facts
	calls int
}

func (p *selectedIdentitySwitch) Resolve(context.Context) (Facts, error) {
	p.calls++
	f := p.facts
	if p.calls > 1 {
		f.Subject = "switched"
	}
	return f, nil
}
func TestSelectedScopeReconfirmsOriginalIdentity(t *testing.T) {
	resource := Resource{Kind: "report", ID: "r", Tenant: "one"}
	selection := []Entity{{Type: "advertiser", ID: "1"}}
	provider := &selectedIdentitySwitch{facts: Facts{Subject: "alice", Issuer: "issuer", Tenant: "one", Roles: []string{"reader"}, ValidUntil: time.Now().Add(time.Minute)}}
	scopes := &selectedAuthority{decision: SelectedScopeDecision{Entities: selection, ValidUntil: time.Now().Add(time.Minute)}}
	service := &Service{Store: &testStore{doc: Document{Resource: resource, Revision: 1, Policies: map[string]Policy{"execute": {Mode: "protected", Rule: &Rule{Kind: "role", Value: "reader"}, EntityType: "advertiser"}}}}, Provider: provider, SelectedScopes: scopes}
	if _, _, _, err := service.AuthorizeSelectionWithStatus(context.Background(), Request{Resource: resource, Action: "execute"}, selection); !errors.Is(err, ErrIdentityDenied) {
		t.Fatalf("identity switch escaped selected scope: %v", err)
	}
}

type selectedSlowIdentity struct {
	facts Facts
	calls int
}

func (p *selectedSlowIdentity) Resolve(context.Context) (Facts, error) {
	p.calls++
	if p.calls > 1 {
		time.Sleep(30 * time.Millisecond)
	}
	return p.facts, nil
}
func TestSelectedScopeLeaseCannotExpireDuringIdentityReconfirmation(t *testing.T) {
	resource := Resource{Kind: "report", ID: "r", Tenant: "one"}
	selection := []Entity{{Type: "advertiser", ID: "1"}}
	provider := &selectedSlowIdentity{facts: Facts{Subject: "alice", Issuer: "issuer", Tenant: "one", Roles: []string{"reader"}, ValidUntil: time.Now().Add(time.Minute)}}
	scopes := &selectedAuthority{decision: SelectedScopeDecision{Entities: selection, ValidUntil: time.Now().Add(20 * time.Millisecond)}}
	service := &Service{Store: &testStore{doc: Document{Resource: resource, Revision: 1, Policies: map[string]Policy{"execute": {Mode: "protected", Rule: &Rule{Kind: "role", Value: "reader"}, EntityType: "advertiser"}}}}, Provider: provider, SelectedScopes: scopes}
	if _, _, _, err := service.AuthorizeSelectionWithStatus(context.Background(), Request{Resource: resource, Action: "execute"}, selection); !errors.Is(err, ErrDenied) {
		t.Fatalf("scope lease expired during reconfirm but returned allow: %v", err)
	}
}
