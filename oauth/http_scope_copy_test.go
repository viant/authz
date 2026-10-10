package oauth

import (
	"context"
	"testing"
	"time"
)

type copiedDecisionValueKey struct{}

func TestHTTPCopyDecisionPreservesRequestAndScopeBoundary(t *testing.T) {
	f := newAuthorityHTTPFixture(t)
	providers, err := NewHTTPProviders(context.Background(), f.config(), nil)
	if err != nil {
		t.Fatal(err)
	}
	p := providers.Identity.(*HTTPIdentityProvider)
	credential := f.token(t, 21, f.server.URL, "configured-client")
	base := WithBearer(context.Background(), credential)
	scoped, finish, err := p.BeginDecision(base)
	if err != nil {
		t.Fatal(err)
	}
	request := context.WithValue(base, copiedDecisionValueKey{}, "held-window-pin")
	before := f.userinfoCalls.Load()
	copied, err := p.CopyDecision(request, scoped)
	if err != nil {
		t.Fatal(err)
	}
	if copied.Value(copiedDecisionValueKey{}) != "held-window-pin" {
		t.Fatal("request values were replaced")
	}
	facts, err := p.Resolve(copied)
	if err != nil {
		t.Fatal(err)
	}
	initial, err := p.Resolve(scoped)
	if err != nil || facts.ValidUntil != initial.ValidUntil {
		t.Fatal("scope lease changed")
	}
	if f.userinfoCalls.Load() != before {
		t.Fatal("copy must preserve active scope without a fresh profile read")
	}
	if _, err = p.CopyDecision(context.Background(), scoped); err == nil {
		t.Fatal("missing credential accepted")
	}
	if _, err = p.CopyDecision(WithBearer(context.Background(), "invalid"), scoped); err == nil {
		t.Fatal("wrong credential accepted")
	}
	if _, err = p.CopyDecision(WithBearer(context.Background(), f.token(t, 22, f.server.URL, "configured-client")), scoped); err == nil {
		t.Fatal("signed foreign-account credential accepted")
	}
	other, err := newHTTPIdentity(f.config())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = other.CopyDecision(request, scoped); err == nil {
		t.Fatal("foreign provider scope accepted")
	}
	if _, err = p.CopyDecision(request, base); err == nil {
		t.Fatal("missing scope accepted")
	}
	if err = finish(); err != nil {
		t.Fatal(err)
	}
	if _, err = p.Resolve(copied); err == nil {
		t.Fatal("copied scope survived finish")
	}
	if _, err = p.CopyDecision(request, scoped); err == nil {
		t.Fatal("closed scope copied")
	}
	metadata, closeMetadata, err := p.BeginMetadataRead(base)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = p.CopyDecision(request, metadata); err == nil {
		t.Fatal("metadata scope upgraded")
	}
	if err = closeMetadata(); err != nil {
		t.Fatal(err)
	}
}
func TestHTTPCopyDecisionRejectsCancellationAndConflictingScopes(t *testing.T) {
	f := newAuthorityHTTPFixture(t)
	p, err := newHTTPIdentity(f.config())
	if err != nil {
		t.Fatal(err)
	}
	base := WithBearer(context.Background(), f.token(t, 21, f.server.URL, "configured-client"))
	source, cancel := context.WithCancel(base)
	scoped, finish, err := p.BeginDecision(source)
	if err != nil {
		t.Fatal(err)
	}
	copied, err := p.CopyDecision(base, scoped)
	if err != nil {
		t.Fatal(err)
	}
	independent, closeIndependent, err := p.BeginDecision(base)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = p.CopyDecision(independent, scoped); err == nil {
		t.Fatal("conflicting active scope overwritten")
	}
	canceled, cancelRequest := context.WithCancel(base)
	cancelRequest()
	if _, err = p.CopyDecision(canceled, scoped); err == nil {
		t.Fatal("canceled caller accepted")
	}
	cancel()
	if _, err = p.Resolve(copied); err == nil {
		t.Fatal("copy outlived its source cancellation")
	}
	if _, err = p.CopyDecision(base, scoped); err == nil {
		t.Fatal("canceled source copied")
	}
	if err = finish(); err == nil {
		t.Fatal("canceled source released")
	}
	if err = closeIndependent(); err != nil {
		t.Fatal(err)
	}
}

func TestHTTPCopyDecisionCannotRenewExpiredHeldScope(t *testing.T) {
	f := newAuthorityHTTPFixture(t)
	p, err := newHTTPIdentity(f.config())
	if err != nil {
		t.Fatal(err)
	}
	base := WithBearer(context.Background(), f.token(t, 21, f.server.URL, "configured-client"))
	scoped, finish, err := p.BeginDecision(base)
	if err != nil {
		t.Fatal(err)
	}
	state := scoped.Value(httpScopeKey{}).(*httpScope)
	state.Lock()
	state.profile.principal.Facts.ValidUntil = time.Now().Add(-time.Second)
	state.Unlock()
	before := f.userinfoCalls.Load()
	if _, err = p.CopyDecision(base, scoped); err == nil {
		t.Fatal("expired held scope was renewed")
	}
	if f.userinfoCalls.Load() != before {
		t.Fatal("copy refreshed an expired held scope")
	}
	_ = finish()
}
