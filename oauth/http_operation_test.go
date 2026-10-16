package oauth

import (
	"context"
	"testing"
)

func TestHTTPOperationReadsUserInfoOnceAndClosesWithoutRoleRecheck(t *testing.T) {
	f := newAuthorityHTTPFixture(t)
	providers, err := NewHTTPProviders(context.Background(), f.config(), nil)
	if err != nil {
		t.Fatal(err)
	}
	p := providers.Identity.(*HTTPIdentityProvider)
	bearer := f.token(t, 21, f.server.URL, "configured-client")
	ctx := WithBearer(context.Background(), bearer)
	scoped, finish, err := p.BeginOperation(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 10; i++ {
		if _, err = p.ResolvePrincipal(scoped); err != nil {
			t.Fatal(err)
		}
	}
	nested, endNested, err := p.BeginOperation(scoped)
	if err != nil {
		t.Fatal(err)
	}
	if err = endNested(); err != nil {
		t.Fatal(err)
	}
	if _, err = p.Resolve(nested); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.info["roles"] = []string{"changed"}
	f.mu.Unlock()
	if err = finish(); err != nil {
		t.Fatal(err)
	}
	if got := f.userinfoCalls.Load(); got != 1 {
		t.Fatalf("userinfo reads=%d, want1", got)
	}
	if _, err = p.Resolve(scoped); err == nil {
		t.Fatal("closed operation remained usable")
	}
	next, closeNext, err := p.BeginOperation(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = p.Resolve(next); err != nil {
		t.Fatal(err)
	}
	if err = closeNext(); err != nil {
		t.Fatal(err)
	}
	if got := f.userinfoCalls.Load(); got != 2 {
		t.Fatalf("separate operation reads=%d, want2", got)
	}
}

func TestHTTPOperationRejectsSwappedBearerAndCancellation(t *testing.T) {
	f := newAuthorityHTTPFixture(t)
	providers, err := NewHTTPProviders(context.Background(), f.config(), nil)
	if err != nil {
		t.Fatal(err)
	}
	p := providers.Identity.(*HTTPIdentityProvider)
	bearer := f.token(t, 21, f.server.URL, "configured-client")
	base, cancel := context.WithCancel(WithBearer(context.Background(), bearer))
	scoped, finish, err := p.BeginOperation(base)
	if err != nil {
		t.Fatal(err)
	}
	swapped := WithBearer(scoped, f.token(t, 22, f.server.URL, "configured-client"))
	if _, err = p.Resolve(swapped); err == nil {
		t.Fatal("swapped bearer reused operation")
	}
	cancel()
	if err = finish(); err == nil {
		t.Fatal("canceled operation accepted")
	}
	if got := f.userinfoCalls.Load(); got != 1 {
		t.Fatalf("userinfo reads=%d, want1", got)
	}
}
