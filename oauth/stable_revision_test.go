package oauth

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"github.com/golang-jwt/jwt/v5"
	"github.com/viant/authz"
	"github.com/viant/authz/gating"
	"testing"
	"time"
)

func renewedHTTPBearer(t *testing.T, f *authorityHTTPFixture, expires time.Time) string {
	t.Helper()
	claims := jwt.MapClaims{"iss": f.server.URL, "aud": "configured-client", "sub": "reader", "user_id": 7, "account_id": 21, "exp": expires.Unix()}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = "key"
	value, err := token.SignedString(f.key)
	if err != nil {
		t.Fatal(err)
	}
	return value
}
func TestHTTPPrincipalRevisionStableAcrossCredentialRenewalAndBoundToFacts(t *testing.T) {
	f := newAuthorityHTTPFixture(t)
	f.info["groups"] = []string{"operators"}
	config := f.config()
	config.Mapping.MembershipGroups = "info.groups"
	providers, err := NewHTTPProviders(context.Background(), config, nil)
	if err != nil {
		t.Fatal(err)
	}
	firstToken := renewedHTTPBearer(t, f, time.Now().Add(time.Hour))
	nextToken := renewedHTTPBearer(t, f, time.Now().Add(2*time.Hour))
	firstCtx := WithBearer(context.Background(), firstToken)
	nextCtx := WithBearer(context.Background(), nextToken)
	first, err := providers.Identity.ResolvePrincipal(firstCtx)
	if err != nil {
		t.Fatal(err)
	}
	next, err := providers.Identity.ResolvePrincipal(nextCtx)
	if err != nil {
		t.Fatal(err)
	}
	if firstToken == nextToken || !gating.SamePrincipalAuthority(first, next) {
		t.Fatal("same verified facts changed durable authority on renewal")
	}
	nativeBefore, err := providers.NativeWindowIdentity(firstCtx)
	if err != nil {
		t.Fatal(err)
	}
	nativeAfter, err := providers.NativeWindowIdentity(nextCtx)
	if err != nil || nativeBefore.IdentityRevision != nativeAfter.IdentityRevision {
		t.Fatal("identity-only tuple changed on expiry renewal")
	}
	scoped, finish, err := providers.MetadataScope.BeginMetadataRead(firstCtx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = providers.Identity.ResolvePrincipal(WithBearer(scoped, nextToken)); err == nil {
		t.Fatal("credential change reused held decision/cache context")
	}
	if err = finish(); err != nil {
		t.Fatal(err)
	}
	for _, change := range []struct {
		field string
		value any
	}{{"roles", []string{"reader"}}, {"features", []string{"other"}}, {"groups", []string{"other"}}, {"authorityRevision", "profile-2"}, {"businessModelContext", 2}, {"entityPermissions", []any{map[string]any{"type": "document", "id": 101, "permissions": []string{"read"}}}}} {
		f.mu.Lock()
		old := f.info[change.field]
		f.info[change.field] = change.value
		f.mu.Unlock()
		current, err := providers.Identity.ResolvePrincipal(nextCtx)
		if err != nil {
			t.Fatal(err)
		}
		if current.IdentityRevision == first.IdentityRevision {
			t.Fatalf("changed verified %s retained authority", change.field)
		}
		f.mu.Lock()
		f.info[change.field] = old
		f.mu.Unlock()
	}
	expired := WithBearer(context.Background(), renewedHTTPBearer(t, f, time.Now().Add(-time.Minute)))
	if _, err = providers.Identity.ResolvePrincipal(expired); err == nil {
		t.Fatal("expired current credential accepted")
	}
	foreign := WithBearer(context.Background(), f.token(t, 22, f.server.URL, "configured-client"))
	if _, err = providers.Identity.ResolvePrincipal(foreign); err == nil {
		t.Fatal("foreign account accepted")
	}
}
func TestJWTPrincipalRevisionTracksFactsInsteadOfExpirationBytes(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	p, err := New(Config{Issuer: "https://owned.invalid", Audience: "owned", Algorithms: []string{"EdDSA"}, Keyfunc: func(*jwt.Token) (any, error) { return pub, nil }})
	if err != nil {
		t.Fatal(err)
	}
	claims := Claims{RegisteredClaims: jwt.RegisteredClaims{Issuer: "https://owned.invalid", Subject: "reader", Audience: []string{"owned"}, ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour))}, Tenant: "workspace", AccountID: "21", MembershipGroups: []string{"operators"}, Roles: []string{"reader"}, Scope: "read", AllowedEntities: []authz.Entity{{Type: "document", ID: "101"}}}
	principal := func(c Claims) (gating.Principal, error) {
		token, e := jwt.NewWithClaims(jwt.SigningMethodEdDSA, c).SignedString(key)
		if e != nil {
			t.Fatal(e)
		}
		return p.ResolvePrincipal(WithBearer(context.Background(), token))
	}
	first, err := principal(claims)
	if err != nil {
		t.Fatal(err)
	}
	claims.ExpiresAt = jwt.NewNumericDate(time.Now().Add(2 * time.Hour))
	next, err := principal(claims)
	if err != nil || !gating.SamePrincipalAuthority(first, next) {
		t.Fatal("JWT expiry-only renewal changed identity")
	}
	claims.Roles = []string{"writer"}
	changed, err := principal(claims)
	if err != nil || changed.IdentityRevision == first.IdentityRevision {
		t.Fatal("changed JWT role retained authority")
	}
	claims.ExpiresAt = jwt.NewNumericDate(time.Now().Add(-time.Minute))
	if _, err = principal(claims); err == nil {
		t.Fatal("expired JWT accepted")
	}
}
