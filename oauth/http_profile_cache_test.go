package oauth

import (
	"context"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"github.com/viant/authz"
	"net/http"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type profileClock struct {
	sync.Mutex
	value time.Time
}

func (c *profileClock) now() time.Time      { c.Lock(); defer c.Unlock(); return c.value }
func (c *profileClock) add(d time.Duration) { c.Lock(); c.value = c.value.Add(d); c.Unlock() }
func cacheFixture(t *testing.T) (*authorityHTTPFixture, *profileClock, HTTPIdentityConfig) {
	t.Helper()
	f := newAuthorityHTTPFixture(t)
	clock := &profileClock{value: time.Now().UTC()}
	stampCacheInfo(f, clock.now(), 15*time.Minute)
	c := f.config()
	c.FactLease = "15m"
	c.UserInfoCacheTTL = "15m"
	c.JWKSRefreshInterval = "1h"
	c.Now = clock.now
	return f, clock, c
}
func stampCacheInfo(f *authorityHTTPFixture, now time.Time, lease time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.info["evaluatedAt"] = now.UTC().Format(time.RFC3339Nano)
	f.info["validUntil"] = now.Add(lease).UTC().Format(time.RFC3339Nano)
}
func cacheIdentity(t *testing.T, c HTTPIdentityConfig) *HTTPIdentityProvider {
	t.Helper()
	p, e := newHTTPIdentity(c)
	if e != nil {
		t.Fatal(e)
	}
	return p
}
func cacheToken(t *testing.T, f *authorityHTTPFixture, overrides jwt.MapClaims) string {
	t.Helper()
	claims := jwt.MapClaims{"iss": f.server.URL, "aud": "configured-client", "sub": "reader", "user_id": 7, "account_id": 21, "iat": time.Now().Add(-time.Second).Unix(), "exp": time.Now().Add(time.Hour).Unix()}
	for k, v := range overrides {
		claims[k] = v
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = "key"
	value, e := token.SignedString(f.key)
	if e != nil {
		t.Fatal(e)
	}
	return value
}
func TestUserInfoCacheManyPathsRenewedCredentialAndMetadataFinishOneRead(t *testing.T) {
	f, _, c := cacheFixture(t)
	p := cacheIdentity(t, c)
	ctx := WithBearer(context.Background(), cacheToken(t, f, nil))
	principal, e := p.ResolvePrincipal(ctx)
	if e != nil {
		t.Fatal(e)
	}
	for i := 0; i < 20; i++ {
		if _, e = p.ResolvePrincipal(ctx); e != nil {
			t.Fatal(e)
		}
		if _, e = p.ProjectAccount(ctx, principal.Facts, principal.AccountID); e != nil {
			t.Fatal(e)
		}
		scoped, end, err := p.BeginMetadataRead(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = p.ResolvePrincipal(scoped); err != nil {
			t.Fatal(err)
		}
		if err = end(); err != nil {
			t.Fatal(err)
		}
	}
	renewed := WithBearer(context.Background(), cacheToken(t, f, jwt.MapClaims{"jti": "renewed-valid-token"}))
	if _, e = p.ResolvePrincipal(renewed); e != nil {
		t.Fatal(e)
	}
	scoped, end, e := p.BeginOperation(renewed)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = p.ResolvePrincipal(scoped); e != nil {
		t.Fatal(e)
	}
	if e = end(); e != nil {
		t.Fatal(e)
	}
	if got := f.userinfoCalls.Load(); got != 1 {
		t.Fatalf("userinfo calls=%d,want1 across projections/scopes/renewals", got)
	}
}
func TestUserInfoCacheFifteenMinuteRevocationAndFailedRefresh(t *testing.T) {
	f, clock, c := cacheFixture(t)
	p := cacheIdentity(t, c)
	ctx := WithBearer(context.Background(), cacheToken(t, f, nil))
	if _, e := p.Resolve(ctx); e != nil {
		t.Fatal(e)
	}
	f.mu.Lock()
	f.info["roles"] = []string{"viewer"}
	f.mu.Unlock()
	clock.add(14 * time.Minute)
	before, e := p.Resolve(ctx)
	if e != nil || len(before.Roles) != 1 || before.Roles[0] != "editor" {
		t.Fatal("cached profile not retained until configured TTL", e)
	}
	if f.userinfoCalls.Load() != 1 {
		t.Fatal("TTL hit fetched userinfo")
	}
	clock.add(time.Minute)
	stampCacheInfo(f, clock.now(), 15*time.Minute)
	after, e := p.Resolve(ctx)
	if e != nil || after.Roles[0] != "viewer" || f.userinfoCalls.Load() != 2 {
		t.Fatal("TTL did not refresh changed authority", e)
	}
	clock.add(15 * time.Minute)
	stampCacheInfo(f, clock.now(), 15*time.Minute)
	f.mu.Lock()
	f.info["subject"] = "wrong-signed-identity"
	f.mu.Unlock()
	for i := 0; i < 2; i++ {
		if _, e = p.Resolve(ctx); e == nil {
			t.Fatal("failed refresh reused stale profile")
		}
	}
	if f.userinfoCalls.Load() != 4 {
		t.Fatal("failed refresh was cached")
	}
	f.mu.Lock()
	f.info["subject"] = "reader"
	f.mu.Unlock()
	if _, e = p.Resolve(ctx); e != nil {
		t.Fatal(e)
	}
	if f.userinfoCalls.Load() != 5 {
		t.Fatal("successful retry missing")
	}
}
func TestUserInfoCacheAccountUserProviderMappingAndScopePartition(t *testing.T) {
	f, _, c := cacheFixture(t)
	c.TenantByAccount["22"] = "other-tenant"
	p := cacheIdentity(t, c)
	ctx := WithBearer(context.Background(), cacheToken(t, f, nil))
	first, e := p.ResolvePrincipal(ctx)
	if e != nil {
		t.Fatal(e)
	}
	f.mu.Lock()
	f.info["accountId"] = 22
	f.info["roles"] = []string{"second-account"}
	f.mu.Unlock()
	other := WithBearer(context.Background(), cacheToken(t, f, jwt.MapClaims{"account_id": 22}))
	second, e := p.ResolvePrincipal(other)
	if e != nil || second.AccountID != "22" || second.Facts.Tenant != "other-tenant" {
		t.Fatal("account partition missing", e)
	}
	again, e := p.ResolvePrincipal(ctx)
	if e != nil || again.AccountID != first.AccountID || again.Facts.Roles[0] != "editor" || f.userinfoCalls.Load() != 2 {
		t.Fatal("account profiles mixed", e)
	}
	// A changed verified user ID cannot hit the previous subject/account entry.
	f.mu.Lock()
	f.info["accountId"] = 21
	f.mu.Unlock()
	if _, e = p.ResolvePrincipal(WithBearer(context.Background(), cacheToken(t, f, jwt.MapClaims{"user_id": 8}))); e == nil {
		t.Fatal("signed user mismatch borrowed cached profile")
	}
	f.mu.Lock()
	f.info["accountId"] = 21
	f.info["alternateRoles"] = []string{"different-mapping"}
	f.mu.Unlock()
	c.Mapping.Roles = "info.alternateRoles"
	otherProvider := cacheIdentity(t, c)
	mapped, e := otherProvider.ResolvePrincipal(ctx)
	if e != nil || mapped.Facts.Roles[0] != "different-mapping" {
		t.Fatal("provider mapping partition missing", e)
	}
	before := f.userinfoCalls.Load()
	if _, e = p.ResolvePrincipal(WithBearer(context.Background(), cacheToken(t, f, jwt.MapClaims{"scope": "restricted"}))); e != nil {
		t.Fatal(e)
	}
	if f.userinfoCalls.Load() != before+1 {
		t.Fatal("credential scope borrowed another userinfo representation")
	}
}
func TestUserInfoCacheDeepClonesAndBoundedEntries(t *testing.T) {
	f, _, c := cacheFixture(t)
	c.UserInfoCacheMaxEntries = 2
	c.TenantByAccount["22"] = "workspace"
	c.TenantByAccount["23"] = "workspace"
	c.Mapping.AccountProjection["nested"] = "info.nested"
	f.mu.Lock()
	f.info["nested"] = map[string]any{"values": []string{"original"}}
	f.mu.Unlock()
	p := cacheIdentity(t, c)
	ctx := WithBearer(context.Background(), cacheToken(t, f, nil))
	first, e := p.readProfile(ctx)
	if e != nil {
		t.Fatal(e)
	}
	first.principal.Facts.Roles[0] = "mutated"
	first.principal.Facts.EntityPermissions[0].Permissions[0] = "mutated"
	first.projection["nested"].(map[string]any)["values"].([]any)[0] = "mutated"
	again, e := p.readProfile(ctx)
	if e != nil || again.principal.Facts.Roles[0] != "editor" || again.principal.Facts.EntityPermissions[0].Permissions[0] != "read" || again.projection["nested"].(map[string]any)["values"].([]any)[0] != "original" {
		t.Fatal("profile cache shares mutable data", e)
	}
	for _, account := range []int{22, 23} {
		f.mu.Lock()
		f.info["accountId"] = account
		f.mu.Unlock()
		if _, e = p.Resolve(WithBearer(context.Background(), cacheToken(t, f, jwt.MapClaims{"account_id": account}))); e != nil {
			t.Fatal(e)
		}
	}
	p.profiles.Lock()
	size := len(p.profiles.entries)
	p.profiles.Unlock()
	if size != 2 {
		t.Fatalf("cache capacity=%d,want2", size)
	}
	f.mu.Lock()
	f.info["accountId"] = 21
	f.mu.Unlock()
	if _, e = p.Resolve(ctx); e != nil {
		t.Fatal(e)
	}
	if f.userinfoCalls.Load() != 4 {
		t.Fatal("bounded cache did not evict oldest entry")
	}
}
func TestUserInfoCacheTokenAndProviderExpiryBoundProfile(t *testing.T) {
	f, clock, c := cacheFixture(t)
	p := cacheIdentity(t, c)
	short := WithBearer(context.Background(), cacheToken(t, f, jwt.MapClaims{"exp": clock.now().Add(5 * time.Second).Unix()}))
	profile, e := p.Resolve(short)
	if e != nil {
		t.Fatal(e)
	}
	if profile.ValidUntil.After(clock.now().Add(5 * time.Second)) {
		t.Fatal("profile exceeded verified token expiry")
	}
	clock.add(6 * time.Second)
	if _, e = p.Resolve(short); e == nil {
		t.Fatal("expired JWT hit cache")
	}
	if f.userinfoCalls.Load() != 1 {
		t.Fatal("expired credential reached userinfo")
	}
	stampCacheInfo(f, clock.now(), time.Minute)
	long := WithBearer(context.Background(), cacheToken(t, f, jwt.MapClaims{"jti": "long"}))
	fresh, e := p.Resolve(long)
	if e != nil {
		t.Fatal(e)
	}
	if fresh.ValidUntil.After(clock.now().Add(time.Minute)) {
		t.Fatal("profile exceeded source lease")
	}
	clock.add(time.Minute + time.Second)
	if _, e = p.Resolve(long); e == nil {
		t.Fatal("expired provider lease reused")
	}
}

type cacheRoundTrip func(*http.Request) (*http.Response, error)

func (f cacheRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestUserInfoCacheConcurrentRenewedCredentialsSingleFlight(t *testing.T) {
	f, _, c := cacheFixture(t)
	release := make(chan struct{})
	started := make(chan struct{}, 1)
	var entered atomic.Int32
	c.Client = &http.Client{Transport: cacheRoundTrip(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/userinfo" {
			entered.Add(1)
			select {
			case started <- struct{}{}:
			default:
			}
			select {
			case <-release:
			case <-r.Context().Done():
				return nil, r.Context().Err()
			}
		}
		return http.DefaultTransport.RoundTrip(r)
	})}
	p := cacheIdentity(t, c)
	var wg sync.WaitGroup
	errs := make(chan error, 24)
	begin := make(chan struct{})
	for i := 0; i < 24; i++ {
		token := cacheToken(t, f, jwt.MapClaims{"jti": fmt.Sprint(i)})
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-begin
			_, err := p.Resolve(WithBearer(context.Background(), token))
			errs <- err
		}()
	}
	close(begin)
	<-started
	for i := 0; i < 50; i++ {
		runtime.Gosched()
	}
	if entered.Load() != 1 {
		t.Fatalf("concurrent miss dispatched%duserinfo calls", entered.Load())
	}
	close(release)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if f.userinfoCalls.Load() != 1 {
		t.Fatal("renewed same-user credentials were keyed by bearer")
	}
}
func TestUserInfoCacheNeverCachesBusinessEvaluationDecisions(t *testing.T) {
	f, _, c := cacheFixture(t)
	evaluation := f.evaluation()
	providers, e := NewHTTPProviders(context.Background(), c, &evaluation)
	if e != nil {
		t.Fatal(e)
	}
	ctx := WithBearer(context.Background(), cacheToken(t, f, nil))
	principal, e := providers.Identity.ResolvePrincipal(ctx)
	if e != nil {
		t.Fatal(e)
	}

	// Use the native configured permission interface, with a concrete selected entity.
	for i := 0; i < 2; i++ {
		if _, _, e = providers.PermissionWithLease(ctx, principal.Facts, authz.Entity{Type: "document", ID: "101"}, "read"); e != nil {
			t.Fatal(e)
		}
	}
	if f.evaluationCalls.Load() != 2 {
		t.Fatalf("business permission decisions cached: calls%d", f.evaluationCalls.Load())
	}
	if f.userinfoCalls.Load() != 1 {
		t.Fatal("evaluation before/after escaped userinfo cache")
	}
}

func TestUserInfoCacheConfigurationBoundsAndDefault(t *testing.T) {
	_, _, base := cacheFixture(t)
	base.UserInfoCacheTTL = ""
	if p := cacheIdentity(t, base); p.cacheTTL != 15*time.Minute || p.profiles.capacity != 1024 {
		t.Fatal("default profile cache policy")
	}
	for _, change := range []func(*HTTPIdentityConfig){
		func(c *HTTPIdentityConfig) { c.UserInfoCacheTTL = "16m" },
		func(c *HTTPIdentityConfig) { c.UserInfoCacheTTL = "-1s" },
		func(c *HTTPIdentityConfig) { c.UserInfoCacheMaxEntries = 65537 },
		func(c *HTTPIdentityConfig) { c.FactLease = "16m" },
		func(c *HTTPIdentityConfig) { c.Mapping.JWTAccountID = "" },
	} {
		c := base
		change(&c)
		if _, err := newHTTPIdentity(c); err == nil {
			t.Fatal("invalid cache policy accepted")
		}
	}
}

func TestUserInfoCacheHitStillRejectsInvalidSignedIdentity(t *testing.T) {
	f, _, c := cacheFixture(t)
	p := cacheIdentity(t, c)
	if _, err := p.Resolve(WithBearer(context.Background(), cacheToken(t, f, nil))); err != nil {
		t.Fatal(err)
	}
	for _, override := range []jwt.MapClaims{{"iss": "https://wrong.example"}, {"aud": "wrong-client"}, {"account_id": nil}, {"user_id": nil}, {"sub": ""}} {
		if _, err := p.Resolve(WithBearer(context.Background(), cacheToken(t, f, override))); err == nil {
			t.Fatal("invalid signed identity borrowed cached profile")
		}
	}
	if f.userinfoCalls.Load() != 1 {
		t.Fatal("invalid credentials forwarded to userinfo")
	}
}

func TestUserInfoCacheHitExpiresOnlyRequestedEntry(t *testing.T) {
	f, clock, c := cacheFixture(t)
	p := cacheIdentity(t, c)
	ctx := WithBearer(context.Background(), cacheToken(t, f, nil))
	if _, err := p.Resolve(ctx); err != nil {
		t.Fatal(err)
	}
	p.profiles.Lock()
	p.profiles.entries["unrelated-expired"] = httpProfileEntry{until: clock.now().Add(-time.Second)}
	p.profiles.Unlock()
	if _, err := p.Resolve(ctx); err != nil {
		t.Fatal(err)
	}
	p.profiles.Lock()
	_, retained := p.profiles.entries["unrelated-expired"]
	p.profiles.Unlock()
	if !retained {
		t.Fatal("cache hit walked unrelated entries for expiry")
	}
	if f.userinfoCalls.Load() != 1 {
		t.Fatal("cache hit fetched userinfo")
	}
}
