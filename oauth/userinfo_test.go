package oauth

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/viant/authz"
)

func TestUserInfoProviderVerifiesIdentityAndSeparatesFacts(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	responseBody := `{"status":"ok","info":{"uid":"alice","subject":"alice","userId":7,"accountId":21,"roles":["writer","reader"],"features":["export"],"scopes":[{"id":9001,"scope":"plan:read"}],"entityPermissions":[{"type":"advertiser","id":"42","permissions":["ADVERTISER_OWNER"]}]}}`
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.Header.Get("Authorization") == "" || r.Header.Get("Accept") != "application/json" {
			t.Errorf("user-info request headers=%v", r.Header)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(responseBody))
	}))
	defer server.Close()
	provider, err := NewUserInfo(UserInfoConfig{Issuer: "https://identity.example", Audience: "studio-web", Algorithms: []string{"EdDSA"}, Keyfunc: func(*jwt.Token) (any, error) { return public, nil }, URL: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	sign := func(change func(*userInfoClaims)) string {
		t.Helper()
		claims := &userInfoClaims{RegisteredClaims: jwt.RegisteredClaims{Issuer: "https://identity.example", Audience: []string{"studio-web"}, Subject: "alice", ExpiresAt: jwt.NewNumericDate(time.Now().Add(59 * time.Minute))}, UserID: 7, AccountID: 21}
		if change != nil {
			change(claims)
		}
		token, signErr := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims).SignedString(private)
		if signErr != nil {
			t.Fatal(signErr)
		}
		return token
	}
	valid := sign(nil)
	facts, err := provider.Resolve(WithBearer(context.Background(), valid))
	if err != nil || facts.Subject != "alice" || facts.Tenant != "21" || facts.Issuer != "https://identity.example" || !facts.ValidUntil.After(time.Now()) || len(facts.Roles) != 2 || facts.Roles[0] != "reader" || facts.Roles[1] != "writer" || len(facts.Exposures) != 1 || facts.Exposures[0] != "export" || len(facts.EntityPermissions) != 1 || facts.EntityGroups["advertiser"][0] != "42" || len(facts.GrantedScopes) != 0 {
		t.Fatalf("facts=%+v error=%v", facts, err)
	}
	if requests != 1 {
		t.Fatalf("user-info calls=%d", requests)
	}
	identity, err := provider.ResolveIdentity(WithBearer(context.Background(), valid))
	if err != nil || identity.Subject != "alice" || identity.Tenant != "21" || identity.Issuer != "https://identity.example" ||
		len(identity.Roles) != 0 || len(identity.Exposures) != 0 || len(identity.EntityPermissions) != 0 || requests != 1 {
		t.Fatalf("identity-only facts=%+v error=%v user-info calls=%d", identity, err, requests)
	}
	if _, err := provider.ResolveIdentity(WithBearer(context.Background(), "invalid")); err == nil {
		t.Fatal("identity-only resolver accepted an invalid token")
	}
	responseBody = `{"status":"ok","info":{"uid":"different-stored-id","subject":"alice","userId":7,"accountId":21,"roles":["reader"],"features":["export"],"entityPermissions":[]}}`
	if _, err := provider.Resolve(WithBearer(context.Background(), valid)); err != nil {
		t.Fatalf("a verified subject must not be confused with the stored UID: %v", err)
	}
	responseBody = `{"status":"ok","info":{"uid":"alice","subject":"alice","userId":7,"accountId":21,"roles":["writer","reader"],"features":["export"],"entityPermissions":[]}}`
	for name, token := range map[string]string{
		"wrong issuer":      sign(func(c *userInfoClaims) { c.Issuer = "https://other.example" }),
		"wrong audience":    sign(func(c *userInfoClaims) { c.Audience = []string{"other"} }),
		"missing subject":   sign(func(c *userInfoClaims) { c.Subject = "" }),
		"overlong lifetime": sign(func(c *userInfoClaims) { c.ExpiresAt = jwt.NewNumericDate(time.Now().Add(2 * time.Hour)) }),
		"other account":     sign(func(c *userInfoClaims) { c.AccountID = 22 }),
		"other user":        sign(func(c *userInfoClaims) { c.UserID = 8 }),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := provider.Resolve(WithBearer(context.Background(), token)); err == nil {
				t.Fatal("credential was accepted")
			}
		})
	}
	for name, body := range map[string]string{
		"missing subject":          `{"status":"ok","info":{"userId":7,"accountId":21,"roles":[],"features":[],"entityPermissions":[]}}`,
		"wrong subject":            `{"status":"ok","info":{"subject":"other","userId":7,"accountId":21,"roles":[],"features":[],"entityPermissions":[]}}`,
		"missing roles":            `{"status":"ok","info":{"subject":"alice","userId":7,"accountId":21,"features":[],"entityPermissions":[]}}`,
		"null features":            `{"status":"ok","info":{"subject":"alice","userId":7,"accountId":21,"roles":[],"features":null,"entityPermissions":[]}}`,
		"different account":        `{"status":"ok","info":{"subject":"alice","userId":7,"accountId":22,"roles":[],"features":[],"entityPermissions":[]}}`,
		"duplicate role authority": `{"status":"ok","info":{"subject":"alice","userId":7,"accountId":21,"roles":[],"roles":["admin"],"features":[],"entityPermissions":[]}}`,
		"case-folded duplicate":    `{"status":"ok","info":{"subject":"alice","userId":7,"accountId":21,"roles":[],"Roles":["admin"],"features":[],"entityPermissions":[]}}`,
		"duplicate grant":          `{"status":"ok","info":{"subject":"alice","userId":7,"accountId":21,"roles":["admin","admin"],"features":[],"entityPermissions":[]}}`,
		"missing entity grants":    `{"status":"ok","info":{"subject":"alice","userId":7,"accountId":21,"roles":[],"features":[]}}`,
		"numeric ACL identity":     `{"status":"ok","info":{"subject":"alice","userId":7,"accountId":21,"roles":[],"features":[],"entityPermissions":[{"type":"advertiser","id":42,"permissions":["ADVERTISER_OWNER"]}]}}`,
		"duplicate entity key":     `{"status":"ok","info":{"subject":"alice","userId":7,"accountId":21,"roles":[],"features":[],"entityPermissions":[{"type":"advertiser","id":"42","permissions":["OWNER"]},{"type":"advertiser","id":"42","permissions":["EDIT"]}]}}`,
		"extra ACL row id":         `{"status":"ok","info":{"subject":"alice","userId":7,"accountId":21,"roles":[],"features":[],"entityPermissions":[{"type":"advertiser","id":"42","aclId":99,"permissions":["OWNER"]}]}}`,
	} {
		t.Run(name, func(t *testing.T) {
			responseBody = body
			if _, err := provider.Resolve(WithBearer(context.Background(), valid)); err == nil {
				t.Fatal("malformed user-info authority was accepted")
			}
		})
	}
}

func TestUserInfoProviderRejectsRedirectAndUnsafeEndpoint(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	other := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("bearer was redirected") }))
	defer other.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, other.URL, http.StatusFound) }))
	defer server.Close()
	config := UserInfoConfig{Issuer: "issuer", Audience: "audience", Algorithms: []string{"EdDSA"}, Keyfunc: func(*jwt.Token) (any, error) { return public, nil }, URL: server.URL}
	provider, err := NewUserInfo(config)
	if err != nil {
		t.Fatal(err)
	}
	claims := userInfoClaims{RegisteredClaims: jwt.RegisteredClaims{Issuer: "issuer", Audience: []string{"audience"}, Subject: "alice", ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Minute))}, UserID: 7, AccountID: 21}
	token, _ := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims).SignedString(private)
	if _, err := provider.Resolve(WithBearer(context.Background(), token)); !errors.Is(err, authz.ErrUnavailable) {
		t.Fatalf("redirect was not classified unavailable: %v", err)
	}
	config.URL = "http://identity.example/user-info"
	if _, err := NewUserInfo(config); err == nil || !strings.Contains(err.Error(), "HTTPS") {
		t.Fatalf("unsafe endpoint error=%v", err)
	}
}

func TestAccountUserInfoKeepsAccountAndTenantDistinct(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"status":"ok","info":{"subject":"alice","userId":7,"accountId":21,"roles":["ROLE_READER"],"features":["EXPOSE_REPORTS"],"entityPermissions":[]}}`))
	}))
	defer server.Close()
	config := UserInfoConfig{Issuer: "https://identity.example", Audience: "studio-web", Algorithms: []string{"EdDSA"}, Keyfunc: func(*jwt.Token) (any, error) { return public, nil }, URL: server.URL, FactLease: 2 * time.Minute}
	if _, err := NewAccountUserInfo(config, nil); err == nil {
		t.Fatal("implicit account-to-tenant mapping accepted")
	}
	withoutLease := config
	withoutLease.FactLease = 0
	if _, err := NewAccountUserInfo(withoutLease, func(context.Context, string, int) (string, error) { return "tenant", nil }); err == nil {
		t.Fatal("unbounded authority fact lease accepted")
	}
	provider, err := NewAccountUserInfo(config, func(_ context.Context, subject string, accountID int) (string, error) {
		if subject != "alice" || accountID != 21 {
			t.Fatalf("unverified mapping input %q %d", subject, accountID)
		}
		return "tenant-west", nil
	})
	if err != nil {
		t.Fatal(err)
	}
	claims := userInfoClaims{RegisteredClaims: jwt.RegisteredClaims{Issuer: config.Issuer, Audience: []string{config.Audience}, Subject: "alice", ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Minute))}, UserID: 7, AccountID: 21}
	token, err := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims).SignedString(private)
	if err != nil {
		t.Fatal(err)
	}
	principal, err := provider.ResolvePrincipal(WithBearer(context.Background(), token))
	if err != nil || principal.AccountID != "21" || principal.Facts.Tenant != "tenant-west" || principal.Facts.Roles[0] != "ROLE_READER" || principal.Facts.Exposures[0] != "EXPOSE_REPORTS" || principal.IdentityRevision == "" {
		t.Fatalf("principal=%+v err=%v", principal, err)
	}
	if principal.Facts.ValidUntil.After(time.Now().Add(2 * time.Minute)) {
		t.Fatalf("authority lease exceeded configured cap: %v", principal.Facts.ValidUntil)
	}
	facts, err := provider.Resolve(WithBearer(context.Background(), token))
	if err != nil || facts.Tenant != "tenant-west" {
		t.Fatalf("facts=%+v err=%v", facts, err)
	}
	account, err := provider.Account(WithBearer(context.Background(), token), facts)
	if err != nil || account != "21" {
		t.Fatalf("account=%q err=%v", account, err)
	}
	revision, revisionLease, err := provider.AuthorityRevision(WithBearer(context.Background(), token), facts, account)
	if err != nil || revision != principal.IdentityRevision || !revisionLease.After(time.Now()) || revisionLease.After(principal.Facts.ValidUntil) {
		t.Fatalf("authority revision=%q lease=%v err=%v", revision, revisionLease, err)
	}
	if _, _, err := provider.AuthorityRevision(WithBearer(context.Background(), token), facts, "another-account"); !errors.Is(err, authz.ErrDenied) {
		t.Fatalf("cross-account authority revision=%v", err)
	}
	facts.Exposures = nil
	if _, err := provider.Account(WithBearer(context.Background(), token), facts); err == nil {
		t.Fatal("facts changed between account and ACL resolution")
	}
	if _, _, err := provider.AuthorityRevision(WithBearer(context.Background(), token), facts, account); !errors.Is(err, authz.ErrDenied) {
		t.Fatalf("changed facts reused authority revision: %v", err)
	}
	facts = principal.Facts
	facts.EntityPermissions = []authz.EntityPermission{{Type: "customer", ID: "42", Permissions: []string{"write"}}}
	if _, err := provider.Account(WithBearer(context.Background(), token), facts); err == nil {
		t.Fatal("named entity permission drift was accepted")
	}
	server.Close()
	if _, err := provider.Account(WithBearer(context.Background(), token), principal.Facts); !errors.Is(err, authz.ErrUnavailable) {
		t.Fatalf("user-info outage was treated as denial: %v", err)
	}
}
