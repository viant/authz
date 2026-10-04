package oauth

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	access "github.com/viant/authz"
)

func TestVerifyIdentityAndFacts(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	provider, err := New(Config{Issuer: "https://identity.example", Audience: "studio-access", Algorithms: []string{"EdDSA"}, Keyfunc: func(*jwt.Token) (any, error) { return pub, nil }})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		change func(*Claims)
		denied bool
	}{
		{"valid", func(*Claims) {}, false},
		{"wrong issuer", func(c *Claims) { c.Issuer = "https://attacker.example" }, true},
		{"wrong audience", func(c *Claims) { c.Audience = []string{"other"} }, true},
		{"expired", func(c *Claims) { c.ExpiresAt = jwt.NewNumericDate(time.Now().Add(-time.Minute)) }, true},
		{"missing expiry", func(c *Claims) { c.ExpiresAt = nil }, true},
		{"missing tenant", func(c *Claims) { c.Tenant = "" }, true},
		{"wildcard tenant", func(c *Claims) { c.Tenant = "*" }, true},
		{"invalid entity", func(c *Claims) { c.AllowedEntities = []access.Entity{{ID: "42"}} }, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			claims := Claims{RegisteredClaims: jwt.RegisteredClaims{Issuer: "https://identity.example", Subject: "alice", Audience: []string{"studio-access"}, ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Minute))}, Tenant: "one", Roles: []string{"reader"}, Exposures: []string{"analytics"}, Scope: "plan:read reports:read", AllowedEntities: []access.Entity{{Type: "project", ID: "42"}}}
			tc.change(&claims)
			token, err := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims).SignedString(priv)
			if err != nil {
				t.Fatal(err)
			}
			facts, err := provider.Resolve(WithBearer(context.Background(), token))
			if (err != nil) != tc.denied {
				t.Fatalf("facts=%+v error=%v", facts, err)
			}
			if !tc.denied && (facts.Subject != "alice" || len(facts.Entities) != 1 || facts.Exposures[0] != "analytics" || len(facts.GrantedScopes) != 2 || facts.GrantedScopes[0] != "plan:read") {
				t.Fatalf("lost claims: %+v", facts)
			}
		})
	}
	_, wrongKey, _ := ed25519.GenerateKey(rand.Reader)
	token, _ := jwt.NewWithClaims(jwt.SigningMethodEdDSA, jwt.MapClaims{"iss": "https://identity.example", "aud": "studio-access", "sub": "alice", "tenant": "one", "exp": time.Now().Add(time.Minute).Unix()}).SignedString(wrongKey)
	if _, err := provider.Resolve(WithBearer(context.Background(), token)); err == nil {
		t.Fatal("forged signature accepted")
	}
}

func TestSignedOAuthScopeClaimRejectsMalformedAuthority(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	provider, err := New(Config{Issuer: "issuer", Audience: "audience", Algorithms: []string{"EdDSA"}, Keyfunc: func(*jwt.Token) (any, error) { return pub, nil }})
	if err != nil {
		t.Fatal(err)
	}
	for _, scope := range []string{"plan:read plan:read", " plan:read", "plan:read  reports:read", "plan:read\nreports:read"} {
		claims := Claims{RegisteredClaims: jwt.RegisteredClaims{Issuer: "issuer", Subject: "alice", Audience: []string{"audience"}, ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Minute))}, Tenant: "one", Scope: scope}
		token, err := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims).SignedString(priv)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := provider.Resolve(WithBearer(context.Background(), token)); err == nil {
			t.Fatalf("malformed scope claim accepted: %q", scope)
		}
	}
	var claims Claims
	for _, payload := range []string{`{"scope":"plan:read","scope":"reports:read"}`, `{"scope":"plan:read","Scope":"reports:read"}`} {
		if err := json.Unmarshal([]byte(payload), &claims); err == nil {
			t.Fatalf("ambiguous scope claim accepted: %s", payload)
		}
	}
}

func TestSignedAccountPrincipalRequiresExplicitAccount(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	provider, err := New(Config{Issuer: "issuer", Audience: "audience", Algorithms: []string{"EdDSA"}, Keyfunc: func(*jwt.Token) (any, error) { return pub, nil }})
	if err != nil {
		t.Fatal(err)
	}
	claims := Claims{RegisteredClaims: jwt.RegisteredClaims{Issuer: "issuer", Subject: "alice", Audience: []string{"audience"}, ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Minute))}, Tenant: "policy-owner", Roles: []string{"reader"}}
	sign := func() string {
		t.Helper()
		token, err := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims).SignedString(priv)
		if err != nil {
			t.Fatal(err)
		}
		return token
	}
	if _, err := provider.ResolvePrincipal(WithBearer(context.Background(), sign())); err == nil {
		t.Fatal("missing signed account accepted")
	}
	claims.AccountID, claims.MembershipGroups = "account-21", []string{"group-one"}
	principal, err := provider.ResolvePrincipal(WithBearer(context.Background(), sign()))
	if err != nil {
		t.Fatal(err)
	}
	if principal.AccountID != "account-21" || principal.Facts.Tenant != "policy-owner" || principal.IdentityRevision == "" || len(principal.MembershipGroups) != 1 {
		t.Fatalf("unexpected principal: %+v", principal)
	}
	claims.AccountID = " account-21"
	if _, err := provider.ResolvePrincipal(WithBearer(context.Background(), sign())); err == nil {
		t.Fatal("malformed account accepted")
	}
	var ambiguous Claims
	for _, payload := range []string{`{"accountId":"a","accountId":"b"}`, `{"accountId":"a","AccountId":"b"}`, `{"membershipGroups":["x"],"membershipGroups":["y"]}`} {
		if err := json.Unmarshal([]byte(payload), &ambiguous); err == nil {
			t.Fatalf("ambiguous account authority accepted: %s", payload)
		}
	}
}
