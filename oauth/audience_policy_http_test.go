package oauth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/viant/authz"
)

func TestHTTPIdentityAudiencePolicy(t *testing.T) {
	for _, setting := range []string{`{}`, `{"skipAudienceCheck":false}`, `{"skipAudienceCheck":true}`} {
		t.Run(setting, func(t *testing.T) {
			f := newAuthorityHTTPFixture(t)
			c := f.config()
			if err := json.Unmarshal([]byte(setting), &c); err != nil {
				t.Fatal(err)
			}
			p, err := NewHTTPProviders(context.Background(), c, nil)
			if err != nil {
				t.Fatal(err)
			}
			ctx := WithBearer(context.Background(), f.token(t, 21, c.Issuer, "https://resource.example/mcp"))
			principal, err := p.Identity.ResolvePrincipal(ctx)
			if c.SkipAudienceCheck {
				if err != nil || principal.AccountID != "21" || principal.Facts.Tenant != "workspace" || len(principal.Facts.Roles) != 1 {
					t.Fatalf("verified profile: %+v, %v", principal, err)
				}
				if f.userinfoCalls.Load() != 1 {
					t.Fatal("expected one authoritative profile read")
				}
				scoped, finish, err := p.MetadataScope.BeginMetadataRead(ctx)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := p.Identity.ResolvePrincipal(scoped); err != nil {
					t.Fatal(err)
				}
				f.mu.Lock()
				f.info["roles"] = []string{}
				f.mu.Unlock()
				if finish() == nil {
					t.Fatal("revocation must invalidate admitted scope")
				}
			} else {
				if !errors.Is(err, authz.ErrDenied) {
					t.Fatalf("strict audience policy: %v", err)
				}
				if f.userinfoCalls.Load() != 0 {
					t.Fatal("rejected token reached identity endpoint")
				}
			}
		})
	}
}

func TestHTTPIdentityAudienceOptOutPreservesVerification(t *testing.T) {
	for _, mode := range []string{"issuer", "signature", "expired", "missing-expiry", "missing-subject", "account", "userinfo-subject", "userinfo-account", "expired-source", "unavailable"} {
		t.Run(mode, func(t *testing.T) {
			f := newAuthorityHTTPFixture(t)
			c := f.config()
			c.SkipAudienceCheck = true
			// Exercise the existing host-owned public key binding as well as JWKS above.
			c.JWKSURL = ""
			c.Keyfunc = func(*jwt.Token) (any, error) { return &f.key.PublicKey, nil }
			p, err := NewHTTPProviders(context.Background(), c, nil)
			if err != nil {
				t.Fatal(err)
			}
			claims := jwt.MapClaims{"iss": c.Issuer, "aud": "https://resource.example/mcp", "sub": "reader", "user_id": 7, "account_id": 21, "exp": time.Now().Add(time.Minute).Unix()}
			key := f.key
			cryptographic := false
			switch mode {
			case "issuer":
				claims["iss"] = "https://other.example"
				cryptographic = true
			case "signature":
				key, err = rsa.GenerateKey(rand.Reader, 2048)
				if err != nil {
					t.Fatal(err)
				}
				cryptographic = true
			case "expired":
				claims["exp"] = time.Now().Add(-time.Minute).Unix()
				cryptographic = true
			case "missing-expiry":
				delete(claims, "exp")
				cryptographic = true
			case "missing-subject":
				delete(claims, "sub")
				cryptographic = true
			case "account":
				claims["account_id"] = 22
			case "userinfo-subject":
				f.info["subject"] = "other"
			case "userinfo-account":
				f.info["accountId"] = 22
			case "expired-source":
				f.info["evaluatedAt"] = time.Now().Add(-time.Minute).Format(time.RFC3339Nano)
				f.info["validUntil"] = time.Now().Add(-time.Second).Format(time.RFC3339Nano)
			case "unavailable":
				f.server.Close()
			}
			token, err := jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(key)
			if err != nil {
				t.Fatal(err)
			}
			_, err = p.Identity.ResolvePrincipal(WithBearer(context.Background(), token))
			want := authz.ErrDenied
			if mode == "unavailable" {
				want = authz.ErrUnavailable
			}
			if !errors.Is(err, want) {
				t.Fatalf("want %v, got %v", want, err)
			}
			if cryptographic && f.userinfoCalls.Load() != 0 {
				t.Fatal("unverified credential reached identity endpoint")
			}
		})
	}
}
