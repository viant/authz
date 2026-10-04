package oauth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func rsaJWK(key *rsa.PrivateKey, kid string) map[string]string {
	exponent := big.NewInt(int64(key.PublicKey.E)).Bytes()
	return map[string]string{"kty": "RSA", "kid": kid, "alg": "RS256", "use": "sig", "n": base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(exponent)}
}

func TestJWKSKeyfuncVerifiesRotationAndRejectsStaleKeys(t *testing.T) {
	first, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	second, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	current := []map[string]string{rsaJWK(first, "first")}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			t.Fatal("JWT credential sent to JWKS endpoint")
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": current})
	}))
	defer server.Close()
	now := time.Now()
	keyfunc, err := NewJWKSKeyfunc(JWKSConfig{URL: server.URL, RefreshInterval: 10 * time.Millisecond, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	signed := func(kid string, key *rsa.PrivateKey) string {
		token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.RegisteredClaims{Subject: "alice", ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Minute))})
		token.Header["kid"] = kid
		value, err := token.SignedString(key)
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	verify := func(raw string) error {
		_, err := jwt.Parse(raw, keyfunc, jwt.WithValidMethods([]string{"RS256"}))
		return err
	}
	if err := verify(signed("first", first)); err != nil {
		t.Fatalf("first key: %v", err)
	}
	current = []map[string]string{rsaJWK(second, "second")}
	if err := verify(signed("second", second)); err == nil {
		t.Fatal("unknown key bypassed configured refresh lease")
	}
	now = now.Add(20 * time.Millisecond)
	if err := verify(signed("second", second)); err != nil {
		t.Fatalf("rotated key: %v", err)
	}
	now = now.Add(20 * time.Millisecond)
	if err := verify(signed("first", first)); err == nil {
		t.Fatal("revoked key remained accepted beyond JWKS lease")
	}
}

func TestJWKSKeyfuncRejectsUnsafeEndpointRedirectAndDuplicateKeys(t *testing.T) {
	if _, err := NewJWKSKeyfunc(JWKSConfig{URL: "http://identity.example/jwks", RefreshInterval: time.Minute}); err == nil {
		t.Fatal("non-TLS remote JWKS accepted")
	}
	if _, err := NewJWKSKeyfunc(JWKSConfig{URL: "https://identity.example/jwks", RefreshInterval: 0}); err == nil {
		t.Fatal("unbounded key lease accepted")
	}
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	other := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("JWKS redirect followed") }))
	defer other.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, other.URL, http.StatusFound) }))
	defer redirect.Close()
	keyfunc, err := NewJWKSKeyfunc(JWKSConfig{URL: redirect.URL, RefreshInterval: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	token := jwt.New(jwt.SigningMethodRS256)
	token.Header["kid"] = "first"
	if _, err := keyfunc(token); err == nil {
		t.Fatal("redirected JWKS was accepted")
	}
	duplicate := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{rsaJWK(key, "same"), rsaJWK(key, "same")}})
	}))
	defer duplicate.Close()
	keyfunc, err = NewJWKSKeyfunc(JWKSConfig{URL: duplicate.URL, RefreshInterval: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := keyfunc(token); err == nil {
		t.Fatal("duplicate key ID was accepted")
	}
}

func TestAccountUserInfoUsesConfiguredJWKSAndVerifiedProfile(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	userinfoCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/jwks":
			if r.Header.Get("Authorization") != "" {
				t.Fatal("credential forwarded to JWKS")
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{rsaJWK(key, "current")}})
		case "/userinfo":
			userinfoCalls++
			if r.Header.Get("Authorization") == "" {
				t.Fatal("user-info missing verified bearer")
			}
			_, _ = w.Write([]byte(`{"status":"ok","info":{"subject":"alice","userId":7,"accountId":21,"roles":["reader"],"features":["FEATURE"],"entityPermissions":[]}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	config := AccountUserInfoConfig{Issuer: server.URL, Audience: "host", Algorithms: []string{"RS256"}, JWKSURL: server.URL + "/jwks", JWKSRefreshInterval: time.Minute, UserInfoURL: server.URL + "/userinfo", FactLease: time.Minute, TenantByAccount: map[int]string{21: "tenant"}}
	provider, err := NewConfiguredAccountUserInfo(config)
	if err != nil {
		t.Fatal(err)
	}
	config.TenantByAccount[21] = "forged"
	claims := userInfoClaims{RegisteredClaims: jwt.RegisteredClaims{Issuer: server.URL, Audience: []string{"host"}, Subject: "alice", ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour))}, UserID: 7, AccountID: 21}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = "current"
	raw, err := token.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	principal, err := provider.ResolvePrincipal(WithBearer(context.Background(), raw))
	if err != nil || principal.AccountID != "21" || principal.Facts.Tenant != "tenant" || principal.Facts.Roles[0] != "reader" || principal.Facts.Exposures[0] != "FEATURE" || userinfoCalls != 1 {
		t.Fatalf("verified principal=%+v calls=%d err=%v", principal, userinfoCalls, err)
	}
	claims.Audience = []string{"other"}
	bad := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	bad.Header["kid"] = "current"
	raw, err = bad.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provider.ResolvePrincipal(WithBearer(context.Background(), raw)); err == nil || userinfoCalls != 1 {
		t.Fatalf("wrong audience reached user-info: calls=%d err=%v", userinfoCalls, err)
	}
}
