package oauth

import (
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
