package oauth

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/viant/authz"
)

func TestIdentityProjectionRequiresExplicitRequestAndSourceLease(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	evaluatedAt := time.Now().UTC().Add(-4 * time.Minute)
	sourceExpiry := evaluatedAt.Add(5 * time.Minute)
	info := map[string]any{"subject": "alice", "userId": 7, "accountId": 21, "roles": []string{"reader"}, "features": []string{}, "evaluatedAt": evaluatedAt, "validUntil": sourceExpiry}
	projected := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		projected = r.URL.Query().Get("includeEntityPermissions") == "false"
		json.NewEncoder(w).Encode(map[string]any{"status": "ok", "info": info})
	}))
	defer server.Close()
	config := UserInfoConfig{Issuer: "issuer", Audience: "audience", Algorithms: []string{"EdDSA"}, Keyfunc: func(*jwt.Token) (any, error) { return public, nil }, URL: server.URL, FactLease: 5 * time.Minute, OmitEntityPermissions: true}
	token, _ := jwt.NewWithClaims(jwt.SigningMethodEdDSA, &userInfoClaims{RegisteredClaims: jwt.RegisteredClaims{Issuer: "issuer", Audience: []string{"audience"}, Subject: "alice", ExpiresAt: jwt.NewNumericDate(time.Now().Add(30 * time.Minute))}, UserID: 7, AccountID: 21}).SignedString(private)
	ctx := WithBearer(context.Background(), token)
	provider, err := NewUserInfo(config)
	if err != nil {
		t.Fatal(err)
	}
	facts, err := provider.Resolve(ctx)
	if err != nil || !projected || facts.EntityGroups != nil || facts.EntityPermissions != nil || !facts.ValidUntil.Equal(sourceExpiry) {
		t.Fatalf("projected facts=%+v request=%v err=%v", facts, projected, err)
	}
	// Existing defaults still reject omitted lists; no arbitrary response can
	// turn absent authority into an empty or unbounded grant.
	config.OmitEntityPermissions = false
	strict, _ := NewUserInfo(config)
	if _, err = strict.Resolve(ctx); !errors.Is(err, authz.ErrDenied) {
		t.Fatalf("default accepted missing grants: %v", err)
	}
	delete(info, "evaluatedAt")
	delete(info, "validUntil")
	if _, err = provider.Resolve(ctx); !errors.Is(err, authz.ErrDenied) {
		t.Fatalf("projection accepted unknown source freshness: %v", err)
	}
}
func TestUserInfoLeaseCannotRestartFromCachedSource(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	start := time.Now().UTC().Add(-4 * time.Minute)
	expiry := start.Add(5 * time.Minute)
	info := map[string]any{"subject": "alice", "userId": 7, "accountId": 21, "roles": []string{}, "features": []string{}, "entityPermissions": []any{}, "evaluatedAt": start, "validUntil": expiry}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"status": "ok", "info": info})
	}))
	defer server.Close()
	config := UserInfoConfig{Issuer: "issuer", Audience: "audience", Algorithms: []string{"EdDSA"}, Keyfunc: func(*jwt.Token) (any, error) { return public, nil }, URL: server.URL, FactLease: 5 * time.Minute}
	provider, _ := NewUserInfo(config)
	token, _ := jwt.NewWithClaims(jwt.SigningMethodEdDSA, &userInfoClaims{RegisteredClaims: jwt.RegisteredClaims{Issuer: "issuer", Audience: []string{"audience"}, Subject: "alice", ExpiresAt: jwt.NewNumericDate(time.Now().Add(30 * time.Minute))}, UserID: 7, AccountID: 21}).SignedString(private)
	ctx := WithBearer(context.Background(), token)
	for i := 0; i < 2; i++ {
		facts, err := provider.Resolve(ctx)
		if err != nil || !facts.ValidUntil.Equal(expiry) {
			t.Fatalf("source lease extended %+v %v", facts, err)
		}
	}
	info["validUntil"] = time.Now().Add(-time.Second)
	if _, err := provider.Resolve(ctx); !errors.Is(err, authz.ErrDenied) {
		t.Fatalf("expired source accepted %v", err)
	}
	info["evaluatedAt"] = time.Now().Add(time.Minute)
	info["validUntil"] = time.Now().Add(2 * time.Minute)
	if _, err := provider.Resolve(ctx); !errors.Is(err, authz.ErrDenied) {
		t.Fatalf("future source evaluation accepted %v", err)
	}
}
