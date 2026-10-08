package oauth

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/viant/authz"
)

func TestRegisteredIdentityIsProviderIndependentAndGrantsNoAuthority(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	config := Config{Issuer: "https://generic.example", Audience: "host", Algorithms: []string{"EdDSA"}, Keyfunc: func(*jwt.Token) (any, error) { return public, nil }}
	provider, err := NewIdentity(config)
	if err != nil {
		t.Fatal(err)
	}
	claims := jwt.MapClaims{"iss": config.Issuer, "aud": config.Audience, "sub": "opaque:person/abc", "exp": time.Now().Add(time.Minute).Unix(), "roles": []string{"admin"}, "account_id": 99, "tenant": "spoof"}
	sign := func() string {
		token, err := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims).SignedString(private)
		if err != nil {
			t.Fatal(err)
		}
		return token
	}
	facts, err := provider.Resolve(WithBearer(context.Background(), sign()))
	if err != nil || facts.Subject != "opaque:person/abc" || facts.Tenant != "" || len(facts.Roles) != 0 || len(facts.Entities) != 0 || len(facts.EntityPermissions) != 0 {
		t.Fatalf("unexpected identity: %+v %v", facts, err)
	}
	for _, mutate := range []func(){func() { claims["iss"] = "wrong" }, func() { claims["iss"] = config.Issuer; claims["aud"] = "wrong" }, func() { claims["aud"] = config.Audience; claims["exp"] = time.Now().Add(-time.Minute).Unix() }} {
		mutate()
		if _, err := provider.Resolve(WithBearer(context.Background(), sign())); err != authz.ErrDenied {
			t.Fatalf("invalid credential accepted: %v", err)
		}
	}
}
func TestVerifyTokenRejectsDuplicateRegisteredClaims(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	config := Config{Issuer: "issuer", Audience: "host", Algorithms: []string{"EdDSA"}, Keyfunc: func(*jwt.Token) (any, error) { return public, nil }}
	// Raw claims exercise signed duplicate keys that ordinary map serialization removes.
	token, err := jwt.NewWithClaims(jwt.SigningMethodEdDSA, duplicateIdentityClaims{RegisteredClaims: jwt.RegisteredClaims{Issuer: "issuer", Audience: []string{"host"}, Subject: "alice", ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Minute))}}).SignedString(private)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyToken(WithBearer(context.Background(), token), config, &jwt.RegisteredClaims{}); err != authz.ErrDenied {
		t.Fatalf("ambiguous identity accepted: %v", err)
	}
}

type duplicateIdentityClaims struct{ jwt.RegisteredClaims }

func (c duplicateIdentityClaims) MarshalJSON() ([]byte, error) {
	raw, err := json.Marshal(c.RegisteredClaims)
	if err != nil {
		return nil, err
	}
	return append(raw[:len(raw)-1], []byte(`,"sub":"other"}`)...), nil
}
