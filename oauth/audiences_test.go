package oauth

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"github.com/golang-jwt/jwt/v5"
	"testing"
	"time"
)

func TestIdentityAllowsConfiguredAudiences(t *testing.T) {
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, legacy := range []string{"", "original"} {
		config := Config{Issuer: "https://issuer.example", Audience: legacy, Audiences: []string{"first", "second"}, Algorithms: []string{"EdDSA"}, Keyfunc: func(*jwt.Token) (any, error) { return pub, nil }}
		provider, err := NewIdentity(config)
		if err != nil {
			t.Fatal(err)
		}
		config.Audiences[0] = "mutated"
		for _, tc := range []struct {
			name   string
			aud    any
			issuer string
			expiry time.Time
			allow  bool
		}{
			{"first", "first", config.Issuer, time.Now().Add(time.Minute), true},
			{"second", "second", config.Issuer, time.Now().Add(time.Minute), true},
			{"legacy", "original", config.Issuer, time.Now().Add(time.Minute), legacy != ""},
			{"array", []string{"other", "second"}, config.Issuer, time.Now().Add(time.Minute), true},
			{"unknown", "other", config.Issuer, time.Now().Add(time.Minute), false},
			{"missing", nil, config.Issuer, time.Now().Add(time.Minute), false},
			{"mutated", "mutated", config.Issuer, time.Now().Add(time.Minute), false},
			{"issuer", "first", "https://wrong.example", time.Now().Add(time.Minute), false},
			{"expired", "first", config.Issuer, time.Now().Add(-time.Minute), false},
		} {
			t.Run(legacy+"/"+tc.name, func(t *testing.T) {
				claims := jwt.MapClaims{"iss": tc.issuer, "sub": "reader", "exp": tc.expiry.Unix()}
				if tc.aud != nil {
					claims["aud"] = tc.aud
				}
				token, err := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims).SignedString(key)
				if err != nil {
					t.Fatal(err)
				}
				_, err = provider.Resolve(WithBearer(context.Background(), token))
				if (err == nil) != tc.allow {
					t.Fatalf("allowed=%v error=%v", tc.allow, err)
				}
			})
		}
	}
	for _, audiences := range [][]string{nil, {""}, {"first", " "}} {
		_, err := New(Config{Issuer: "issuer", Audiences: audiences, Algorithms: []string{"EdDSA"}, Keyfunc: func(*jwt.Token) (any, error) { return pub, nil }})
		if err == nil {
			t.Fatalf("invalid audiences accepted: %q", audiences)
		}
	}
}
