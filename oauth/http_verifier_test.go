package oauth

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

func TestHTTPIdentityUsesTrustedVerifier(t *testing.T) {
	fixture := newAuthorityHTTPFixture(t)
	config := fixture.config()
	config.JWKSURL = ""
	calls := 0
	config.Keyfunc = func(*jwt.Token) (any, error) { calls++; return &fixture.key.PublicKey, nil }
	providers, err := NewHTTPProviders(context.Background(), config, nil)
	if err != nil {
		t.Fatal(err)
	}
	token := fixture.token(t, 21, fixture.server.URL, config.Audience)
	if _, err = providers.Identity.Resolve(WithBearer(context.Background(), token)); err != nil {
		t.Fatal(err)
	}
	if calls == 0 {
		t.Fatal("injected verifier was not used")
	}
	// A JSON document cannot install executable verifier behavior.
	raw, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	var decoded HTTPIdentityConfig
	if err = json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Keyfunc != nil {
		t.Fatal("trusted verifier serialized into configuration")
	}
	config.JWKSURL = fixture.server.URL + "/jwks"
	if _, err = NewHTTPProviders(context.Background(), config, nil); err == nil {
		t.Fatal("ambiguous verifier sources accepted")
	}
}
