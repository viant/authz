package oauth

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// JWKSConfig is deployment-owned. The configured URL is never selected by a
// token, caller payload or user-info response.
type JWKSConfig struct {
	URL             string
	RefreshInterval time.Duration
	Client          *http.Client
	Now             func() time.Time
}

type jwkKey struct {
	public    any
	algorithm string
}
type jwksKeyfunc struct {
	url             string
	client          *http.Client
	refreshInterval time.Duration
	now             func() time.Time
	mu              sync.Mutex
	keys            map[string]jwkKey
	loadedAt        time.Time
}

// NewJWKSKeyfunc resolves asymmetric verification keys from a trusted issuer
// endpoint. It refreshes on the configured lease; an untrusted unknown key ID
// cannot force a network fetch on every request. Failed refreshes discard the
// old key set.
func NewJWKSKeyfunc(config JWKSConfig) (jwt.Keyfunc, error) {
	endpoint, err := url.Parse(config.URL)
	if err != nil || endpoint.Host == "" || endpoint.User != nil || endpoint.Fragment != "" || endpoint.RawQuery != "" || (endpoint.Scheme != "https" && !(endpoint.Scheme == "http" && loopbackHost(endpoint.Hostname()))) {
		return nil, errors.New("JWKS URL requires HTTPS or loopback HTTP without credentials or query")
	}
	if config.RefreshInterval <= 0 {
		return nil, errors.New("positive JWKS refresh interval is required")
	}
	client := http.Client{Timeout: 5 * time.Second}
	if config.Client != nil {
		client = *config.Client
		if client.Timeout == 0 {
			client.Timeout = 5 * time.Second
		}
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	now := config.Now
	if now == nil {
		now = time.Now
	}
	resolver := &jwksKeyfunc{url: config.URL, client: &client, refreshInterval: config.RefreshInterval, now: now}
	return resolver.key, nil
}

func (r *jwksKeyfunc) key(token *jwt.Token) (any, error) {
	if token == nil {
		return nil, errors.New("JWT is required")
	}
	kid, ok := token.Header["kid"].(string)
	if !ok || kid == "" || strings.TrimSpace(kid) != kid {
		return nil, errors.New("JWT key ID is required")
	}
	algorithm := token.Method.Alg()
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.keys == nil || r.now().Sub(r.loadedAt) >= r.refreshInterval {
		keys, err := r.fetch()
		if err != nil {
			r.keys = nil
			return nil, err
		}
		r.keys, r.loadedAt = keys, r.now()
	}
	key, ok := r.keys[kid]
	if !ok || key.public == nil {
		return nil, errors.New("JWT key ID is unknown")
	}
	if key.algorithm != "" && key.algorithm != algorithm {
		return nil, errors.New("JWT algorithm does not match JWKS key")
	}
	return key.public, nil
}

func (r *jwksKeyfunc) fetch() (map[string]jwkKey, error) {
	request, err := http.NewRequestWithContext(context.Background(), http.MethodGet, r.url, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", "application/json")
	response, err := r.client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("JWKS fetch failed: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, errors.New("JWKS endpoint is unavailable")
	}
	const maxJWKSBytes = 256 << 10
	raw, err := io.ReadAll(io.LimitReader(response.Body, maxJWKSBytes+1))
	if err != nil || len(raw) > maxJWKSBytes {
		return nil, errors.New("JWKS response is invalid")
	}
	root, err := uniqueObject(raw)
	if err != nil {
		return nil, errors.New("JWKS response is invalid")
	}
	var entries []json.RawMessage
	if json.Unmarshal(root["keys"], &entries) != nil || len(entries) == 0 {
		return nil, errors.New("JWKS has no keys")
	}
	keys := make(map[string]jwkKey, len(entries))
	for _, entry := range entries {
		fields, err := uniqueObject(entry)
		if err != nil {
			return nil, errors.New("JWKS key is invalid")
		}
		kid, err := jwkString(fields, "kid")
		if err != nil || kid == "" || strings.TrimSpace(kid) != kid || keys[kid].public != nil {
			return nil, errors.New("JWKS key ID is invalid or duplicate")
		}
		if usage, exists := fields["use"]; exists {
			var value string
			if json.Unmarshal(usage, &value) != nil || value != "sig" {
				return nil, errors.New("JWKS key is not for signatures")
			}
		}
		algorithm := ""
		if rawAlg, exists := fields["alg"]; exists {
			if json.Unmarshal(rawAlg, &algorithm) != nil || algorithm == "" {
				return nil, errors.New("JWKS algorithm is invalid")
			}
		}
		public, err := parseJWK(fields)
		if err != nil {
			return nil, err
		}
		keys[kid] = jwkKey{public: public, algorithm: algorithm}
	}
	return keys, nil
}

func jwkString(fields map[string]json.RawMessage, name string) (string, error) {
	var value string
	if raw, ok := fields[name]; !ok || json.Unmarshal(raw, &value) != nil {
		return "", errors.New("JWKS key field is invalid")
	}
	return value, nil
}

func jwkBytes(fields map[string]json.RawMessage, name string) ([]byte, error) {
	value, err := jwkString(fields, name)
	if err != nil || value == "" {
		return nil, errors.New("JWKS key material is missing")
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(decoded) == 0 {
		return nil, errors.New("JWKS key material is invalid")
	}
	return decoded, nil
}

func parseJWK(fields map[string]json.RawMessage) (any, error) {
	kind, err := jwkString(fields, "kty")
	if err != nil {
		return nil, err
	}
	switch kind {
	case "RSA":
		n, err := jwkBytes(fields, "n")
		if err != nil {
			return nil, err
		}
		e, err := jwkBytes(fields, "e")
		if err != nil {
			return nil, err
		}
		if len(e) > 4 {
			return nil, errors.New("JWKS RSA exponent is invalid")
		}
		exponent := uint64(0)
		for _, digit := range e {
			exponent = exponent<<8 | uint64(digit)
		}
		if exponent < 3 || exponent%2 == 0 || exponent > 1<<31-1 {
			return nil, errors.New("JWKS RSA exponent is invalid")
		}
		modulus := new(big.Int).SetBytes(n)
		if modulus.BitLen() < 2048 {
			return nil, errors.New("JWKS RSA modulus is too short")
		}
		return &rsa.PublicKey{N: modulus, E: int(exponent)}, nil
	case "EC":
		curveName, err := jwkString(fields, "crv")
		if err != nil {
			return nil, err
		}
		var curve elliptic.Curve
		switch curveName {
		case "P-256":
			curve = elliptic.P256()
		case "P-384":
			curve = elliptic.P384()
		case "P-521":
			curve = elliptic.P521()
		default:
			return nil, errors.New("JWKS curve is unsupported")
		}
		x, err := jwkBytes(fields, "x")
		if err != nil {
			return nil, err
		}
		y, err := jwkBytes(fields, "y")
		if err != nil {
			return nil, err
		}
		pointX, pointY := new(big.Int).SetBytes(x), new(big.Int).SetBytes(y)
		if !curve.IsOnCurve(pointX, pointY) {
			return nil, errors.New("JWKS EC point is invalid")
		}
		return &ecdsa.PublicKey{Curve: curve, X: pointX, Y: pointY}, nil
	case "OKP":
		curve, err := jwkString(fields, "crv")
		if err != nil || curve != "Ed25519" {
			return nil, errors.New("JWKS OKP curve is unsupported")
		}
		x, err := jwkBytes(fields, "x")
		if err != nil || len(x) != ed25519.PublicKeySize {
			return nil, errors.New("JWKS Ed25519 key is invalid")
		}
		return ed25519.PublicKey(x), nil
	default:
		return nil, errors.New("JWKS key type is unsupported")
	}
}
