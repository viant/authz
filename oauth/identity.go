package oauth

import (
	"context"
	"encoding/base64"
	"net"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/viant/authz"
)

// Bearer returns the unverified request credential. Only a trusted verifier may
// interpret it; possession of this context value never establishes authority.
func Bearer(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	token, _ := ctx.Value(tokenKey{}).(string)
	return token
}

// VerifyToken validates the generic signed OAuth/OIDC credential contract.
// The caller supplies the claim type; provider-specific claims remain host code.
func VerifyToken(ctx context.Context, config Config, claims jwt.Claims) (string, error) {
	if ctx == nil || ctx.Err() != nil || claims == nil {
		return "", authz.ErrDenied
	}
	verifier, err := New(config)
	if err != nil {
		return "", authz.ErrDenied
	}
	bearer := Bearer(ctx)
	parts := strings.Split(bearer, ".")
	if len(parts) != 3 {
		return "", authz.ErrDenied
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || validateUniqueJSON(payload) != nil {
		return "", authz.ErrDenied
	}
	if _, err := uniqueObject(payload); err != nil {
		return "", authz.ErrDenied
	}
	_, err = jwt.ParseWithClaims(bearer, claims, verifier.config.Keyfunc, jwt.WithValidMethods(verifier.config.Algorithms), jwt.WithIssuer(verifier.config.Issuer), jwt.WithAudience(verifier.config.Audience), jwt.WithExpirationRequired(), jwt.WithIssuedAt())
	if err != nil {
		return "", authz.ErrDenied
	}
	subject, err := claims.GetSubject()
	if err != nil || subject == "" {
		return "", authz.ErrDenied
	}
	expiry, err := claims.GetExpirationTime()
	if err != nil || expiry == nil || !expiry.After(time.Now()) {
		return "", authz.ErrDenied
	}
	return bearer, nil
}

// IdentityProvider supplies verified registered identity claims only. It grants
// no tenant membership, roles, exposures, or entity authority.
type IdentityProvider struct{ config Config }

func NewIdentity(config Config) (*IdentityProvider, error) {
	verifier, err := New(config)
	if err != nil {
		return nil, err
	}
	return &IdentityProvider{config: verifier.config}, nil
}
func (p *IdentityProvider) Resolve(ctx context.Context) (authz.Facts, error) {
	if p == nil {
		return authz.Facts{}, authz.ErrDenied
	}
	claims := &jwt.RegisteredClaims{}
	if _, err := VerifyToken(ctx, p.config, claims); err != nil {
		return authz.Facts{}, err
	}
	return authz.Facts{Subject: claims.Subject, Issuer: claims.Issuer, ValidUntil: claims.ExpiresAt.Time}, nil
}
func loopbackHost(host string) bool {
	return strings.EqualFold(host, "localhost") || net.ParseIP(host) != nil && net.ParseIP(host).IsLoopback()
}
