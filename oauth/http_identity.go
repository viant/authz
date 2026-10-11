package oauth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"github.com/viant/authz"
	"github.com/viant/authz/gating"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"time"
)

type HTTPIdentityProvider struct {
	config      HTTPIdentityConfig
	verifier    Config
	client      *http.Client
	lease, skew time.Duration
}
type httpProfile struct {
	principal  gating.Principal
	userID     string
	projection map[string]any
	bearerHash string
}

func NewHTTPProviders(ctx context.Context, c HTTPIdentityConfig, e *HTTPEvaluationConfig) (HTTPProviders, error) {
	if ctx == nil || ctx.Err() != nil {
		return HTTPProviders{}, authz.ErrDenied
	}
	p, err := newHTTPIdentity(c)
	if err != nil {
		return HTTPProviders{}, err
	}
	out := HTTPProviders{Identity: p, NativeWindowIdentity: p.ResolveIdentityPrincipal, AccountProjection: p.ProjectAccount, DecisionScope: p, MetadataScope: p, AllowsTenant: p.allowsTenant}
	if e != nil {
		client, err := newHTTPEvaluation(p, *e)
		if err != nil {
			return HTTPProviders{}, err
		}
		out.EntityPermissions = client
		out.PermissionWithLease = client.PermissionWithLease
		out.Entitlements = map[string]gating.EntitlementProvider{}
		if e.EntitlementProviderRef != "" {
			out.Entitlements[e.EntitlementProviderRef] = client
		}
	} else if c.Mapping.EntityPermissions != "" {
		out.EntityPermissions = &FactEntityPermissionProvider{Principals: p}
		out.PermissionWithLease = p.PermissionWithLease
	}
	return out, nil
}
func newHTTPIdentity(c HTTPIdentityConfig) (*HTTPIdentityProvider, error) {
	if c.Kind != "oidc-userinfo" {
		return nil, fmt.Errorf("identity kind must be oidc-userinfo")
	}
	if _, e := httpEndpoint(c.UserInfoURL); e != nil {
		return nil, e
	}
	lease, e := time.ParseDuration(c.FactLease)
	if e != nil || lease <= 0 || lease > 5*time.Minute {
		return nil, fmt.Errorf("factLease must be positive and at most five minutes")
	}
	refresh, e := time.ParseDuration(c.JWKSRefreshInterval)
	if e != nil || refresh <= 0 {
		return nil, fmt.Errorf("positive JWKS refresh required")
	}
	skew := time.Duration(0)
	if c.SourceClockSkew != "" {
		skew, e = time.ParseDuration(c.SourceClockSkew)
		if e != nil || skew < 0 || skew > 5*time.Second {
			return nil, fmt.Errorf("source clock skew must be zero to five seconds")
		}
	}
	if (len(c.TenantByAccount) == 0) == (c.TenantForAllAccounts == "") {
		return nil, fmt.Errorf("one explicit tenant mapping required")
	}
	c.TenantByAccount = copyHTTPMap(c.TenantByAccount)
	for account, tenant := range c.TenantByAccount {
		if account == "" || !validTenantHTTP(tenant) {
			return nil, fmt.Errorf("invalid tenant mapping")
		}
	}
	if c.TenantForAllAccounts != "" && !validTenantHTTP(c.TenantForAllAccounts) {
		return nil, fmt.Errorf("invalid shared tenant")
	}
	m := c.Mapping
	if !validHTTPPath(m.Subject) || !validHTTPPath(m.AccountID) || (m.UserID == "") != (m.JWTUserID == "") || (m.EvaluatedAt == "") != (m.ValidUntil == "") {
		return nil, fmt.Errorf("explicit subject/account and paired user/source mappings required")
	}
	for _, path := range []string{m.UserID, m.JWTUserID, m.JWTAccountID, m.Roles, m.Exposures, m.MembershipGroups, m.EntityPermissions, m.Status, m.AuthorityRevision, m.EvaluatedAt, m.ValidUntil} {
		if path != "" && !validHTTPPath(path) {
			return nil, fmt.Errorf("invalid identity mapping path")
		}
	}
	if m.RequireSourceLease && m.EvaluatedAt == "" {
		return nil, fmt.Errorf("required source lease paths missing")
	}
	if (m.Status == "") != (m.StatusValue == "") {
		return nil, fmt.Errorf("status mapping/value must be paired")
	}
	m.AccountProjection = copyHTTPMap(m.AccountProjection)
	for name, path := range m.AccountProjection {
		if name == "" || name == "id" || strings.TrimSpace(name) != name || !validHTTPPath(path) {
			return nil, fmt.Errorf("invalid display projection mapping")
		}
	}
	c.Mapping = m
	c.Query = copyHTTPMap(c.Query)
	for key := range c.Query {
		if key == "" {
			return nil, fmt.Errorf("invalid identity query key")
		}
	}
	key, e := NewJWKSKeyfunc(JWKSConfig{URL: c.JWKSURL, RefreshInterval: refresh, Client: c.Client})
	if e != nil {
		return nil, e
	}
	verifier := Config{Issuer: c.Issuer, Audience: c.Audience, Algorithms: append([]string(nil), c.Algorithms...), Keyfunc: key}
	if _, e = New(verifier); e != nil {
		return nil, e
	}
	return &HTTPIdentityProvider{config: c, verifier: verifier, client: authorityClient(c.Client), lease: lease, skew: skew}, nil
}
func copyHTTPMap(in map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range in {
		out[k] = v
	}
	return out
}
func validTenantHTTP(t string) bool { return t != "" && t != "*" && strings.TrimSpace(t) == t }
func (p *HTTPIdentityProvider) allowsTenant(t string) bool {
	if t == "*" {
		return true
	}
	if p.config.TenantForAllAccounts == t {
		return true
	}
	for _, v := range p.config.TenantByAccount {
		if v == t {
			return true
		}
	}
	return false
}
func (p *HTTPIdentityProvider) claims(ctx context.Context) (*jwt.RegisteredClaims, json.RawMessage, string, error) {
	if p == nil {
		return nil, nil, "", authz.ErrDenied
	}
	claims := &jwt.RegisteredClaims{}
	bearer, e := VerifyToken(ctx, p.verifier, claims)
	if e != nil || ctx.Err() != nil {
		return nil, nil, "", authz.ErrDenied
	}
	parts := strings.Split(bearer, ".")
	raw, e := decodeHTTPJWT(parts[1])
	if e != nil {
		return nil, nil, "", authz.ErrDenied
	}
	return claims, raw, bearer, nil
}
func (p *HTTPIdentityProvider) readProfile(ctx context.Context) (httpProfile, error) {
	claims, signed, bearer, e := p.claims(ctx)
	if e != nil {
		return httpProfile{}, e
	}
	started := time.Now()
	u, _ := url.Parse(p.config.UserInfoURL)
	q := u.Query()
	for k, v := range p.config.Query {
		q.Set(k, v)
	}
	u.RawQuery = q.Encode()
	req, e := http.NewRequestWithContext(ctx, "GET", u.String(), nil)
	if e != nil {
		return httpProfile{}, authz.ErrUnavailable
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Cache-Control", "no-cache")
	resp, e := p.client.Do(req)
	if e != nil {
		return httpProfile{}, authz.ErrUnavailable
	}
	raw, e := decodeHTTPBody(resp, 64<<10)
	if e != nil {
		return httpProfile{}, e
	}
	m := p.config.Mapping
	if m.Status != "" {
		status, e := stringAt(raw, m.Status)
		if e != nil || status != m.StatusValue {
			return httpProfile{}, authz.ErrDenied
		}
	}
	sub, e := stringAt(raw, m.Subject)
	if e != nil || sub != claims.Subject {
		return httpProfile{}, authz.ErrDenied
	}
	account, e := idAt(raw, m.AccountID)
	if e != nil {
		return httpProfile{}, e
	}
	if m.JWTAccountID != "" {
		a, e := idAt(signed, m.JWTAccountID)
		if e != nil || a != account {
			return httpProfile{}, authz.ErrDenied
		}
	}
	user := ""
	if m.UserID != "" {
		user, e = idAt(raw, m.UserID)
		if e != nil {
			return httpProfile{}, e
		}
		expected, e := idAt(signed, m.JWTUserID)
		if e != nil || user != expected {
			return httpProfile{}, authz.ErrDenied
		}
	}
	tenant := p.config.TenantForAllAccounts
	if tenant == "" {
		tenant = p.config.TenantByAccount[account]
	}
	if tenant == "" {
		return httpProfile{}, authz.ErrDenied
	}
	roles, e := stringsAt(raw, m.Roles)
	if e != nil {
		return httpProfile{}, e
	}
	exposures, e := stringsAt(raw, m.Exposures)
	if e != nil {
		return httpProfile{}, e
	}
	groups, e := stringsAt(raw, m.MembershipGroups)
	if e != nil {
		return httpProfile{}, e
	}
	var permissions []authz.EntityPermission
	entities := authz.EntityGroups(nil)
	if m.EntityPermissions != "" {
		v, e := requiredHTTPPath(raw, m.EntityPermissions)
		if e != nil {
			return httpProfile{}, authz.ErrDenied
		}
		var records []json.RawMessage
		if json.Unmarshal(v, &records) != nil || records == nil {
			return httpProfile{}, authz.ErrDenied
		}
		permissions = make([]authz.EntityPermission, 0, len(records))
		for _, record := range records {
			object, err := uniqueObject(record)
			if err != nil || len(object) != 3 {
				return httpProfile{}, authz.ErrDenied
			}
			for _, key := range []string{"type", "id", "permissions"} {
				if _, found := object[key]; !found {
					return httpProfile{}, authz.ErrDenied
				}
			}
			var grant authz.EntityPermission
			if json.Unmarshal(record, &grant) != nil {
				return httpProfile{}, authz.ErrDenied
			}
			permissions = append(permissions, grant)
		}
		if authz.ValidateEntityPermissions(permissions) != nil {
			return httpProfile{}, authz.ErrDenied
		}
		entities = authz.EntityGroups{}
		for _, grant := range permissions {
			if grant.Type == "" || grant.ID == "" || len(grant.Permissions) == 0 {
				return httpProfile{}, authz.ErrDenied
			}
			entities[grant.Type] = append(entities[grant.Type], grant.ID)
		}
		if _, e = authz.NormalizeEntityGroups(entities); e != nil {
			return httpProfile{}, authz.ErrDenied
		}
	}
	sourceRevision := ""
	if m.AuthorityRevision != "" {
		v, found, e := rawHTTPPath(raw, m.AuthorityRevision)
		if e != nil {
			return httpProfile{}, e
		}
		if found {
			sourceRevision, e = httpString(v)
			if e != nil {
				return httpProfile{}, e
			}
		}
	}
	projection := map[string]any{"id": account}
	for name, path := range m.AccountProjection {
		v, e := requiredHTTPPath(raw, path)
		if e != nil {
			return httpProfile{}, e
		}
		decoder := json.NewDecoder(bytes.NewReader(v))
		decoder.UseNumber()
		var value any
		if decoder.Decode(&value) != nil {
			return httpProfile{}, authz.ErrDenied
		}
		projection[name] = value
	}
	deadline, e := deadlineHTTP(started, time.Now(), claims.ExpiresAt.Time, p.lease, p.skew, raw, m.EvaluatedAt, m.ValidUntil, m.RequireSourceLease)
	if e != nil {
		return httpProfile{}, e
	}
	facts := authz.Facts{Subject: sub, Issuer: claims.Issuer, Tenant: tenant, Roles: roles, Exposures: exposures, EntityGroups: entities, EntityPermissions: permissions, ValidUntil: deadline}
	principal := gating.Principal{Facts: facts, AccountID: account, MembershipGroups: groups}
	// Authority revision describes verified identity/facts. Credential freshness
	// and decision/cache isolation remain independently bound to bearerHash.
	revision := hashHTTP(struct {
		User, Account, Source string
		Facts                 authz.Facts
		Groups                []string
		Projection            map[string]any
	}{user, account, sourceRevision, withoutHTTPDeadline(facts), groups, projection})
	principal.IdentityRevision = revision
	principal.Facts.AuthorityRevision = revision
	if ctx.Err() != nil {
		return httpProfile{}, authz.ErrDenied
	}
	return httpProfile{principal: principal, userID: user, projection: projection, bearerHash: hashHTTP(bearer)}, nil
}
func withoutHTTPDeadline(f authz.Facts) authz.Facts { f.ValidUntil = time.Time{}; return f }
func (p *HTTPIdentityProvider) ResolvePrincipal(ctx context.Context) (gating.Principal, error) {
	profile, e := p.profile(ctx)
	return profile.principal, e
}
func (p *HTTPIdentityProvider) Resolve(ctx context.Context) (authz.Facts, error) {
	principal, e := p.ResolvePrincipal(ctx)
	return principal.Facts, e
}
func (p *HTTPIdentityProvider) Account(ctx context.Context, expected authz.Facts) (string, error) {
	current, e := p.ResolvePrincipal(ctx)
	if e != nil {
		return "", e
	}
	if !expected.ValidUntil.After(time.Now()) || !sameVerifiedAccountFacts(current.Facts, expected) {
		return "", authz.ErrDenied
	}
	return current.AccountID, nil
}
func (p *HTTPIdentityProvider) AuthorityRevision(ctx context.Context, expected authz.Facts, account string) (string, time.Time, error) {
	current, e := p.ResolvePrincipal(ctx)
	if e != nil {
		return "", time.Time{}, e
	}
	if account != current.AccountID || !sameVerifiedAccountFacts(current.Facts, expected) || !expected.ValidUntil.After(time.Now()) {
		return "", time.Time{}, authz.ErrDenied
	}
	return current.IdentityRevision, minHTTPTime(current.Facts.ValidUntil, expected.ValidUntil), nil
}
func (p *HTTPIdentityProvider) ProjectAccount(ctx context.Context, expected authz.Facts, account string) (map[string]any, error) {
	base := p.withoutScope(ctx)
	before, e := p.readProfile(base)
	if e != nil {
		return nil, e
	}
	after, e := p.readProfile(base)
	if e != nil {
		return nil, e
	}
	if account != before.principal.AccountID || !sameVerifiedAccountFacts(before.principal.Facts, expected) || !expected.ValidUntil.After(time.Now()) || !gating.SamePrincipalAuthority(before.principal, after.principal) || !reflect.DeepEqual(before.projection, after.projection) || !before.principal.Facts.ValidUntil.After(time.Now()) || !after.principal.Facts.ValidUntil.After(time.Now()) {
		return nil, authz.ErrDenied
	}
	return before.projection, nil
}
func minHTTPTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}
func (p *HTTPIdentityProvider) PermissionWithLease(ctx context.Context, expected authz.Facts, entity authz.Entity, permission string) (bool, time.Time, error) {
	before, e := p.ResolvePrincipal(p.withoutScope(ctx))
	if e != nil {
		return false, time.Time{}, e
	}
	if !sameVerifiedAccountFacts(before.Facts, expected) || !expected.ValidUntil.After(time.Now()) {
		return false, time.Time{}, authz.ErrDenied
	}
	allowed := authz.HasPermission(before.Facts.EntityPermissions, entity.Type, authz.EntityID(entity.ID), permission)
	after, e := p.ResolvePrincipal(p.withoutScope(ctx))
	if e != nil {
		return false, time.Time{}, e
	}
	if !gating.SamePrincipalAuthority(before, after) || !before.Facts.ValidUntil.After(time.Now()) || !after.Facts.ValidUntil.After(time.Now()) {
		return false, time.Time{}, authz.ErrDenied
	}
	return allowed, minHTTPTime(expected.ValidUntil, minHTTPTime(before.Facts.ValidUntil, after.Facts.ValidUntil)), nil
}
