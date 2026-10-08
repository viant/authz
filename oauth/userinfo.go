package oauth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	access "github.com/viant/authz"
)

// UserInfoConfig opts an ACL host into resolving role and feature facts from
// a trusted identity service. The endpoint is deployment configuration, never
// a request parameter. Keyfunc validates the ID token independently of the
// remote response.
type UserInfoConfig struct {
	Issuer     string
	Audience   string
	Algorithms []string
	Keyfunc    jwt.Keyfunc
	URL        string
	Client     *http.Client
	// FactLease caps the lifetime of authority facts returned by the
	// account-bound wrapper. Hosts set it to their identity service's allowed
	// freshness window; the ID token expiry remains an upper bound.
	FactLease time.Duration
	// OmitEntityPermissions explicitly requests identity/role/feature facts only.
	// Selected entity authorization must be configured separately by the host.
	OmitEntityPermissions bool
}

type userInfoClaims struct {
	jwt.RegisteredClaims
	UserID    int `json:"user_id"`
	AccountID int `json:"account_id"`
}

type UserInfoProvider struct {
	config UserInfoConfig
	client *http.Client
}

var _ access.Provider = (*UserInfoProvider)(nil)

func NewUserInfo(config UserInfoConfig) (*UserInfoProvider, error) {
	if config.Issuer == "" || config.Audience == "" || config.Keyfunc == nil || len(config.Algorithms) == 0 {
		return nil, errors.New("user-info issuer, audience, keys and algorithms required")
	}
	for _, algorithm := range config.Algorithms {
		switch algorithm {
		case "RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "EdDSA":
		default:
			return nil, errors.New("user-info signing algorithm must be asymmetric")
		}
	}
	endpoint, err := url.Parse(config.URL)
	if err != nil || endpoint.Host == "" || endpoint.User != nil || endpoint.Fragment != "" || endpoint.RawQuery != "" {
		return nil, errors.New("user-info URL must be an absolute endpoint without credentials or query")
	}
	if endpoint.Scheme != "https" && !(endpoint.Scheme == "http" && loopbackHost(endpoint.Hostname())) {
		return nil, errors.New("user-info URL requires HTTPS or loopback HTTP")
	}
	client := http.Client{Timeout: 5 * time.Second}
	if config.Client != nil {
		client = *config.Client
		if client.Timeout == 0 {
			client.Timeout = 5 * time.Second
		}
	}
	// Redirects must not forward the bearer credential to a new destination.
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	config.Algorithms = append([]string(nil), config.Algorithms...)
	return &UserInfoProvider{config: config, client: &client}, nil
}

func loopbackHost(host string) bool {
	return strings.EqualFold(host, "localhost") || net.ParseIP(host) != nil && net.ParseIP(host).IsLoopback()
}

func (p *UserInfoProvider) Resolve(ctx context.Context) (access.Facts, error) {
	claims, bearer, err := p.verifiedClaims(ctx)
	if err != nil {
		return access.Facts{}, err
	}
	started := time.Now()
	endpoint := p.config.URL
	if p.config.OmitEntityPermissions {
		endpoint += "?includeEntityPermissions=false"
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return access.Facts{}, access.ErrUnavailable
	}
	request.Header.Set("Authorization", "Bearer "+bearer)
	request.Header.Set("Accept", "application/json")
	response, err := p.client.Do(request)
	if err != nil {
		return access.Facts{}, access.ErrUnavailable
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		if response.StatusCode >= 500 || response.StatusCode >= 300 && response.StatusCode < 400 {
			return access.Facts{}, access.ErrUnavailable
		}
		return access.Facts{}, access.ErrDenied
	}
	const maxUserInfoBytes = 64 << 10
	body, err := io.ReadAll(io.LimitReader(response.Body, maxUserInfoBytes+1))
	if err != nil || len(body) > maxUserInfoBytes {
		return access.Facts{}, access.ErrUnavailable
	}
	info, err := decodeUserInfoProjection(body, p.config.OmitEntityPermissions)
	if err != nil || info.UserID != claims.UserID || info.AccountID != claims.AccountID || info.Subject != claims.Subject {
		return access.Facts{}, access.ErrDenied
	}
	var groups access.EntityGroups
	if !p.config.OmitEntityPermissions {
		groups = access.EntityGroups{}
	}
	if !p.config.OmitEntityPermissions {
		for _, grant := range info.EntityPermissions {
			groups[grant.Type] = append(groups[grant.Type], grant.ID)
		}
	}
	lease := claims.ExpiresAt.Time
	if p.config.FactLease > 0 {
		if limit := started.Add(p.config.FactLease); limit.Before(lease) {
			lease = limit
		}
	}
	if info.HasSourceLease {
		if !info.ValidUntil.After(time.Now()) || info.EvaluatedAt.After(time.Now()) {
			return access.Facts{}, access.ErrDenied
		}
		if info.ValidUntil.Before(lease) {
			lease = info.ValidUntil
		}
		if p.config.FactLease > 0 {
			if limit := info.EvaluatedAt.Add(p.config.FactLease); limit.Before(lease) {
				lease = limit
			}
		}
	}
	if !lease.After(time.Now()) {
		return access.Facts{}, access.ErrDenied
	}
	return access.Facts{Subject: claims.Subject, Tenant: strconv.Itoa(claims.AccountID), Issuer: claims.Issuer,
		Roles: info.Roles, Exposures: info.Features, EntityGroups: groups,
		EntityPermissions: info.EntityPermissions, ValidUntil: lease}, nil
}

// ResolveIdentity verifies the ID token without consulting user-info. It is
// suitable only for access based on the verified subject (for example,
// ownership); callers must not infer role, feature, or entity grants from it.
func (p *UserInfoProvider) ResolveIdentity(ctx context.Context) (access.Facts, error) {
	claims, _, err := p.verifiedClaims(ctx)
	if err != nil {
		return access.Facts{}, err
	}
	return access.Facts{Subject: claims.Subject, Tenant: strconv.Itoa(claims.AccountID),
		Issuer: claims.Issuer, ValidUntil: claims.ExpiresAt.Time}, nil
}

func (p *UserInfoProvider) verifiedClaims(ctx context.Context) (*userInfoClaims, string, error) {
	if p == nil || ctx == nil || ctx.Err() != nil {
		return nil, "", access.ErrDenied
	}
	bearer, _ := ctx.Value(tokenKey{}).(string)
	if bearer == "" {
		return nil, "", access.ErrDenied
	}
	claims := &userInfoClaims{}
	_, err := jwt.ParseWithClaims(bearer, claims, p.config.Keyfunc, jwt.WithValidMethods(p.config.Algorithms), jwt.WithIssuer(p.config.Issuer), jwt.WithAudience(p.config.Audience), jwt.WithExpirationRequired(), jwt.WithIssuedAt())
	if err != nil || claims.Subject == "" || claims.UserID <= 0 || claims.AccountID <= 0 || claims.ExpiresAt == nil || !claims.ExpiresAt.After(time.Now()) || claims.ExpiresAt.Time.After(time.Now().Add(time.Hour)) {
		return nil, "", access.ErrDenied
	}
	return claims, bearer, nil
}

type userInfo struct {
	EvaluatedAt       time.Time
	ValidUntil        time.Time
	HasSourceLease    bool
	UID               string
	Subject           string
	UserID            int
	AccountID         int
	Roles             []string
	Features          []string
	EntityPermissions []access.EntityPermission
}

func decodeUserInfo(body []byte) (userInfo, error) { return decodeUserInfoProjection(body, false) }

func decodeUserInfoProjection(body []byte, omitEntities bool) (userInfo, error) {
	root, err := uniqueObject(body)
	if err != nil {
		return userInfo{}, err
	}
	status, ok := objectField(root, "status")
	if !ok || string(status) != `"ok"` {
		return userInfo{}, access.ErrDenied
	}
	raw, ok := objectField(root, "info")
	if !ok {
		return userInfo{}, access.ErrDenied
	}
	object, err := uniqueObject(raw)
	if err != nil {
		return userInfo{}, err
	}
	var info userInfo
	for _, field := range []struct {
		name string
		into any
	}{{"userId", &info.UserID}, {"accountId", &info.AccountID}, {"subject", &info.Subject}, {"roles", &info.Roles}, {"features", &info.Features}} {
		value, found := objectField(object, field.name)
		if !found || bytes.Equal(value, []byte("null")) || json.Unmarshal(value, field.into) != nil {
			return userInfo{}, access.ErrDenied
		}
	}
	if rawUID, found := objectField(object, "uid"); found && json.Unmarshal(rawUID, &info.UID) != nil {
		return userInfo{}, access.ErrDenied
	}
	if info.UserID <= 0 || info.AccountID <= 0 || info.Subject == "" || info.Roles == nil || info.Features == nil {
		return userInfo{}, access.ErrDenied
	}
	evalRaw, hasEval := objectField(object, "evaluatedAt")
	expiryRaw, hasExpiry := objectField(object, "validUntil")
	if hasEval != hasExpiry || omitEntities && !hasEval {
		return userInfo{}, access.ErrDenied
	}
	if hasEval {
		if json.Unmarshal(evalRaw, &info.EvaluatedAt) != nil || json.Unmarshal(expiryRaw, &info.ValidUntil) != nil || info.EvaluatedAt.IsZero() || !info.ValidUntil.After(info.EvaluatedAt) || info.ValidUntil.After(info.EvaluatedAt.Add(5*time.Minute)) {
			return userInfo{}, access.ErrDenied
		}
		info.HasSourceLease = true
	}
	grantsRaw, found := objectField(object, "entityPermissions")
	if omitEntities && !found {
		grantsRaw = []byte("[]")
		found = true
	}
	if !found || bytes.Equal(grantsRaw, []byte("null")) {
		return userInfo{}, access.ErrDenied
	}
	var grants []json.RawMessage
	if json.Unmarshal(grantsRaw, &grants) != nil || grants == nil {
		return userInfo{}, access.ErrDenied
	}
	info.EntityPermissions = make([]access.EntityPermission, 0, len(grants))
	for _, rawGrant := range grants {
		fields, parseErr := uniqueObject(rawGrant)
		if parseErr != nil || len(fields) != 3 {
			return userInfo{}, access.ErrDenied
		}
		grant := access.EntityPermission{}
		for _, field := range []struct {
			name string
			into any
		}{{"type", &grant.Type}, {"id", &grant.ID}, {"permissions", &grant.Permissions}} {
			value, exists := fields[field.name]
			if !exists || bytes.Equal(value, []byte("null")) || json.Unmarshal(value, field.into) != nil {
				return userInfo{}, access.ErrDenied
			}
			if field.name == "id" && (len(value) == 0 || value[0] != '"') {
				return userInfo{}, access.ErrDenied
			}
		}
		if len(grant.Permissions) == 0 {
			return userInfo{}, access.ErrDenied
		}
		info.EntityPermissions = append(info.EntityPermissions, grant)
	}
	if access.ValidateEntityPermissions(info.EntityPermissions) != nil {
		return userInfo{}, access.ErrDenied
	}
	for _, names := range [][]string{info.Roles, info.Features} {
		seen := map[string]bool{}
		for _, name := range names {
			if name == "" || strings.TrimSpace(name) != name || seen[name] {
				return userInfo{}, access.ErrDenied
			}
			seen[name] = true
		}
	}
	if omitEntities {
		info.EntityPermissions = nil
	}
	sort.Strings(info.Roles)
	sort.Strings(info.Features)
	return info, nil
}

func objectField(object map[string]json.RawMessage, name string) (json.RawMessage, bool) {
	for key, value := range object {
		if strings.EqualFold(key, name) {
			return value, true
		}
	}
	return nil, false
}

func uniqueObject(raw []byte) (map[string]json.RawMessage, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	opening, err := decoder.Token()
	if err != nil || opening != json.Delim('{') {
		return nil, access.ErrDenied
	}
	result := map[string]json.RawMessage{}
	seen := map[string]bool{}
	for decoder.More() {
		key, err := decoder.Token()
		name, ok := key.(string)
		if err != nil || !ok || seen[strings.ToLower(name)] {
			return nil, access.ErrDenied
		}
		seen[strings.ToLower(name)] = true
		var value json.RawMessage
		if decoder.Decode(&value) != nil {
			return nil, access.ErrDenied
		}
		result[name] = value
	}
	closing, err := decoder.Token()
	if err != nil || closing != json.Delim('}') {
		return nil, access.ErrDenied
	}
	if _, err = decoder.Token(); err != io.EOF {
		return nil, access.ErrDenied
	}
	return result, nil
}
