package oauth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/viant/authz"
	"github.com/viant/authz/gating"
)

// TenantResolver is a host-owned mapping from verified identity/account to
// policy ownership. An account ID is never assumed to be a tenant ID.
type TenantResolver func(context.Context, string, int) (string, error)

// AccountUserInfoProvider adapts the verified ID-token user-info contract to
// both authz ACL facts and account-bound gate principals. The identity service
// owns user/account membership and feature lookup; this adapter does not.
type AccountUserInfoProvider struct {
	userinfo *UserInfoProvider
	tenant   TenantResolver
}

// AccountUserInfoConfig selects one explicit policy-tenant mapping: exact
// account IDs or a shared policy namespace for all verified accounts. Dynamic
// ownership uses NewAccountUserInfo with a trusted TenantResolver.
type AccountUserInfoConfig struct {
	Issuer               string
	Audience             string
	Algorithms           []string
	UserInfoURL          string
	JWKSURL              string
	JWKSRefreshInterval  time.Duration
	FactLease            time.Duration
	TenantByAccount      map[int]string
	TenantForAllAccounts string
	Client               *http.Client
}

func NewConfiguredAccountUserInfo(config AccountUserInfoConfig) (*AccountUserInfoProvider, error) {
	sharedTenant := config.TenantForAllAccounts
	if (len(config.TenantByAccount) == 0) == (sharedTenant == "") {
		return nil, errors.New("exactly one explicit policy-tenant mapping is required")
	}
	if sharedTenant != "" && (sharedTenant == "*" || strings.TrimSpace(sharedTenant) != sharedTenant) {
		return nil, errors.New("invalid shared policy tenant")
	}
	tenants := make(map[int]string, len(config.TenantByAccount))
	for accountID, tenant := range config.TenantByAccount {
		if accountID <= 0 || tenant == "" || tenant == "*" || strings.TrimSpace(tenant) != tenant {
			return nil, errors.New("invalid account-to-tenant mapping")
		}
		tenants[accountID] = tenant
	}
	keyfunc, err := NewJWKSKeyfunc(JWKSConfig{URL: config.JWKSURL, RefreshInterval: config.JWKSRefreshInterval, Client: config.Client})
	if err != nil {
		return nil, err
	}
	return NewAccountUserInfo(UserInfoConfig{Issuer: config.Issuer, Audience: config.Audience, Algorithms: config.Algorithms, Keyfunc: keyfunc, URL: config.UserInfoURL, Client: config.Client, FactLease: config.FactLease}, func(_ context.Context, _ string, accountID int) (string, error) {
		if sharedTenant != "" {
			return sharedTenant, nil
		}
		tenant, ok := tenants[accountID]
		if !ok {
			return "", authz.ErrDenied
		}
		return tenant, nil
	})
}

func NewAccountUserInfo(config UserInfoConfig, tenant TenantResolver) (*AccountUserInfoProvider, error) {
	if tenant == nil || config.FactLease <= 0 {
		return nil, errors.New("explicit tenant mapping and positive fact lease are required")
	}
	provider, err := NewUserInfo(config)
	if err != nil {
		return nil, err
	}
	return &AccountUserInfoProvider{userinfo: provider, tenant: tenant}, nil
}

var _ authz.Provider = (*AccountUserInfoProvider)(nil)
var _ gating.PrincipalResolver = (*AccountUserInfoProvider)(nil)

func (p *AccountUserInfoProvider) Resolve(ctx context.Context) (authz.Facts, error) {
	principal, err := p.ResolvePrincipal(ctx)
	return principal.Facts, err
}

// Account rechecks account context against the facts used by a consumer that
// resolves ACL facts separately. Hosts can inject this as their account mapper.
func (p *AccountUserInfoProvider) Account(ctx context.Context, expected authz.Facts) (string, error) {
	principal, err := p.ResolvePrincipal(ctx)
	if errors.Is(err, authz.ErrDenied) {
		return "", authz.ErrDenied
	}
	if err != nil {
		return "", authz.ErrUnavailable
	}
	if !sameVerifiedAccountFacts(principal.Facts, expected) {
		return "", authz.ErrDenied
	}
	return principal.AccountID, nil
}

// AuthorityRevision rechecks the verified identity and account for a host
// snapshot. The revision includes the credential and current user-info facts;
// the returned lease is the latest verified fact deadline.
func (p *AccountUserInfoProvider) AuthorityRevision(ctx context.Context, expected authz.Facts, accountID string) (string, time.Time, error) {
	principal, err := p.ResolvePrincipal(ctx)
	if errors.Is(err, authz.ErrDenied) {
		return "", time.Time{}, authz.ErrDenied
	}
	if err != nil {
		return "", time.Time{}, authz.ErrUnavailable
	}
	if accountID == "" || principal.AccountID != accountID || !sameVerifiedAccountFacts(principal.Facts, expected) || principal.IdentityRevision == "" || !principal.Facts.ValidUntil.After(time.Now()) {
		return "", time.Time{}, authz.ErrDenied
	}
	return principal.IdentityRevision, principal.Facts.ValidUntil, nil
}

func sameVerifiedAccountFacts(a, b authz.Facts) bool {
	return a.Subject == b.Subject && a.Issuer == b.Issuer && a.Tenant == b.Tenant &&
		reflect.DeepEqual(a.Roles, b.Roles) && reflect.DeepEqual(a.Exposures, b.Exposures) &&
		reflect.DeepEqual(a.EntityGroups, b.EntityGroups) && reflect.DeepEqual(a.Entities, b.Entities) &&
		reflect.DeepEqual(a.EntityPermissions, b.EntityPermissions) && reflect.DeepEqual(a.GrantedScopes, b.GrantedScopes)
}

func (p *AccountUserInfoProvider) ResolvePrincipal(ctx context.Context) (gating.Principal, error) {
	if p == nil || p.userinfo == nil || p.tenant == nil || ctx == nil || ctx.Err() != nil {
		return gating.Principal{}, authz.ErrDenied
	}
	// Resolve verifies the token and reconciles user ID, subject, and account ID
	// against the current user-info profile before trusting any authority facts.
	facts, err := p.userinfo.Resolve(ctx)
	if err != nil {
		return gating.Principal{}, err
	}
	claims, bearer, err := p.userinfo.verifiedClaims(ctx)
	if err != nil || facts.Tenant != strconv.Itoa(claims.AccountID) {
		return gating.Principal{}, authz.ErrDenied
	}
	tenant, err := p.tenant(ctx, facts.Subject, claims.AccountID)
	if errors.Is(err, authz.ErrDenied) {
		return gating.Principal{}, authz.ErrDenied
	}
	if err != nil {
		return gating.Principal{}, authz.ErrUnavailable
	}
	if tenant == "" || tenant == "*" || strings.TrimSpace(tenant) != tenant {
		return gating.Principal{}, authz.ErrDenied
	}
	facts.Tenant = tenant
	if deadline := time.Now().Add(p.userinfo.config.FactLease); deadline.Before(facts.ValidUntil) {
		facts.ValidUntil = deadline
	}
	// User-info has no IAM revision field. Bind this observed authority snapshot
	// to both the verified credential and current account facts, excluding the
	// rolling lease timestamp. This is not an IAM revocation revision.
	authority, err := json.Marshal(struct {
		Subject           string
		Issuer            string
		Tenant            string
		AccountID         int
		Roles             []string
		Exposures         []string
		EntityGroups      authz.EntityGroups
		EntityPermissions []authz.EntityPermission
		GrantedScopes     []string
	}{facts.Subject, facts.Issuer, facts.Tenant, claims.AccountID, facts.Roles, facts.Exposures, facts.EntityGroups, facts.EntityPermissions, facts.GrantedScopes})
	if err != nil {
		return gating.Principal{}, authz.ErrUnavailable
	}
	hash := sha256.New()
	_, _ = hash.Write([]byte(bearer))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write(authority)
	revision := hash.Sum(nil)
	return gating.Principal{Facts: facts, AccountID: strconv.Itoa(claims.AccountID), IdentityRevision: hex.EncodeToString(revision)}, nil
}
