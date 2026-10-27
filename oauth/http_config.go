package oauth

import (
	"context"
	"github.com/golang-jwt/jwt/v5"
	"github.com/viant/authz"
	"github.com/viant/authz/gating"
	"net/http"
	"time"
)

// HTTPIdentityConfig is operator-owned. Mapping paths select fields from the
// independently verified JWT and the configured identity endpoint, never UI input.
type HTTPIdentityConfig struct {
	// Keyfunc is a trusted process binding, never decoded from an identity
	// document. Embedders can reuse the host verifier instead of configuring JWKS twice.
	Keyfunc jwt.Keyfunc `json:"-"`

	Kind                string   `json:"kind"`
	Issuer              string   `json:"issuer"`
	Audience            string   `json:"audience"`
	Algorithms          []string `json:"algorithms"`
	UserInfoURL         string   `json:"userInfoUrl"`
	JWKSURL             string   `json:"jwksUrl"`
	JWKSRefreshInterval string   `json:"jwksRefreshInterval"`
	FactLease           string   `json:"factLease"`
	// UserInfoCacheTTL defaults to fifteen minutes with a signed JWT account
	// mapping. Without that mapping, omission preserves uncached legacy reads;
	// an explicitly positive TTL still requires the signed account mapping.
	// New resolutions coalesce a fresh profile read near the end of its effective
	// lease (last tenth, at most thirty seconds). Admitted scopes keep their
	// original deadline; a failed refresh never falls back to cached grants.
	UserInfoCacheTTL        string              `json:"userInfoCacheTTL,omitempty"`
	UserInfoCacheMaxEntries int                 `json:"userInfoCacheMaxEntries,omitempty"`
	Now                     func() time.Time    `json:"-"`
	SourceClockSkew         string              `json:"sourceClockSkew,omitempty"`
	TenantByAccount         map[string]string   `json:"tenantByAccount,omitempty"`
	TenantForAllAccounts    string              `json:"tenantForAllAccounts,omitempty"`
	Mapping                 HTTPIdentityMapping `json:"mapping"`
	Query                   map[string]string   `json:"query,omitempty"`
	Client                  *http.Client        `json:"-"`
}
type HTTPIdentityMapping struct {
	Subject            string            `json:"subject"`
	UserID             string            `json:"userId,omitempty"`
	AccountID          string            `json:"accountId"`
	JWTUserID          string            `json:"jwtUserId,omitempty"`
	JWTAccountID       string            `json:"jwtAccountId,omitempty"`
	Roles              string            `json:"roles,omitempty"`
	Exposures          string            `json:"exposures,omitempty"`
	MembershipGroups   string            `json:"membershipGroups,omitempty"`
	EntityPermissions  string            `json:"entityPermissions,omitempty"`
	Status             string            `json:"status,omitempty"`
	StatusValue        string            `json:"statusValue,omitempty"`
	AuthorityRevision  string            `json:"authorityRevision,omitempty"`
	EvaluatedAt        string            `json:"evaluatedAt,omitempty"`
	ValidUntil         string            `json:"validUntil,omitempty"`
	RequireSourceLease bool              `json:"requireSourceLease,omitempty"`
	AccountProjection  map[string]string `json:"accountProjection,omitempty"`
}

// Evaluation names are ordinary endpoint field paths, not protocol extensions.
// Entitlement bindings keep business requirement names in operator configuration.
type HTTPEvaluationConfig struct {
	// SourceClockSkew is explicit tolerance for the evaluation endpoint only; zero remains strict.
	SourceClockSkew        string                            `json:"sourceClockSkew,omitempty"`
	URL                    string                            `json:"url"`
	CacheTTL               string                            `json:"cacheTTL,omitempty"`
	MaxEntries             int                               `json:"maxEntries,omitempty"`
	Mapping                HTTPEvaluationMapping             `json:"mapping"`
	EntitlementProviderRef string                            `json:"entitlementProviderRef,omitempty"`
	Entitlements           map[string]HTTPAccountRequirement `json:"entitlements,omitempty"`
	Client                 *http.Client                      `json:"-"`
}
type HTTPAccountRequirement struct {
	ResourceType string `json:"resourceType"`
	Permission   string `json:"permission"`
}
type HTTPEvaluationMapping struct {
	RequestEntityType   string `json:"requestEntityType"`
	RequestEntityIDs    string `json:"requestEntityIds"`
	RequestPermissions  string `json:"requestPermissions"`
	RequestScope        string `json:"requestScope,omitempty"`
	RequestResourceType string `json:"requestResourceType,omitempty"`
	IntegerEntityIDs    bool   `json:"integerEntityIds,omitempty"`
	Status              string `json:"status,omitempty"`
	StatusValue         string `json:"statusValue,omitempty"`
	Issuer              string `json:"issuer"`
	Subject             string `json:"subject"`
	UserID              string `json:"userId,omitempty"`
	AccountID           string `json:"accountId"`
	EntityType          string `json:"entityType"`
	Results             string `json:"results"`
	ResultEntityID      string `json:"resultEntityId"`
	ResultPermissions   string `json:"resultPermissions"`
	Scope               string `json:"scope,omitempty"`
	ResourceType        string `json:"resourceType,omitempty"`
	Permissions         string `json:"permissions,omitempty"`
	AuthorityRevision   string `json:"authorityRevision"`
	EvaluatedAt         string `json:"evaluatedAt"`
	ValidUntil          string `json:"validUntil"`
}

type HTTPProviders struct {
	NativeWindowIdentity func(context.Context) (gating.Principal, error)
	Entitlements         map[string]gating.EntitlementProvider
	AccountProjection    func(context.Context, authz.Facts, string) (map[string]any, error)
	DecisionScope        interface {
		BeginDecision(context.Context) (context.Context, func() error, error)
		WithoutDecision(context.Context) context.Context
		MetadataReadActive(context.Context) bool
	}
	MetadataScope interface {
		BeginMetadataRead(context.Context) (context.Context, func() error, error)
		WithoutMetadataRead(context.Context) context.Context
	}
	Identity            IdentityAuthority
	AllowsTenant        func(string) bool
	EntityPermissions   gating.EntityPermissionProvider
	PermissionWithLease func(context.Context, authz.Facts, authz.Entity, string) (bool, time.Time, error)
}
