package oauth

import (
	"context"
	"fmt"
	"time"

	"github.com/viant/authz"
	"github.com/viant/authz/gating"
)

// IdentityAuthority is implemented by a trusted host binding. Account and
// policy tenant mappings are explicit; neither is derived by this package.
type IdentityAuthority interface {
	authz.Provider
	gating.PrincipalResolver
	Account(context.Context, authz.Facts) (string, error)
	AuthorityRevision(context.Context, authz.Facts, string) (string, time.Time, error)
}

// StaticAuthorizationConfig assembles trusted policies with injected authorities.
// Hosts supply account, capability, and policy namespace mappings.
type StaticAuthorizationConfig struct {
	Identity IdentityAuthority
	// AllowsTenant validates policy namespaces using trusted host configuration.
	AllowsTenant              func(string) bool
	EntityCapabilityWithLease func(context.Context, authz.Facts, authz.Entity, string) (bool, time.Time, error)
	Policies                  []authz.Document
	Requirements              []gating.Binding
	EntityPermissions         gating.EntityPermissionProvider
	CapabilityPermissions     []CapabilityPermissionBinding
	EntityRoles               []EntityRoleBinding
	Entitlements              map[string]gating.EntitlementProvider
}

type StaticAuthorization struct {
	EntityCapabilityWithLease func(context.Context, authz.Facts, authz.Entity, string) (bool, time.Time, error)
	Identity                  IdentityAuthority
	ACL                       *authz.Service
	Gates                     *gating.Evaluator
	Policies                  *authz.StaticStore
	Requirements              *gating.StaticStore
	EntityCapability          func(context.Context, authz.Facts, authz.Entity, string) (bool, error)
	EntityRoleProjection      func(context.Context, authz.Facts, authz.Entity) ([]string, error)
}

func NewStaticAuthorization(config StaticAuthorizationConfig) (*StaticAuthorization, error) {
	identity := config.Identity
	if identity == nil || config.AllowsTenant == nil {
		return nil, fmt.Errorf("identity authority and policy tenant validator are required")
	}
	allowedTenant := config.AllowsTenant
	for _, document := range config.Policies {
		if !allowedTenant(document.Resource.Tenant) {
			return nil, fmt.Errorf("ACL policy tenant %q has no configured authority mapping", document.Resource.Tenant)
		}
	}
	for _, binding := range config.Requirements {
		if !allowedTenant(binding.Resource.Tenant) {
			return nil, fmt.Errorf("gate tenant %q has no configured authority mapping", binding.Resource.Tenant)
		}
	}
	policies, err := authz.NewStaticStore(config.Policies)
	if err != nil {
		return nil, err
	}
	requirements, err := gating.NewStaticStore(config.Requirements)
	if err != nil {
		return nil, err
	}
	for _, binding := range config.Requirements {
		if requirement := binding.Document.Requirements.Entitlement; requirement != nil && config.Entitlements[requirement.ProviderRef] == nil {
			return nil, fmt.Errorf("entitlement providerRef %q is not registered", requirement.ProviderRef)
		}
		policy, err := policies.Get(context.Background(), binding.Resource)
		if err != nil || policy.Policies[binding.Action].Mode == "" {
			return nil, fmt.Errorf("gate requirement has no matching ACL policy")
		}
	}
	acl := &authz.Service{Store: policies, Provider: identity}
	entities := config.EntityPermissions
	if entities == nil {
		entities = &FactEntityPermissionProvider{Principals: identity}
	}
	entityCapability, err := NewCapabilityPermissionResolver(config.CapabilityPermissions)
	if err != nil {
		return nil, err
	}
	entityCapabilityWithLease := config.EntityCapabilityWithLease
	if entityCapabilityWithLease != nil {
		entityCapability = func(ctx context.Context, facts authz.Facts, entity authz.Entity, capability string) (bool, error) {
			allowed, _, err := entityCapabilityWithLease(ctx, facts, entity, capability)
			return allowed, err
		}
	}
	entityRoles, err := NewEntityRoleResolver(config.EntityRoles)
	if err != nil {
		return nil, err
	}
	entitlements := make(map[string]gating.EntitlementProvider, len(config.Entitlements))
	for ref, provider := range config.Entitlements {
		if ref == "" || provider == nil {
			return nil, fmt.Errorf("invalid entitlement provider registration")
		}
		entitlements[ref] = provider
	}
	return &StaticAuthorization{EntityCapabilityWithLease: entityCapabilityWithLease, Identity: identity, ACL: acl, Gates: &gating.Evaluator{ACL: acl, Principals: identity, Requirements: requirements, Entities: entities, Entitlements: entitlements}, Policies: policies, Requirements: requirements, EntityCapability: entityCapability, EntityRoleProjection: entityRoles}, nil
}
