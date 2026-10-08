package oauth

import (
	"context"
	"fmt"
	"time"

	"github.com/viant/authz"
	"github.com/viant/authz/gating"
)

// StaticAuthorizationConfig assembles trusted file-backed ACL and requirement
// documents with verified IdP facts. Hosts supply product resource mappings
// separately; no operation, capability or account rule is built in.
type StaticAuthorizationConfig struct {
	EntityEvaluationURL   string // optional trusted selected-entity authority endpoint
	Identity              AccountUserInfoConfig
	Policies              []authz.Document
	Requirements          []gating.Binding
	EntityPermissions     gating.EntityPermissionProvider
	CapabilityPermissions []CapabilityPermissionBinding
	EntityRoles           []EntityRoleBinding
	Entitlements          map[string]gating.EntitlementProvider
}

type StaticAuthorization struct {
	EntityCapabilityWithLease func(context.Context, authz.Facts, authz.Entity, string) (bool, time.Time, error)
	Identity                  *AccountUserInfoProvider
	ACL                       *authz.Service
	Gates                     *gating.Evaluator
	Policies                  *authz.StaticStore
	Requirements              *gating.StaticStore
	EntityCapability          func(context.Context, authz.Facts, authz.Entity, string) (bool, error)
	EntityRoleProjection      func(context.Context, authz.Facts, authz.Entity) ([]string, error)
	EntityEvaluation          *EntityEvaluationClient
}

func NewStaticAuthorization(config StaticAuthorizationConfig) (*StaticAuthorization, error) {
	identity, err := NewConfiguredAccountUserInfo(config.Identity)
	if err != nil {
		return nil, err
	}
	allowedTenant := func(tenant string) bool {
		if tenant == "*" {
			return true
		}
		if config.Identity.TenantForAllAccounts != "" {
			return tenant == config.Identity.TenantForAllAccounts
		}
		for _, mapped := range config.Identity.TenantByAccount {
			if tenant == mapped {
				return true
			}
		}
		return false
	}
	for _, document := range config.Policies {
		if !allowedTenant(document.Resource.Tenant) {
			return nil, fmt.Errorf("ACL policy tenant %q has no configured IdP mapping", document.Resource.Tenant)
		}
	}
	for _, binding := range config.Requirements {
		if !allowedTenant(binding.Resource.Tenant) {
			return nil, fmt.Errorf("gate tenant %q has no configured IdP mapping", binding.Resource.Tenant)
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
	var evaluation *EntityEvaluationClient
	if config.EntityEvaluationURL != "" {
		if entities != nil {
			return nil, fmt.Errorf("configure either entity evaluation URL or entity provider")
		}
		evaluation, err = NewEntityEvaluationClient(EntityEvaluationConfig{URL: config.EntityEvaluationURL, Principals: identity, Client: config.Identity.Client})
		if err != nil {
			return nil, err
		}
		entities = evaluation
	}
	if entities == nil {
		entities = &FactEntityPermissionProvider{Principals: identity}
	}
	entityCapability, err := NewCapabilityPermissionResolver(config.CapabilityPermissions)
	if err != nil {
		return nil, err
	}
	if evaluation != nil {
		entityCapability, err = evaluation.CapabilityResolver(config.CapabilityPermissions)
		if err != nil {
			return nil, err
		}
	}
	var entityCapabilityWithLease func(context.Context, authz.Facts, authz.Entity, string) (bool, time.Time, error)
	if evaluation != nil {
		entityCapabilityWithLease, err = evaluation.CapabilityResolverWithLease(config.CapabilityPermissions)
		if err != nil {
			return nil, err
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
	return &StaticAuthorization{EntityCapabilityWithLease: entityCapabilityWithLease, EntityEvaluation: evaluation, Identity: identity, ACL: acl, Gates: &gating.Evaluator{ACL: acl, Principals: identity, Requirements: requirements, Entities: entities, Entitlements: entitlements}, Policies: policies, Requirements: requirements, EntityCapability: entityCapability, EntityRoleProjection: entityRoles}, nil
}
