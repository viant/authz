package oauth

import (
	"context"
	"time"

	"github.com/viant/authz"
	"github.com/viant/authz/gating"
)

// PermissionWithLease retains the authority's actual remaining permission lease.
// Consumers must narrow snapshots and recheck this lease before releasing data.
func (c *EntityEvaluationClient) PermissionWithLease(ctx context.Context, facts authz.Facts, entity authz.Entity, permission string) (bool, time.Time, error) {
	if c == nil || ctx == nil {
		return false, time.Time{}, authz.ErrDenied
	}
	principal, err := c.config.Principals.ResolvePrincipal(ctx)
	if err != nil {
		return false, time.Time{}, err
	}
	if !sameVerifiedAccountFacts(facts, principal.Facts) || !facts.ValidUntil.After(time.Now()) {
		return false, time.Time{}, authz.ErrDenied
	}
	selected, hash, err := gating.CanonicalSelection([]authz.Entity{entity})
	if err != nil {
		return false, time.Time{}, err
	}
	decision, err := c.CheckEntityPermission(ctx, gating.ProviderRequest{SchemaVersion: 1, RequestID: hash, Subject: principal.Facts.Subject, Issuer: principal.Facts.Issuer, TenantID: principal.Facts.Tenant, AccountID: principal.AccountID, ResourceKind: entity.Type, ResourceID: entity.ID, Action: permission, RequirementsRevision: principal.IdentityRevision, RequirementKey: permission, ProviderRef: "entity", EntitySelection: selected, EntitySelectionHash: hash})
	if err != nil {
		return false, time.Time{}, err
	}
	lease := decision.ValidUntil
	if facts.ValidUntil.Before(lease) {
		lease = facts.ValidUntil
	}
	if !lease.After(time.Now()) {
		return false, time.Time{}, authz.ErrDenied
	}
	return decision.Effect == "allow", lease, nil
}

func (c *EntityEvaluationClient) CapabilityResolverWithLease(bindings []CapabilityPermissionBinding) (func(context.Context, authz.Facts, authz.Entity, string) (bool, time.Time, error), error) {
	if _, err := NewCapabilityPermissionResolver(bindings); err != nil {
		return nil, err
	}
	permissions := map[capabilityKey]string{}
	for _, binding := range bindings {
		permissions[capabilityKey{binding.EntityType, binding.Capability}] = binding.Permission
	}
	return func(ctx context.Context, facts authz.Facts, entity authz.Entity, capability string) (bool, time.Time, error) {
		permission := permissions[capabilityKey{entity.Type, capability}]
		if permission == "" {
			return false, facts.ValidUntil, nil
		}
		return c.PermissionWithLease(ctx, facts, entity, permission)
	}, nil
}
