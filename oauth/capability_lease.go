package oauth

import (
	"context"
	"time"

	"github.com/viant/authz"
)

// NewLeasedCapabilityPermissionResolver maps configured capabilities to an
// injected authority and preserves its remaining lease.
func NewLeasedCapabilityPermissionResolver(bindings []CapabilityPermissionBinding, permission func(context.Context, authz.Facts, authz.Entity, string) (bool, time.Time, error)) (func(context.Context, authz.Facts, authz.Entity, string) (bool, time.Time, error), error) {
	if permission == nil {
		return nil, authz.ErrDenied
	}
	if _, err := NewCapabilityPermissionResolver(bindings); err != nil {
		return nil, err
	}
	index := map[capabilityKey]string{}
	for _, binding := range bindings {
		index[capabilityKey{binding.EntityType, binding.Capability}] = binding.Permission
	}
	return func(ctx context.Context, facts authz.Facts, entity authz.Entity, capability string) (bool, time.Time, error) {
		name := index[capabilityKey{entity.Type, capability}]
		if name == "" {
			return false, facts.ValidUntil, nil
		}
		allowed, until, err := permission(ctx, facts, entity, name)
		if err != nil {
			return false, time.Time{}, err
		}
		if facts.ValidUntil.Before(until) {
			until = facts.ValidUntil
		}
		if !until.After(time.Now()) {
			return false, time.Time{}, authz.ErrDenied
		}
		return allowed, until, nil
	}, nil
}
