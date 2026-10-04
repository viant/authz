package oauth

import (
	"context"
	"fmt"
	"strings"

	"github.com/viant/authz"
)

// CapabilityPermissionBinding maps one authored UI capability to one exact
// identity-provider entity permission. Names are deployment configuration.
type CapabilityPermissionBinding struct {
	EntityType string `json:"entityType"`
	Capability string `json:"capability"`
	Permission string `json:"permission"`
}

type capabilityKey struct{ entityType, capability string }

func NewCapabilityPermissionResolver(bindings []CapabilityPermissionBinding) (func(context.Context, authz.Facts, authz.Entity, string) (bool, error), error) {
	permissions := make(map[capabilityKey]string, len(bindings))
	for _, binding := range bindings {
		if binding.EntityType == "" || binding.Capability == "" || binding.Permission == "" || strings.TrimSpace(binding.EntityType) != binding.EntityType || strings.TrimSpace(binding.Capability) != binding.Capability || strings.TrimSpace(binding.Permission) != binding.Permission {
			return nil, fmt.Errorf("invalid capability permission binding")
		}
		key := capabilityKey{binding.EntityType, binding.Capability}
		if _, exists := permissions[key]; exists {
			return nil, fmt.Errorf("duplicate capability permission binding")
		}
		permissions[key] = binding.Permission
	}
	return func(ctx context.Context, facts authz.Facts, entity authz.Entity, capability string) (bool, error) {
		if ctx == nil || ctx.Err() != nil || facts.Subject == "" || facts.Tenant == "" || facts.Issuer == "" || entity.Type == "" || entity.ID == "" {
			return false, authz.ErrDenied
		}
		permission := permissions[capabilityKey{entity.Type, capability}]
		if permission == "" {
			return false, nil
		}
		return authz.HasPermission(facts.EntityPermissions, entity.Type, authz.EntityID(entity.ID), permission), nil
	}, nil
}
