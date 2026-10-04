package oauth

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/viant/authz"
)

// EntityRoleBinding exposes one named IdP entity permission as one UI role.
// Both names are host configuration; no permission is implicitly a role.
type EntityRoleBinding struct {
	EntityType string `json:"entityType"`
	Permission string `json:"permission"`
	Role       string `json:"role"`
}

type entityRoleKey struct{ entityType, permission string }

func NewEntityRoleResolver(bindings []EntityRoleBinding) (func(context.Context, authz.Facts, authz.Entity) ([]string, error), error) {
	roles := make(map[entityRoleKey]string, len(bindings))
	for _, binding := range bindings {
		if binding.EntityType == "" || binding.Permission == "" || binding.Role == "" || strings.TrimSpace(binding.EntityType) != binding.EntityType || strings.TrimSpace(binding.Permission) != binding.Permission || strings.TrimSpace(binding.Role) != binding.Role {
			return nil, fmt.Errorf("invalid entity role binding")
		}
		key := entityRoleKey{binding.EntityType, binding.Permission}
		if _, exists := roles[key]; exists {
			return nil, fmt.Errorf("duplicate entity role binding")
		}
		roles[key] = binding.Role
	}
	return func(ctx context.Context, facts authz.Facts, entity authz.Entity) ([]string, error) {
		if ctx == nil || ctx.Err() != nil || facts.Subject == "" || facts.Issuer == "" || facts.Tenant == "" || !facts.ValidUntil.After(time.Now()) || entity.Type == "" || entity.ID == "" {
			return nil, authz.ErrDenied
		}
		selected := map[string]bool{}
		for _, grant := range facts.EntityPermissions {
			if grant.Type != entity.Type || grant.ID != authz.EntityID(entity.ID) {
				continue
			}
			for _, permission := range grant.Permissions {
				if role := roles[entityRoleKey{entity.Type, permission}]; role != "" {
					selected[role] = true
				}
			}
		}
		result := make([]string, 0, len(selected))
		for role := range selected {
			result = append(result, role)
		}
		sort.Strings(result)
		return result, nil
	}, nil
}
