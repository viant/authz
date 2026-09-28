package authz

import (
	"sort"
	"strings"
)

// EntityPermission attaches opaque application-defined permissions directly to
// one entity. It implies neither ancestry nor a global role. Providers supply a
// list of verified grants; applications define what each permission permits.
type EntityPermission struct {
	Type        string   `json:"type"`
	ID          EntityID `json:"id"`
	Permissions []string `json:"permissions"`
}

// HasPermission checks exact entity identity and permission membership only.
// It never treats a permission such as "admin" as a universal bypass.
func HasPermission(grants []EntityPermission, entityType string, id EntityID, permission string) bool {
	if entityType == "" || id == "" || permission == "" {
		return false
	}
	for _, grant := range grants {
		if grant.Type != entityType || grant.ID != id {
			continue
		}
		for _, allowed := range grant.Permissions {
			if allowed == permission {
				return true
			}
		}
	}
	return false
}

// ValidateEntityPermissions validates trusted-provider data before it is used.
func ValidateEntityPermissions(grants []EntityPermission) error {
	seen := map[Entity]bool{}
	for _, grant := range grants {
		entity := Entity{Type: grant.Type, ID: string(grant.ID)}
		if !validEntityType(grant.Type) || grant.ID == "" || strings.TrimSpace(string(grant.ID)) != string(grant.ID) || seen[entity] {
			return ErrDenied
		}
		seen[entity] = true
		permissions := map[string]bool{}
		for _, permission := range grant.Permissions {
			if permission == "" || strings.TrimSpace(permission) != permission || permissions[permission] {
				return ErrDenied
			}
			permissions[permission] = true
		}
	}
	return nil
}

// EntityPermissionIndex gives SQL criteria direct slices by type and permission.
// It is a runtime view; canonical provider/storage grants remain a record list.
type EntityPermissionIndex map[string]map[string][]string

// IndexEntityPermissions intersects grants with the mandatory entity decision.
// Returned slices are detached from provider data and include no removed IDs.
func IndexEntityPermissions(grants []EntityPermission, decision Decision) (EntityPermissionIndex, error) {
	if err := ValidateEntityPermissions(grants); err != nil {
		return nil, err
	}
	if _, err := Intersect(decision, decision); err != nil {
		return nil, err
	}
	if !decision.Bounded {
		return nil, ErrDenied
	}
	allowed := map[Entity]bool{}
	for _, entity := range decision.Entities {
		allowed[entity] = true
	}
	index := EntityPermissionIndex{}
	for _, grant := range grants {
		if !allowed[Entity{Type: grant.Type, ID: string(grant.ID)}] {
			continue
		}
		if index[grant.Type] == nil {
			index[grant.Type] = map[string][]string{}
		}
		for _, permission := range grant.Permissions {
			index[grant.Type][permission] = append(index[grant.Type][permission], string(grant.ID))
		}
	}
	for _, permissions := range index {
		for permission, ids := range permissions {
			sort.Strings(ids)
			permissions[permission] = ids
		}
	}
	return index, nil
}
