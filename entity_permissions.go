package authz

import "strings"

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
