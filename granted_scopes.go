package authz

import "strings"

// validScopeNames rejects malformed or duplicate scope names. OAuth scope names
// are printable ASCII tokens separated by spaces in a credential's scope claim.
func validScopeNames(scopes []string) bool {
	seen := make(map[string]bool, len(scopes))
	for _, scope := range scopes {
		if scope == "" || seen[scope] {
			return false
		}
		for _, char := range scope {
			if char < '!' || char > '~' || char == '"' || char == '\\' {
				return false
			}
		}
		seen[scope] = true
	}
	return true
}

// ParseGrantedScopes parses the standard space-delimited OAuth scope claim.
// An absent claim grants no scopes; malformed claims fail closed.
func ParseGrantedScopes(claim string) ([]string, error) {
	if claim == "" {
		return nil, nil
	}
	values := strings.Split(claim, " ")
	if !validScopeNames(values) {
		return nil, ErrDenied
	}
	return values, nil
}

func hasGrantedScopes(granted, required []string) bool {
	if !validScopeNames(granted) || !validScopeNames(required) {
		return false
	}
	available := make(map[string]bool, len(granted))
	for _, scope := range granted {
		available[scope] = true
	}
	for _, scope := range required {
		if !available[scope] {
			return false
		}
	}
	return true
}
