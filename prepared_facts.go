package authz

import "slices"

// PreparedFacts is an immutable, request-owned snapshot of verified facts.
// It grants no authority: callers still supply verified identity and leases.
// Reuse one snapshot across an evaluation's rules, gates and candidate policies.
// Its maps are private and never retained in a global cache.
type PreparedFacts struct {
	facts         Facts
	roles         map[string]struct{}
	exposures     map[string]struct{}
	groups        map[string]struct{}
	scopes        map[string]struct{}
	scopesValid   bool
	entities      []Entity
	entitiesValid bool
}

// PrepareFacts copies the verified facts and builds each membership set once.
// Invalid entity/scope facts remain invalid for protected evaluation; public
// consumption retains Evaluate's existing behavior with those unused facts.
func PrepareFacts(facts Facts) *PreparedFacts {
	facts = clonePreparedFacts(facts)
	entities, err := facts.FlatEntities()
	return &PreparedFacts{facts: facts, roles: factSet(facts.Roles), exposures: factSet(facts.Exposures), groups: factSet(facts.MembershipGroups), scopes: factSet(facts.GrantedScopes), scopesValid: validScopeNames(facts.GrantedScopes), entities: slices.Clone(entities), entitiesValid: err == nil}
}
func factSet(values []string) map[string]struct{} {
	out := make(map[string]struct{}, len(values))
	for _, value := range values {
		if value != "" {
			out[value] = struct{}{}
		}
	}
	return out
}
func factMember(values map[string]struct{}, value string) bool {
	if value == "" {
		return false
	}
	_, ok := values[value]
	return ok
}

// HasRoleLiteral checks an exact role; "*" is literal in gate requirements.
func (p *PreparedFacts) HasRoleLiteral(value string) bool {
	return p != nil && factMember(p.roles, value)
}

// HasExposureLiteral checks an exact exposure, including a literal "*".
func (p *PreparedFacts) HasExposureLiteral(value string) bool {
	return p != nil && factMember(p.exposures, value)
}

// HasGroup checks exact verified membership, independently of roles/exposures.
func (p *PreparedFacts) HasGroup(value string) bool { return p != nil && factMember(p.groups, value) }

// Facts returns a defensive copy; mutations cannot change this snapshot.
func (p *PreparedFacts) Facts() Facts {
	if p == nil {
		return Facts{}
	}
	return clonePreparedFacts(p.facts)
}
func clonePreparedFacts(f Facts) Facts {
	f.Roles = slices.Clone(f.Roles)
	f.Exposures = slices.Clone(f.Exposures)
	f.MembershipGroups = slices.Clone(f.MembershipGroups)
	f.GrantedScopes = slices.Clone(f.GrantedScopes)
	f.Entities = slices.Clone(f.Entities)
	if f.EntityGroups != nil {
		groups := make(EntityGroups, len(f.EntityGroups))
		for kind, ids := range f.EntityGroups {
			groups[kind] = slices.Clone(ids)
		}
		f.EntityGroups = groups
	}
	f.EntityPermissions = slices.Clone(f.EntityPermissions)
	for i := range f.EntityPermissions {
		f.EntityPermissions[i].Permissions = slices.Clone(f.EntityPermissions[i].Permissions)
	}
	return f
}
func (p *PreparedFacts) hasScopes(required []string) bool {
	if p == nil || !p.scopesValid || !validScopeNames(required) {
		return false
	}
	for _, scope := range required {
		if !factMember(p.scopes, scope) {
			return false
		}
	}
	return true
}
