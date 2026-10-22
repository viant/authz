package authz

import (
	"context"
	"sort"
	"strings"
)

// NamedReference follows a reusable policy's current head. Revision is the
// minimum reviewed revision, not a frozen copy; every resolved head is returned
// separately for the caller's freshness fence. Resource IDs survive renaming.
const NamedDefinitionAction = "$definition"

// NamedDefinition is the editable payload of a policy resource. Its policies
// never confer access to editing the policy resource itself.
type NamedDefinition struct {
	DisplayName string            `json:"displayName"`
	Policies    map[string]Policy `json:"policies"`
	Archived    bool              `json:"archived,omitempty"`
}

func (d NamedDefinition) Validate() error {
	if strings.TrimSpace(d.DisplayName) != d.DisplayName || d.DisplayName == "" || len(d.DisplayName) > 255 || len(d.Policies) == 0 || len(d.Policies) > 128 {
		return ErrDenied
	}
	for action, policy := range d.Policies {
		if action == NamedDefinitionAction || policy.Definition != nil || policy.Named != nil || (policy.Mode != "protected" && policy.Mode != "deny") || ValidatePolicy(action, policy) != nil {
			return ErrDenied
		}
	}
	return nil
}

func Definition(document Document) (NamedDefinition, error) {
	entry, ok := document.Policies[NamedDefinitionAction]
	if document.Resource.Kind != "policy" || !ok || entry.Mode != "definition" || entry.Definition == nil || entry.Definition.Validate() != nil || entry.Definition.Archived {
		return NamedDefinition{}, ErrDenied
	}
	return *entry.Definition, nil
}

type NamedReference struct {
	Resource Resource `json:"resource"`
	Revision int64    `json:"revision"`
}

func (r NamedReference) Valid() bool {
	clean := func(s string) bool { return s != "" && strings.TrimSpace(s) == s }
	return r.Resource.Kind == "policy" && clean(r.Resource.ID) && clean(r.Resource.Version) && clean(r.Resource.Tenant) && r.Resource.Tenant != "*" && r.Revision > 0
}

// NamedDependency is an exact input revision, not an authorization decision.
type NamedDependency struct {
	Resource Resource `json:"resource"`
	Revision int64    `json:"revision"`
}

// ResolveNamedDocument compiles reusable references into ordinary policies.
// It retains local restrictions and scopes, rejects ambiguous entity scope
// intersections, and uses exact-action-before-wildcard semantics at every level.
// Hosts must fence all returned dependencies before releasing protected data.
// This function neither resolves identity nor caches authorization decisions.
func ResolveNamedDocument(ctx context.Context, source Store, document Document) (Document, []NamedDependency, error) {
	if ctx == nil || ctx.Err() != nil || source == nil || document.Resource.Tenant == "" || ValidateDocument(document) != nil {
		return Document{}, nil, ErrDenied
	}
	loaded := map[Resource]Document{}
	visiting := map[Resource]bool{document.Resource: true}
	var resolve func(string, Policy, int) (Policy, error)
	resolve = func(action string, policy Policy, depth int) (Policy, error) {
		if depth > 32 || ValidatePolicy(action, policy) != nil {
			return Policy{}, ErrDenied
		}
		if policy.Named == nil {
			return policy, nil
		}
		ref := *policy.Named
		if !ref.Valid() || ref.Resource.Tenant != document.Resource.Tenant || visiting[ref.Resource] {
			return Policy{}, ErrDenied
		}
		target, ok := loaded[ref.Resource]
		if !ok {
			var err error
			target, err = source.Get(ctx, ref.Resource)
			if err != nil {
				return Policy{}, err
			}
			if target.Resource != ref.Resource || target.Revision < 1 {
				return Policy{}, ErrDenied
			}
			loaded[ref.Resource] = target
		}
		if target.Revision < ref.Revision {
			return Policy{}, ErrConflict
		}
		definition, err := Definition(target)
		if err != nil {
			return Policy{}, err
		}
		next, ok := PolicyForAction(definition.Policies, action)
		if !ok {
			return Policy{Mode: "deny", Priority: policy.Priority}, nil
		}
		visiting[ref.Resource] = true
		next, err = resolve(action, next, depth+1)
		delete(visiting, ref.Resource)
		if err != nil {
			return Policy{}, err
		}
		if next.Mode == "deny" {
			return Policy{Mode: "deny", Priority: policy.Priority}, nil
		}
		// A public consumption policy cannot supply verified membership authority.
		if next.Mode != "protected" || next.Rule == nil {
			return Policy{}, ErrDenied
		}
		policy.Named = nil
		policy.Mode = "protected"
		if policy.Rule == nil {
			policy.Rule = next.Rule
		} else {
			policy.Rule = &Rule{Kind: "all", Rules: []Rule{*policy.Rule, *next.Rule}}
		}
		if policy.EntityType != "" && next.EntityType != "" && policy.EntityType != next.EntityType {
			return Policy{}, ErrDenied
		}
		if policy.EntityType == "" {
			policy.EntityType = next.EntityType
		}
		scopes := append(append([]string{}, policy.RequiredScopes...), next.RequiredScopes...)
		seen := map[string]bool{}
		policy.RequiredScopes = nil
		for _, scope := range scopes {
			if !seen[scope] {
				seen[scope] = true
				policy.RequiredScopes = append(policy.RequiredScopes, scope)
			}
		}
		if err := ValidatePolicy(action, policy); err != nil {
			return Policy{}, err
		}
		return policy, nil
	}
	result := cloneStaticDocument(document)
	// A named wildcard can contain exact overrides. Materialize every action
	// mentioned anywhere in its reference graph before compiling the fallback.
	var collect func(Policy, map[Resource]bool, int) error
	collect = func(policy Policy, path map[Resource]bool, depth int) error {
		if policy.Named == nil {
			return nil
		}
		ref := *policy.Named
		if depth > 32 || !ref.Valid() || ref.Resource.Tenant != document.Resource.Tenant || path[ref.Resource] {
			return ErrDenied
		}
		target, ok := loaded[ref.Resource]
		if !ok {
			var err error
			target, err = source.Get(ctx, ref.Resource)
			if err != nil {
				return err
			}
			if target.Resource != ref.Resource || target.Revision < 1 {
				return ErrDenied
			}
			loaded[ref.Resource] = target
		}
		if target.Revision < ref.Revision {
			return ErrConflict
		}
		nextPath := make(map[Resource]bool, len(path)+1)
		for resource, value := range path {
			nextPath[resource] = value
		}
		nextPath[ref.Resource] = true
		definition, err := Definition(target)
		if err != nil {
			return err
		}
		for action, next := range definition.Policies {
			if _, exists := result.Policies[action]; !exists {
				if fallback, present := document.Policies["*"]; present {
					result.Policies[action] = fallback
				}
			}
			if err := collect(next, nextPath, depth+1); err != nil {
				return err
			}
		}
		return nil
	}
	for _, policy := range document.Policies {
		if err := collect(policy, map[Resource]bool{document.Resource: true}, 0); err != nil {
			return Document{}, nil, err
		}
	}
	for action, policy := range result.Policies {
		if action == NamedDefinitionAction {
			continue
		}
		compiled, err := resolve(action, policy, 0)
		if err != nil {
			return Document{}, nil, err
		}
		result.Policies[action] = compiled
	}
	if ctx.Err() != nil {
		return Document{}, nil, ErrDenied
	}
	dependencies := make([]NamedDependency, 0, len(loaded))
	for resource, doc := range loaded {
		dependencies = append(dependencies, NamedDependency{Resource: resource, Revision: doc.Revision})
	}
	sort.Slice(dependencies, func(i, j int) bool {
		a, b := dependencies[i].Resource, dependencies[j].Resource
		if a.Tenant != b.Tenant {
			return a.Tenant < b.Tenant
		}
		if a.ID != b.ID {
			return a.ID < b.ID
		}
		return a.Version < b.Version
	})
	return cloneStaticDocument(result), dependencies, nil
}
