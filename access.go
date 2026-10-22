// Package access supplies resource-neutral ACL contracts and evaluation for
// Studio and embedding applications. Authentication providers own fact issuance.
package authz

import (
	"context"
	"errors"
	"time"
)

var ErrDenied = errors.New("access denied")

type Resource struct {
	Kind    string `json:"kind"`
	ID      string `json:"id"`
	Version string `json:"version"`
	Tenant  string `json:"tenant"`
}

type Entity struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

// Facts must originate from a verified OAuth/OIDC identity and its configured
// authorization provider. Exposures are feature entitlements, not publications.
type Facts struct {
	// AuthorityRevision is an optional opaque fingerprint of verified identity
	// and account context. It grants no permissions and excludes rolling leases.
	AuthorityRevision string             `json:"authorityRevision,omitempty"`
	EntityPermissions []EntityPermission `json:"entityPermissions,omitempty"`
	Subject           string             `json:"subject"`
	Tenant            string             `json:"tenant"`
	Issuer            string             `json:"issuer"`
	Roles             []string           `json:"roles"`
	// MembershipGroups are verified membership groups, distinct from application roles.
	MembershipGroups []string `json:"membershipGroups,omitempty"`
	Exposures        []string `json:"exposures"`
	// GrantedScopes are OAuth scopes from a verified credential, not entity bounds.
	GrantedScopes []string `json:"grantedScopes,omitempty"`
	// EntityGroups is the canonical typed authorization fact.
	EntityGroups EntityGroups `json:"allowedEntities,omitempty"`
	// Entities is a compatibility view for existing flat fact providers.
	Entities   []Entity  `json:"-"`
	ValidUntil time.Time `json:"validUntil"`
}

// Provider resolves facts using server-verified credentials in ctx. It must not
// trust a subject, role list or entity list supplied in an operation's payload.
type Provider interface {
	Resolve(context.Context) (Facts, error)
}

type Rule struct {
	Kind   string  `json:"kind"` // subject, role, group, exposure, entity, all, any
	Value  string  `json:"value,omitempty"`
	Entity *Entity `json:"entity,omitempty"`
	Rules  []Rule  `json:"rules,omitempty"`
}

type Policy struct {
	// Definition is non-executable metadata, valid only at the reserved action
	// of a reusable policy resource. It is stored in existing versioned JSON.
	Definition *NamedDefinition `json:"definition,omitempty"`
	// Named is valid only with mode named and narrows the optional local rule
	// using the current head of a reusable policy.
	// Unresolved references are never executable by Evaluate.
	Named *NamedReference `json:"named,omitempty"`
	// Priority orders revision-selection policies. Larger values are evaluated
	// first; equal priorities are valid and the first evaluated match wins.
	Priority int    `json:"priority,omitempty"`
	Mode     string `json:"mode"` // public or protected
	Rule     *Rule  `json:"rule,omitempty"`
	// RequiredScopes are mandatory for a protected action, outside Rule's OR branches.
	RequiredScopes []string `json:"requiredScopes,omitempty"`
	// EntityType requires scoped authorization outside the rule's OR branches.
	EntityType string `json:"entityType,omitempty"`
}

type Request struct {
	Resource Resource
	Action   string
	// Nil selection expands to all allowed entities; empty explicitly denies.
	Selection *[]Entity
}

type Decision struct {
	Entities []Entity
	Bounded  bool
}

// Evaluate checks one explicitly configured action. Callers resolve policies
// from trusted storage and compose dependency decisions separately.
func Evaluate(req Request, policies map[string]Policy, facts Facts, now time.Time) (Decision, error) {
	return EvaluatePrepared(req, policies, PrepareFacts(facts), now)
}

// EvaluatePrepared uses the same immutable fact sets for every rule and policy.
// It preserves Evaluate's semantics without rebuilding role/exposure maps.
func EvaluatePrepared(req Request, policies map[string]Policy, prepared *PreparedFacts, now time.Time) (Decision, error) {
	if prepared == nil {
		return Decision{}, ErrDenied
	}
	facts := prepared.facts
	deny := func() (Decision, error) { return Decision{}, ErrDenied }
	if req.Resource.Kind == "" || req.Resource.ID == "" || req.Resource.Tenant == "" || req.Action == "" {
		return deny()
	}
	p, ok := PolicyForAction(policies, req.Action)
	if !ok {
		return deny()
	}
	if p.Named != nil {
		return deny()
	}
	if req.Resource.Tenant != "*" && req.Resource.Tenant != facts.Tenant {
		return deny()
	}
	switch p.Mode {
	case "public":
		// Public management is forbidden, including unrecognized custom actions.
		switch req.Action {
		case "discover", "describe", "execute", "retrieve":
		default:
			return deny()
		}
		if p.Rule != nil || p.EntityType != "" || len(p.RequiredScopes) != 0 {
			return deny()
		}
	case "protected":
		if !prepared.entitiesValid {
			return deny()
		}
		facts.Entities = prepared.entities
		if facts.Subject == "" || facts.Tenant == "" || facts.Issuer == "" || !facts.ValidUntil.After(now) || p.Rule == nil || !valid(*p.Rule, 0) || !matchesPrepared(*p.Rule, prepared) || !prepared.hasScopes(p.RequiredScopes) {
			return deny()
		}
	default:
		return deny()
	}
	if p.EntityType == "" {
		if req.Selection != nil {
			return deny()
		}
		return Decision{}, nil
	}
	allowed := map[Entity]bool{}
	d := Decision{Bounded: true}
	for _, e := range facts.Entities {
		if e.Type == p.EntityType && e.ID != "" && !allowed[e] {
			allowed[e] = true
			d.Entities = append(d.Entities, e)
		}
	}
	if req.Selection != nil {
		d.Entities = nil
		seen := map[Entity]bool{}
		for _, e := range *req.Selection {
			if !allowed[e] || seen[e] {
				return deny()
			}
			seen[e] = true
			d.Entities = append(d.Entities, e)
		}
	}
	if len(d.Entities) == 0 {
		return deny()
	}
	return d, nil
}

func valid(r Rule, depth int) bool {
	if depth > 32 {
		return false
	}
	switch r.Kind {
	case "all", "any":
		if len(r.Rules) == 0 || r.Value != "" || r.Entity != nil {
			return false
		}
		for _, c := range r.Rules {
			if !valid(c, depth+1) {
				return false
			}
		}
		return true
	case "entity":
		return r.Value == "" && len(r.Rules) == 0 && r.Entity != nil && r.Entity.Type != "" && r.Entity.ID != ""
	case "subject", "role", "exposure", "group":
		return r.Value != "" && r.Entity == nil && len(r.Rules) == 0
	}
	return false
}

func matchesPrepared(r Rule, prepared *PreparedFacts) bool {
	f := prepared.facts
	switch r.Kind {
	case "subject":
		return f.Subject != "" && (f.Subject == r.Value || r.Value == "*")
	case "role":
		return r.Value == "*" && len(prepared.roles) > 0 || prepared.HasRoleLiteral(r.Value)
	case "group":
		return prepared.HasGroup(r.Value)
	case "exposure":
		return r.Value == "*" && len(prepared.exposures) > 0 || prepared.HasExposureLiteral(r.Value)
	case "entity":
		for _, e := range prepared.entities {
			if e.Type == r.Entity.Type && e.ID != "" && (e.ID == r.Entity.ID || r.Entity.ID == "*") {
				return true
			}
		}
	case "all":
		for _, c := range r.Rules {
			if !matchesPrepared(c, prepared) {
				return false
			}
		}
		return true
	case "any":
		for _, c := range r.Rules {
			if matchesPrepared(c, prepared) {
				return true
			}
		}
	}
	return false
}

// PolicyForAction resolves an exact policy before the wildcard fallback.
// An explicit deny therefore overrides an otherwise permissive wildcard.
func PolicyForAction(policies map[string]Policy, action string) (Policy, bool) {
	if action == "" {
		return Policy{}, false
	}
	if policy, ok := policies[action]; ok {
		return policy, true
	}
	policy, ok := policies["*"]
	return policy, ok
}
