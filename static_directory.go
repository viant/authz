package authz

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// PolicyChoiceBinding is a server-owned editor directory for one exact policy
// resource. Its options are display choices, never identity facts or grants.
type PolicyChoiceBinding struct {
	Resource Resource `json:"resource"`
	Choices  Choices  `json:"choices"`
}

// StaticDirectory rechecks viewAccess before returning configured choices.
// It is useful where the agreed IdP has no organization directory endpoint.
type StaticDirectory struct {
	bindings map[Resource]Choices
	access   *Service
}

var _ Directory = (*StaticDirectory)(nil)

func NewStaticDirectory(bindings []PolicyChoiceBinding, access *Service) (*StaticDirectory, error) {
	if access == nil || access.Store == nil || access.Provider == nil {
		return nil, fmt.Errorf("policy choice directory requires a checked authorization service")
	}
	result := &StaticDirectory{bindings: make(map[Resource]Choices, len(bindings)), access: access}
	for _, binding := range bindings {
		r := binding.Resource
		if r.Kind == "" || r.ID == "" || r.Version == "" || r.Tenant == "" || !validPolicyChoices(binding.Choices) {
			return nil, fmt.Errorf("invalid policy choice binding")
		}
		if _, exists := result.bindings[r]; exists {
			return nil, fmt.Errorf("duplicate policy choice binding")
		}
		result.bindings[r] = clonePolicyChoices(binding.Choices)
	}
	return result, nil
}

func (d *StaticDirectory) Choices(ctx context.Context, resource Resource, expected Facts) (Choices, error) {
	if d == nil || d.access == nil || ctx == nil || ctx.Err() != nil {
		return Choices{}, ErrDenied
	}
	choices, present := d.bindings[resource]
	if !present {
		return Choices{}, ErrDenied
	}
	decision, current, err := d.access.AuthorizeWithFacts(ctx, Request{Resource: resource, Action: "viewAccess"})
	if errors.Is(err, ErrDenied) {
		return Choices{}, ErrDenied
	}
	if err != nil {
		return Choices{}, ErrUnavailable
	}
	if decision.Bounded || !sameManagementFacts(current, expected) {
		return Choices{}, ErrDenied
	}
	return clonePolicyChoices(choices), nil
}

func validPolicyChoices(value Choices) bool {
	seen := func(items []Choice, entity bool) bool {
		ids := map[string]bool{}
		for _, item := range items {
			id := item.ID
			if entity {
				if item.Entity == nil || item.Entity.Type == "" || item.Entity.ID == "" || strings.TrimSpace(item.Entity.Type) != item.Entity.Type || strings.TrimSpace(item.Entity.ID) != item.Entity.ID {
					return false
				}
				id = item.Entity.Type + "\x00" + item.Entity.ID
			} else if id == "" || strings.TrimSpace(id) != id {
				return false
			}
			if strings.TrimSpace(item.Label) != item.Label || ids[id] {
				return false
			}
			ids[id] = true
		}
		return true
	}
	if !seen(value.Subjects, false) || !seen(value.Roles, false) || !seen(value.Exposures, false) || !seen(value.Entities, true) {
		return false
	}
	types := map[string]bool{}
	for _, item := range value.EntityTypes {
		if item == "" || strings.TrimSpace(item) != item || types[item] {
			return false
		}
		types[item] = true
	}
	return true
}

func clonePolicyChoices(input Choices) Choices {
	clone := func(items []Choice) []Choice {
		result := make([]Choice, len(items))
		for i, item := range items {
			result[i] = item
			if item.Entity != nil {
				entity := *item.Entity
				result[i].Entity = &entity
			}
		}
		return result
	}
	return Choices{Subjects: clone(input.Subjects), Roles: clone(input.Roles), Exposures: clone(input.Exposures), Entities: clone(input.Entities), EntityTypes: append([]string(nil), input.EntityTypes...)}
}
