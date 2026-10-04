package gating

import (
	"context"
	"fmt"
	"strings"

	"github.com/viant/authz"
)

type ChoiceBinding struct {
	Resource authz.Resource `json:"resource"`
	Action   string         `json:"action"`
	Choices  EditorChoices  `json:"choices"`
}

// StaticChoices is a trusted exact resource/action editor catalog. It carries
// display options only; it never grants the ability to read or edit a gate.
type StaticChoices struct{ choices map[bindingKey]EditorChoices }

var _ ChoicesProvider = (*StaticChoices)(nil)

func NewStaticChoices(bindings []ChoiceBinding) (*StaticChoices, error) {
	result := &StaticChoices{choices: make(map[bindingKey]EditorChoices, len(bindings))}
	for _, binding := range bindings {
		r := binding.Resource
		if r.Kind == "" || r.ID == "" || r.Version == "" || r.Tenant == "" || binding.Action == "" || strings.TrimSpace(binding.Action) != binding.Action || !validEditorChoices(binding.Choices) {
			return nil, fmt.Errorf("invalid gate editor choices binding")
		}
		key := bindingKey{resource: r, action: binding.Action}
		if _, exists := result.choices[key]; exists {
			return nil, fmt.Errorf("duplicate gate editor choices binding")
		}
		result.choices[key] = cloneEditorChoices(binding.Choices)
	}
	return result, nil
}

func (s *StaticChoices) ResolveChoices(ctx context.Context, resource authz.Resource, action string) (EditorChoices, error) {
	if s == nil || ctx == nil || ctx.Err() != nil {
		return EditorChoices{}, ErrUnavailable
	}
	choices, ok := s.choices[bindingKey{resource: resource, action: action}]
	if !ok {
		return EditorChoices{}, authz.ErrDenied
	}
	return cloneEditorChoices(choices), nil
}

func validEditorChoices(choices EditorChoices) bool {
	validList := func(items []Choice) bool {
		seen := map[string]bool{}
		for _, item := range items {
			if item.ID == "" || strings.TrimSpace(item.ID) != item.ID || strings.TrimSpace(item.Label) != item.Label || seen[item.ID] {
				return false
			}
			seen[item.ID] = true
		}
		return true
	}
	for _, list := range [][]Choice{choices.Exposures, choices.Roles, choices.EntityTypes, choices.SelectionParameters, choices.EntitlementProviders} {
		if !validList(list) {
			return false
		}
	}
	for _, values := range []map[string][]Choice{choices.EntityPermissions, choices.EntitlementKeys} {
		for key, list := range values {
			if key == "" || strings.TrimSpace(key) != key || !validList(list) {
				return false
			}
		}
	}
	return true
}
