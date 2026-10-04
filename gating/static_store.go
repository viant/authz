package gating

import (
	"context"
	"fmt"

	"github.com/viant/authz"
)

// Binding is a host-owned, versioned requirement mapping for one exact
// resource/action. It is suitable for existing file-backed windows without a
// reporting database. Configuration reloads construct a new immutable store.
type Binding struct {
	Resource authz.Resource       `json:"resource"`
	Action   string               `json:"action"`
	Document RequirementsDocument `json:"document"`
}

type bindingKey struct {
	resource authz.Resource
	action   string
}

type StaticStore struct {
	documents map[bindingKey]RequirementsDocument
}

func NewStaticStore(bindings []Binding) (*StaticStore, error) {
	store := &StaticStore{documents: make(map[bindingKey]RequirementsDocument, len(bindings))}
	for _, binding := range bindings {
		resource := binding.Resource
		if resource.Kind == "" || resource.ID == "" || resource.Version == "" || resource.Tenant == "" || binding.Action == "" || binding.Document.Revision == "" || !validRequirements(binding.Document.Requirements) {
			return nil, fmt.Errorf("invalid authorization requirement binding")
		}
		key := bindingKey{resource: resource, action: binding.Action}
		if _, exists := store.documents[key]; exists {
			return nil, fmt.Errorf("duplicate authorization requirement binding")
		}
		store.documents[key] = cloneDocument(binding.Document)
	}
	return store, nil
}

func (s *StaticStore) GetRequirements(ctx context.Context, resource authz.Resource, action string) (RequirementsDocument, error) {
	if s == nil || ctx == nil || ctx.Err() != nil {
		return RequirementsDocument{}, ErrUnavailable
	}
	doc, ok := s.documents[bindingKey{resource: resource, action: action}]
	if !ok {
		return RequirementsDocument{}, authz.ErrDenied
	}
	return cloneDocument(doc), nil
}
