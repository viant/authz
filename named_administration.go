package authz

import (
	"context"
	"sort"
	"strings"
	"time"
)

// PolicyInventory is a trusted tenant-scoped inventory of existing policy
// resources, including working and published asset revisions.
type PolicyInventory interface {
	PolicyResources(context.Context, string) ([]Resource, error)
}

type NamedPolicy struct {
	Resource    Resource          `json:"resource"`
	Revision    int64             `json:"revision"`
	DisplayName string            `json:"displayName"`
	Policies    map[string]Policy `json:"policies"`
}
type NamedImpact struct {
	Resource Resource `json:"resource"`
	Revision int64    `json:"revision"`
	Actions  []string `json:"actions"`
}

// NamedAdministration reuses checked policy administration and existing CAS
// documents. Inventory is deployment-owned and must not omit assigned assets.
type NamedAdministration struct {
	Policies  *Administration
	Inventory PolicyInventory
}

func (s *NamedAdministration) actor(ctx context.Context) (Facts, error) {
	if s == nil || s.Policies == nil || s.Policies.Provider == nil || s.Inventory == nil {
		return Facts{}, ErrUnavailable
	}
	f, err := s.Policies.Provider.Resolve(ctx)
	if err != nil {
		return Facts{}, err
	}
	if f.Subject == "" || f.Tenant == "" || f.Issuer == "" || !f.ValidUntil.After(time.Now()) {
		return Facts{}, ErrDenied
	}
	return f, nil
}
func namedView(doc Document) (NamedPolicy, error) {
	d, err := Definition(doc)
	if err != nil {
		return NamedPolicy{}, err
	}
	return NamedPolicy{Resource: doc.Resource, Revision: doc.Revision, DisplayName: d.DisplayName, Policies: d.Policies}, nil
}
func (s *NamedAdministration) List(ctx context.Context) ([]NamedPolicy, error) {
	f, err := s.actor(ctx)
	if err != nil {
		return nil, err
	}
	resources, err := s.Inventory.PolicyResources(ctx, f.Tenant)
	if err != nil {
		return nil, err
	}
	result := []NamedPolicy{}
	for _, r := range resources {
		if r.Kind != "policy" || r.Tenant != f.Tenant {
			continue
		}
		doc, err := s.Policies.Get(ctx, r)
		if err != nil {
			return nil, err
		}
		value, err := namedView(doc)
		if err == nil {
			result = append(result, value)
		}
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].DisplayName != result[j].DisplayName {
			return result[i].DisplayName < result[j].DisplayName
		}
		return result[i].Resource.ID < result[j].Resource.ID
	})
	return result, nil
}
func (s *NamedAdministration) Create(ctx context.Context, id string, definition NamedDefinition) (NamedPolicy, error) {
	f, err := s.actor(ctx)
	if err != nil {
		return NamedPolicy{}, err
	}
	if id == "" || strings.TrimSpace(id) != id || len(id) > 255 || definition.Archived || definition.Validate() != nil {
		return NamedPolicy{}, ErrDenied
	}
	r := Resource{Kind: "policy", ID: id, Version: "logical", Tenant: f.Tenant}
	owner := Policy{Mode: "protected", Rule: &Rule{Kind: "subject", Value: f.Subject}}
	doc, err := s.Policies.Create(ctx, Document{Resource: r, Policies: map[string]Policy{NamedDefinitionAction: {Mode: "definition", Definition: &definition}, "viewAccess": owner, "manageAccess": owner}})
	if err != nil {
		return NamedPolicy{}, err
	}
	return namedView(doc)
}
func (s *NamedAdministration) Update(ctx context.Context, ref NamedReference, definition NamedDefinition) (NamedPolicy, []NamedImpact, error) {
	if _, err := s.actor(ctx); err != nil {
		return NamedPolicy{}, nil, err
	}
	if !ref.Valid() || definition.Archived || definition.Validate() != nil {
		return NamedPolicy{}, nil, ErrDenied
	}
	impacts, err := s.Impact(ctx, ref.Resource)
	if err != nil {
		return NamedPolicy{}, nil, err
	}
	doc, err := s.Policies.Get(ctx, ref.Resource)
	if err != nil {
		return NamedPolicy{}, nil, err
	}
	if doc.Revision != ref.Revision {
		return NamedPolicy{}, nil, ErrConflict
	}
	doc.Policies[NamedDefinitionAction] = Policy{Mode: "definition", Definition: &definition}
	saved, err := s.Policies.Replace(ctx, doc)
	if err != nil {
		return NamedPolicy{}, nil, err
	}
	value, err := namedView(saved)
	return value, impacts, err
}
func (s *NamedAdministration) Impact(ctx context.Context, resource Resource) ([]NamedImpact, error) {
	f, err := s.actor(ctx)
	if err != nil {
		return nil, err
	}
	if resource.Kind != "policy" || resource.Tenant != f.Tenant {
		return nil, ErrDenied
	}
	if _, _, err = s.Policies.replacementActor(ctx, resource); err != nil {
		return nil, err
	}
	resources, err := s.Inventory.PolicyResources(ctx, f.Tenant)
	if err != nil {
		return nil, err
	}
	out := []NamedImpact{}
	for _, r := range resources {
		doc, err := s.Policies.Store.Get(ctx, r)
		if err != nil {
			return nil, err
		}
		if doc.Resource != r || r.Tenant != f.Tenant {
			return nil, ErrDenied
		}
		item := NamedImpact{Resource: r, Revision: doc.Revision}
		for action, p := range doc.Policies {
			if p.Mode == "named" && p.Named != nil && p.Named.Resource == resource {
				item.Actions = append(item.Actions, action)
			}
		}
		if len(item.Actions) > 0 {
			sort.Strings(item.Actions)
			out = append(out, item)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i].Resource, out[j].Resource
		if a.ID != b.ID {
			return a.ID < b.ID
		}
		return a.Version < b.Version
	})
	return out, nil
}
func (s *NamedAdministration) Assign(ctx context.Context, asset Resource, expected int64, actions []string, ref NamedReference) (Document, error) {
	f, err := s.actor(ctx)
	if err != nil {
		return Document{}, err
	}
	if (asset.Kind != "window" && asset.Kind != "namespace") || asset.Tenant != f.Tenant || ref.Resource.Tenant != f.Tenant || !ref.Valid() || len(actions) == 0 {
		return Document{}, ErrDenied
	}
	target, err := s.Policies.Get(ctx, ref.Resource)
	if err != nil {
		return Document{}, err
	}
	if target.Revision != ref.Revision {
		return Document{}, ErrConflict
	}
	if _, err = Definition(target); err != nil {
		return Document{}, err
	}
	doc, err := s.Policies.Get(ctx, asset)
	if err != nil {
		return Document{}, err
	}
	if doc.Revision != expected {
		return Document{}, ErrConflict
	}
	for _, action := range actions {
		if action == "" || action == NamedDefinitionAction {
			return Document{}, ErrDenied
		}
		p, _ := PolicyForAction(doc.Policies, action)
		if p.Mode != "protected" && p.Mode != "named" {
			p = Policy{}
		}
		p.Mode = "named"
		p.Named = &NamedReference{Resource: ref.Resource, Revision: ref.Revision}
		doc.Policies[action] = p
	}
	if _, _, err = ResolveNamedDocument(ctx, s.Policies.Store, doc); err != nil {
		return Document{}, err
	}
	return s.Policies.Replace(ctx, doc)
}

// Archive retains immutable history. Assigned policies cannot be archived.
// Atomic cross-process assignment/archive coordination belongs to the host's
// transaction boundary; a host without it must leave this operation disabled.
func (s *NamedAdministration) Archive(ctx context.Context, ref NamedReference) (Document, error) {
	return Document{}, ErrDenied
}
