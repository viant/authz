package authz

import (
	"context"
	"errors"
)

type Choice struct {
	ID     string  `json:"id,omitempty"`
	Label  string  `json:"label"`
	Entity *Entity `json:"entity,omitempty"`
}

type Choices struct {
	Subjects    []Choice `json:"subject"`
	Roles       []Choice `json:"role"`
	Exposures   []Choice `json:"exposure"`
	Entities    []Choice `json:"entity"`
	EntityTypes []string `json:"entityTypes"`
}

// Directory optionally supplies a tenant-scoped administrative catalog from the
// trusted identity provider. Implementations must authorize their own reads.
type Directory interface {
	Choices(context.Context, Resource, Facts) (Choices, error)
}

type EditorContext struct {
	Choices   Choices `json:"choices"`
	CanManage bool    `json:"canManage"`
	Source    string  `json:"source"`
}

func (s *Service) EditorContext(ctx context.Context, r Resource) (EditorContext, error) {
	doc, facts, err := s.load(ctx, r, "viewAccess")
	if err != nil {
		return EditorContext{}, err
	}
	d, manageErr := s.evaluate(ctx, Request{Resource: r, Action: "manageAccess"}, doc, facts)
	return s.editorContextWithFacts(ctx, r, facts, manageErr == nil && !d.Bounded)
}

// EditorContextWithStatus keeps identity and authority failures distinct from
// an explicit management denial. It rejects policy-revision or fact drift
// between the checked viewAccess and manageAccess decisions.
func (s *Service) EditorContextWithStatus(ctx context.Context, r Resource) (EditorContext, error) {
	view, facts, doc, err := s.authorizeDocumentWithStatus(ctx, Request{Resource: r, Action: "viewAccess"})
	if err != nil {
		return EditorContext{}, err
	}
	if view.Bounded {
		return EditorContext{}, ErrDenied
	}
	decision, current, revision, manageErr := s.AuthorizeWithStatus(ctx, Request{Resource: r, Action: "manageAccess"})
	if errors.Is(manageErr, ErrUnavailable) || errors.Is(manageErr, ErrIdentityDenied) {
		return EditorContext{}, manageErr
	}
	if manageErr != nil && !errors.Is(manageErr, ErrDenied) {
		return EditorContext{}, ErrUnavailable
	}
	if revision != doc.Revision {
		return EditorContext{}, ErrUnavailable
	}
	if manageErr == nil && !sameManagementFacts(facts, current) {
		return EditorContext{}, ErrUnavailable
	}
	if s.Provider == nil {
		return EditorContext{}, ErrUnavailable
	}
	verified, err := s.Provider.Resolve(ctx)
	if err != nil {
		if errors.Is(err, ErrDenied) {
			return EditorContext{}, ErrIdentityDenied
		}
		return EditorContext{}, ErrUnavailable
	}
	if !sameManagementFacts(facts, verified) {
		return EditorContext{}, ErrUnavailable
	}
	result, err := s.editorContextWithFacts(ctx, r, facts, manageErr == nil && !decision.Bounded)
	if err != nil {
		return EditorContext{}, err
	}
	if s.Directory == nil {
		return result, nil
	}
	// A directory may perform remote work after the initial policy and
	// management reads. Do not return its choices with stale canManage state.
	finalView, finalFacts, finalRevision, finalErr := s.AuthorizeWithStatus(ctx, Request{Resource: r, Action: "viewAccess"})
	if errors.Is(finalErr, ErrIdentityDenied) {
		return EditorContext{}, ErrIdentityDenied
	}
	if errors.Is(finalErr, ErrUnavailable) || finalRevision != doc.Revision {
		return EditorContext{}, ErrUnavailable
	}
	if errors.Is(finalErr, ErrDenied) || finalView.Bounded {
		return EditorContext{}, ErrDenied
	}
	if finalErr != nil || !sameManagementFacts(facts, finalFacts) {
		return EditorContext{}, ErrUnavailable
	}
	return result, nil
}

func (s *Service) editorContextWithFacts(ctx context.Context, r Resource, facts Facts, canManage bool) (EditorContext, error) {
	result := EditorContext{CanManage: canManage, Source: "verified-principal"}
	if s.Directory != nil {
		var err error
		result.Choices, err = s.Directory.Choices(ctx, r, facts)
		if err != nil {
			if errors.Is(err, ErrDenied) {
				return EditorContext{}, ErrDenied
			}
			return EditorContext{}, ErrUnavailable
		}
		result.Source = "provider-directory"
		return result, nil
	}
	result.Choices.Subjects = []Choice{{ID: facts.Subject, Label: facts.Subject}}
	for _, role := range facts.Roles {
		result.Choices.Roles = append(result.Choices.Roles, Choice{ID: role, Label: role})
	}
	for _, exposure := range facts.Exposures {
		result.Choices.Exposures = append(result.Choices.Exposures, Choice{ID: exposure, Label: exposure})
	}
	types := map[string]bool{}
	flat, err := facts.FlatEntities()
	if err != nil {
		return EditorContext{}, ErrDenied
	}
	for _, entity := range flat {
		e := entity
		result.Choices.Entities = append(result.Choices.Entities, Choice{Entity: &e, Label: e.Type + ": " + e.ID})
		if !types[e.Type] {
			types[e.Type] = true
			result.Choices.EntityTypes = append(result.Choices.EntityTypes, e.Type)
		}
	}
	return result, nil
}
