package gating

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/viant/authz"
)

// RequirementsWriter stores a new immutable revision only if expectedRevision
// still names the current document. The host owns persistence and revision
// allocation; a caller cannot choose a current revision by writing one.
type RequirementsWriter interface {
	ReplaceRequirements(context.Context, authz.Resource, string, string, Requirements) (RequirementsDocument, error)
}

// ActorRequirementsWriter records the subject proven by manageAccess. Hosts
// with audit-capable stores implement this without changing older writers.
type ActorRequirementsWriter interface {
	ReplaceRequirementsAs(context.Context, authz.Resource, string, string, Requirements, string) (RequirementsDocument, error)
}

type Administration struct {
	ACL     *authz.Service
	Store   RequirementsStore
	Writer  RequirementsWriter
	Choices ChoicesProvider
}

type Choice struct {
	ID    string `json:"id"`
	Label string `json:"label,omitempty"`
}
type EditorChoices struct {
	Exposures            []Choice            `json:"exposures,omitempty"`
	Roles                []Choice            `json:"roles,omitempty"`
	EntityTypes          []Choice            `json:"entityTypes,omitempty"`
	EntityPermissions    map[string][]Choice `json:"entityPermissions,omitempty"`
	SelectionParameters  []Choice            `json:"selectionParameters,omitempty"`
	EntitlementProviders []Choice            `json:"entitlementProviders,omitempty"`
	EntitlementKeys      map[string][]Choice `json:"entitlementKeys,omitempty"`
}
type EditorContext struct {
	CanManage bool          `json:"canManage"`
	Choices   EditorChoices `json:"choices"`
}
type ChoicesProvider interface {
	ResolveChoices(context.Context, authz.Resource, string) (EditorChoices, error)
}

func (a *Administration) Context(ctx context.Context, resource authz.Resource, action string) (EditorContext, error) {
	if _, err := a.Get(ctx, resource, action); err != nil {
		return EditorContext{}, err
	}
	decision, _, _, err := a.ACL.AuthorizeWithStatus(ctx, authz.Request{Resource: resource, Action: "manageAccess"})
	if errors.Is(err, authz.ErrUnavailable) {
		return EditorContext{}, ErrUnavailable
	}
	result := EditorContext{CanManage: a.Writer != nil && err == nil && !decision.Bounded}
	if a.Choices == nil {
		return result, nil
	}
	choices, err := a.Choices.ResolveChoices(ctx, resource, action)
	if err != nil {
		return EditorContext{}, ErrUnavailable
	}
	result.Choices = cloneEditorChoices(choices)
	return result, nil
}

func cloneEditorChoices(value EditorChoices) EditorChoices {
	value.Exposures = append([]Choice(nil), value.Exposures...)
	value.Roles = append([]Choice(nil), value.Roles...)
	value.EntityTypes = append([]Choice(nil), value.EntityTypes...)
	value.SelectionParameters = append([]Choice(nil), value.SelectionParameters...)
	value.EntitlementProviders = append([]Choice(nil), value.EntitlementProviders...)
	if value.EntityPermissions != nil {
		copy := map[string][]Choice{}
		for key, items := range value.EntityPermissions {
			copy[key] = append([]Choice(nil), items...)
		}
		value.EntityPermissions = copy
	}
	if value.EntitlementKeys != nil {
		copy := map[string][]Choice{}
		for key, items := range value.EntitlementKeys {
			copy[key] = append([]Choice(nil), items...)
		}
		value.EntitlementKeys = copy
	}
	return value
}

func (a *Administration) Get(ctx context.Context, resource authz.Resource, action string) (RequirementsDocument, error) {
	if a == nil || a.ACL == nil || a.Store == nil || ctx == nil || ctx.Err() != nil || action == "" {
		return RequirementsDocument{}, authz.ErrDenied
	}
	decision, _, _, err := a.ACL.AuthorizeWithStatus(ctx, authz.Request{Resource: resource, Action: "viewAccess"})
	if errors.Is(err, authz.ErrUnavailable) {
		return RequirementsDocument{}, ErrUnavailable
	}
	if err != nil || decision.Bounded {
		return RequirementsDocument{}, authz.ErrDenied
	}
	doc, err := a.Store.GetRequirements(ctx, resource, action)
	if err != nil {
		return RequirementsDocument{}, requirementError(err)
	}
	if doc.Revision == "" || !validRequirements(doc.Requirements) {
		return RequirementsDocument{}, authz.ErrDenied
	}
	return cloneDocument(doc), nil
}

func (a *Administration) Replace(ctx context.Context, resource authz.Resource, action, expectedRevision string, requirements Requirements) (RequirementsDocument, error) {
	if a == nil || a.ACL == nil || a.Store == nil || a.Writer == nil || action == "" || expectedRevision == "" || !validRequirements(requirements) {
		return RequirementsDocument{}, authz.ErrDenied
	}
	decision, facts, _, err := a.ACL.AuthorizeWithStatus(ctx, authz.Request{Resource: resource, Action: "manageAccess"})
	if errors.Is(err, authz.ErrUnavailable) {
		return RequirementsDocument{}, ErrUnavailable
	}
	if err != nil || decision.Bounded {
		return RequirementsDocument{}, authz.ErrDenied
	}
	if ctx.Err() != nil {
		return RequirementsDocument{}, ctx.Err()
	}
	current, err := a.Store.GetRequirements(ctx, resource, action)
	if err != nil {
		return RequirementsDocument{}, requirementError(err)
	}
	if current.Revision == "" {
		return RequirementsDocument{}, authz.ErrDenied
	}
	if current.Revision != expectedRevision {
		return RequirementsDocument{}, authz.ErrConflict
	}
	var updated RequirementsDocument
	if audited, ok := a.Writer.(ActorRequirementsWriter); ok {
		if facts.Subject == "" {
			return RequirementsDocument{}, authz.ErrDenied
		}
		updated, err = audited.ReplaceRequirementsAs(ctx, resource, action, expectedRevision, cloneRequirements(requirements), facts.Subject)
	} else {
		updated, err = a.Writer.ReplaceRequirements(ctx, resource, action, expectedRevision, cloneRequirements(requirements))
	}
	if err != nil {
		return RequirementsDocument{}, requirementError(err)
	}
	if updated.Revision == "" || updated.Revision == expectedRevision || !validRequirements(updated.Requirements) {
		return RequirementsDocument{}, fmt.Errorf("requirements writer returned invalid revision")
	}
	return cloneDocument(updated), nil
}

func requirementError(err error) error {
	switch {
	case errors.Is(err, authz.ErrDenied), errors.Is(err, sql.ErrNoRows):
		return authz.ErrDenied
	case errors.Is(err, authz.ErrConflict):
		return authz.ErrConflict
	default:
		return ErrUnavailable
	}
}

func cloneDocument(doc RequirementsDocument) RequirementsDocument {
	doc.Requirements = cloneRequirements(doc.Requirements)
	return doc
}

func cloneRequirements(value Requirements) Requirements {
	value.RequiredExposures = append([]string(nil), value.RequiredExposures...)
	value.AllowedRoles = append([]string(nil), value.AllowedRoles...)
	if value.Entity != nil {
		copied := *value.Entity
		value.Entity = &copied
	}
	if value.Entitlement != nil {
		copied := *value.Entitlement
		value.Entitlement = &copied
	}
	return value
}
