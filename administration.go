package authz

import (
	"context"
	"database/sql"
	"errors"
	"reflect"
	"strings"
	"time"
)

// Creator adds an initial immutable policy revision; implementations must reject
// an existing resource atomically. Actor is supplied by the trusted provider.
type Creator interface {
	Create(context.Context, Document, string) (Document, error)
}

// Administration supplies deployment-owned policy administration permissions.
// Every authenticated principal may read policies in its tenant; only the
// configured roles may create/replace them. An empty EditorRoles denies writes.
// Protected resource execution remains a separate Service.Authorize decision.
type Administration struct {
	Store       Store
	Provider    Provider
	EditorRoles []string
	// Management selects a checked manageAccess policy for replacement.
	// When nil, the configured EditorRoles are the replacement authority.
	// Creation still requires EditorRoles because no resource policy exists yet.
	Management *Service
}

func (a *Administration) actor(ctx context.Context, resource Resource, write bool) (Facts, error) {
	if a == nil || a.Store == nil || a.Provider == nil || ctx == nil || ctx.Err() != nil || resource.Kind == "" || resource.ID == "" || resource.Tenant == "" {
		return Facts{}, ErrDenied
	}
	facts, err := a.Provider.Resolve(ctx)
	if err != nil {
		if errors.Is(err, ErrDenied) {
			return Facts{}, ErrDenied
		}
		return Facts{}, ErrUnavailable
	}
	if facts.Subject == "" || facts.Issuer == "" || facts.Tenant == "" || !facts.ValidUntil.After(time.Now()) || ctx.Err() != nil || resource.Tenant != "*" && resource.Tenant != facts.Tenant {
		return Facts{}, ErrDenied
	}
	if !write {
		return facts, nil
	}
	allowed := false
	seen := map[string]bool{}
	for _, role := range a.EditorRoles {
		if role == "" || strings.TrimSpace(role) != role || seen[role] {
			return Facts{}, ErrDenied
		}
		seen[role] = true
		for _, actual := range facts.Roles {
			if role == actual {
				allowed = true
			}
		}
	}
	if !allowed {
		return Facts{}, ErrDenied
	}
	return facts, nil
}

func (a *Administration) Get(ctx context.Context, resource Resource) (Document, error) {
	if _, err := a.actor(ctx, resource, false); err != nil {
		return Document{}, err
	}
	doc, err := a.Store.Get(ctx, resource)
	if err != nil {
		return Document{}, administrationStoreError(err)
	}
	if doc.Resource != resource || doc.Revision < 1 || ctx.Err() != nil {
		return Document{}, ErrDenied
	}
	return doc, nil
}

func validateDocument(doc Document) error {
	if len(doc.Policies) == 0 {
		return ErrDenied
	}
	for action, policy := range doc.Policies {
		if err := ValidatePolicy(action, policy); err != nil {
			return err
		}
	}
	return nil
}

func (a *Administration) Create(ctx context.Context, doc Document) (Document, error) {
	facts, err := a.actor(ctx, doc.Resource, true)
	if err != nil {
		return Document{}, err
	}
	if doc.Revision != 0 {
		return Document{}, ErrConflict
	}
	if err = validateDocument(doc); err != nil {
		return Document{}, err
	}
	creator, ok := a.Store.(Creator)
	if !ok {
		return Document{}, ErrDenied
	}
	if ctx.Err() != nil || !facts.ValidUntil.After(time.Now()) {
		return Document{}, ErrDenied
	}
	created, err := creator.Create(ctx, doc, facts.Subject)
	if err != nil {
		return Document{}, administrationStoreError(err)
	}
	return created, nil
}

func (a *Administration) Replace(ctx context.Context, doc Document) (Document, error) {
	facts, managedRevision, err := a.replacementActor(ctx, doc.Resource)
	if err != nil {
		return Document{}, err
	}
	current, err := a.Store.Get(ctx, doc.Resource)
	if err != nil {
		return Document{}, administrationStoreError(err)
	}
	if current.Resource != doc.Resource || current.Revision < 1 {
		return Document{}, ErrDenied
	}
	if current.Revision != doc.Revision {
		return Document{}, ErrConflict
	}
	if managedRevision > 0 && current.Revision != managedRevision {
		return Document{}, ErrConflict
	}
	if err = validateDocument(doc); err != nil {
		return Document{}, err
	}
	if ctx.Err() != nil || !facts.ValidUntil.After(time.Now()) {
		return Document{}, ErrDenied
	}
	replaced, err := a.Store.Replace(ctx, doc, current.Revision, facts.Subject)
	if err != nil {
		return Document{}, administrationStoreError(err)
	}
	return replaced, nil
}

func administrationStoreError(err error) error {
	switch {
	case errors.Is(err, ErrConflict):
		return ErrConflict
	case errors.Is(err, ErrDenied), errors.Is(err, sql.ErrNoRows):
		return ErrDenied
	default:
		return ErrUnavailable
	}
}

// CanReplace reports the same server rule used by Replace. Callers may show
// this in an editor context, but Replace independently repeats the check.
func (a *Administration) CanReplace(ctx context.Context, resource Resource) (bool, error) {
	_, _, err := a.replacementActor(ctx, resource)
	if errors.Is(err, ErrDenied) {
		return false, nil
	}
	return err == nil, err
}

func (a *Administration) replacementActor(ctx context.Context, resource Resource) (Facts, int64, error) {
	if a == nil || a.Management == nil {
		facts, err := a.actor(ctx, resource, true)
		return facts, 0, err
	}
	facts, err := a.actor(ctx, resource, false)
	if err != nil {
		return Facts{}, 0, err
	}
	decision, current, revision, err := a.Management.AuthorizeWithStatus(ctx, Request{Resource: resource, Action: "manageAccess"})
	if err != nil {
		return Facts{}, 0, err
	}
	if decision.Bounded || revision < 1 || !sameManagementFacts(facts, current) {
		return Facts{}, 0, ErrDenied
	}
	return facts, revision, nil
}

func sameManagementFacts(a, b Facts) bool {
	return a.Subject == b.Subject && a.Issuer == b.Issuer && a.Tenant == b.Tenant &&
		reflect.DeepEqual(a.Roles, b.Roles) && reflect.DeepEqual(a.Exposures, b.Exposures) &&
		reflect.DeepEqual(a.EntityGroups, b.EntityGroups) && reflect.DeepEqual(a.Entities, b.Entities) &&
		reflect.DeepEqual(a.EntityPermissions, b.EntityPermissions) && reflect.DeepEqual(a.GrantedScopes, b.GrantedScopes) &&
		a.ValidUntil.After(time.Now()) && b.ValidUntil.After(time.Now())
}
