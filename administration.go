package authz

import (
	"context"
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
}

func (a *Administration) actor(ctx context.Context, resource Resource, write bool) (Facts, error) {
	if a == nil || a.Store == nil || a.Provider == nil || ctx.Err() != nil || resource.Kind == "" || resource.ID == "" || resource.Tenant == "" {
		return Facts{}, ErrDenied
	}
	facts, err := a.Provider.Resolve(ctx)
	if err != nil || facts.Subject == "" || facts.Issuer == "" || facts.Tenant == "" || !facts.ValidUntil.After(time.Now()) || ctx.Err() != nil || resource.Tenant != "*" && resource.Tenant != facts.Tenant {
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
	if err != nil || doc.Resource != resource || doc.Revision < 1 || ctx.Err() != nil {
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
	return creator.Create(ctx, doc, facts.Subject)
}

func (a *Administration) Replace(ctx context.Context, doc Document) (Document, error) {
	facts, err := a.actor(ctx, doc.Resource, true)
	if err != nil {
		return Document{}, err
	}
	current, err := a.Store.Get(ctx, doc.Resource)
	if err != nil || current.Resource != doc.Resource || current.Revision < 1 {
		return Document{}, ErrDenied
	}
	if current.Revision != doc.Revision {
		return Document{}, ErrConflict
	}
	if err = validateDocument(doc); err != nil {
		return Document{}, err
	}
	if ctx.Err() != nil || !facts.ValidUntil.After(time.Now()) {
		return Document{}, ErrDenied
	}
	return a.Store.Replace(ctx, doc, current.Revision, facts.Subject)
}
