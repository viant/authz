package api

import (
	"context"
	"errors"
	"time"

	"github.com/viant/authz"
	"github.com/viant/authz/gating"
	xhandler "github.com/viant/xdatly/handler"
)

type catalogHandler struct{}

func NewCatalog() xhandler.Contract[CatalogInput, CatalogOutput] { return &catalogHandler{} }

func (*catalogHandler) Exec(ctx context.Context, session xhandler.Session, in *CatalogInput, out *CatalogOutput) error {
	if in == nil || out == nil {
		return failure(400, "request required", nil)
	}
	ctx, services, err := setup(ctx, session, in.JWT)
	if err != nil {
		return err
	}
	out.Resources, err = ListAuthorizedCatalog(ctx, &services)
	if err != nil {
		return publicError(err)
	}
	return nil
}

// ListAuthorizedCatalog applies one verified principal and exact policy
// revisions to a trusted host inventory. Hosts may reuse it for their local
// editor route and MCP SDK so both surfaces expose identical choices.
func ListAuthorizedCatalog(ctx context.Context, services *Services) ([]CatalogEntry, error) {
	if ctx == nil || ctx.Err() != nil || services == nil || services.Catalog == nil || services.Authorization == nil || services.Authorization.Store == nil || services.Gates == nil || services.Gates.Principals == nil {
		return nil, authz.ErrUnavailable
	}
	principal, err := services.Gates.Principals.ResolvePrincipal(ctx)
	if err != nil {
		if errors.Is(err, authz.ErrDenied) {
			return nil, authz.ErrIdentityDenied
		}
		return nil, authz.ErrUnavailable
	}
	if principal.AccountID == "" || principal.IdentityRevision == "" || principal.Facts.Subject == "" || !principal.Facts.ValidUntil.After(time.Now()) {
		return nil, authz.ErrIdentityDenied
	}
	entries, err := services.Catalog.List(ctx)
	if err != nil {
		return nil, authz.ErrUnavailable
	}
	reconfirm := func() error {
		current, err := services.Gates.Principals.ResolvePrincipal(ctx)
		if err != nil || !current.Facts.ValidUntil.After(time.Now()) || !gating.SamePrincipalAuthority(principal, current) {
			return authz.ErrUnavailable
		}
		return nil
	}
	visible := make([]CatalogEntry, 0, len(entries))
	dynamicVisible := make([]CatalogEntry, 0)
	observedPolicies := map[authz.Resource]int64{}
	for _, entry := range entries {
		if entry.Resource.Kind == "" || entry.Resource.ID == "" || entry.Resource.Version == "" || entry.Resource.Tenant == "" {
			return nil, authz.ErrUnavailable
		}
		if services.CatalogAdmission != nil {
			handled, allowed, admissionErr := services.CatalogAdmission(ctx, principal, entry)
			if checkErr := reconfirm(); checkErr != nil {
				return nil, checkErr
			}
			if handled && entry.Context == nil {
				return nil, authz.ErrUnavailable
			}
			if errors.Is(admissionErr, authz.ErrDenied) {
				continue
			}
			if admissionErr != nil {
				return nil, authz.ErrUnavailable
			}
			if handled {
				if allowed {
					visible = append(visible, entry)
					dynamicVisible = append(dynamicVisible, entry)
				}
				continue
			}
		}
		decision, facts, revision, err := services.Authorization.AuthorizeWithStatus(ctx, authz.Request{Resource: entry.Resource, Action: "viewAccess"})
		if checkErr := reconfirm(); checkErr != nil {
			return nil, checkErr
		}
		if revision > 0 {
			if prior, exists := observedPolicies[entry.Resource]; exists && prior != revision {
				return nil, authz.ErrUnavailable
			}
			observedPolicies[entry.Resource] = revision
		}
		if errors.Is(err, authz.ErrIdentityDenied) {
			return nil, err
		}
		if errors.Is(err, authz.ErrDenied) {
			continue
		}
		if err != nil {
			return nil, authz.ErrUnavailable
		}
		if revision < 1 {
			return nil, authz.ErrUnavailable
		}
		observed := principal
		observed.Facts = facts
		if !facts.ValidUntil.After(time.Now()) || !gating.SamePrincipalAuthority(principal, observed) {
			return nil, authz.ErrUnavailable
		}
		if !decision.Bounded {
			visible = append(visible, entry)
		}
	}
	for resource, revision := range observedPolicies {
		current, err := services.Authorization.Store.Get(ctx, resource)
		if err != nil || current.Resource != resource || current.Revision != revision {
			return nil, authz.ErrUnavailable
		}
	}
	for _, entry := range dynamicVisible {
		handled, allowed, err := services.CatalogAdmission(ctx, principal, entry)
		if err != nil || !handled || !allowed {
			return nil, authz.ErrUnavailable
		}
		if err := reconfirm(); err != nil {
			return nil, err
		}
	}
	if err := reconfirm(); err != nil {
		return nil, err
	}
	return visible, nil
}
