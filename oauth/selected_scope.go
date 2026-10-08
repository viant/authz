package oauth

import (
	"context"
	"strconv"
	"time"

	"github.com/viant/authz"
	"github.com/viant/authz/gating"
)

// EntityEvaluationScopeProvider delegates entity bounds to an injected authority.
// Permission is a trusted host mapping (typically read for scope admission);
// mandatory action-specific gates continue to be evaluated independently.
type EntityEvaluationScopeProvider struct {
	Client     gating.EntityPermissionProvider
	Principals gating.PrincipalResolver
	Permission func(authz.Request, authz.Document) (string, error)
}

func (p *EntityEvaluationScopeProvider) ResolveSelectedScope(ctx context.Context, request authz.Request, document authz.Document, facts authz.Facts) (authz.SelectedScopeDecision, error) {
	if p == nil || p.Client == nil || p.Principals == nil || p.Permission == nil || request.Selection == nil {
		return authz.SelectedScopeDecision{}, authz.ErrDenied
	}
	permission, err := p.Permission(request, document)
	if err != nil || permission == "" {
		return authz.SelectedScopeDecision{}, authz.ErrDenied
	}
	principal, err := p.Principals.ResolvePrincipal(ctx)
	if err != nil {
		return authz.SelectedScopeDecision{}, err
	}
	if principal.AccountID == "" || principal.IdentityRevision == "" || !principal.Facts.ValidUntil.After(time.Now()) || !sameVerifiedAccountFacts(principal.Facts, facts) || !facts.ValidUntil.After(time.Now()) {
		return authz.SelectedScopeDecision{}, authz.ErrIdentityDenied
	}
	selected, hash, err := gating.CanonicalSelection(*request.Selection)
	if err != nil || len(selected) == 0 {
		return authz.SelectedScopeDecision{}, authz.ErrDenied
	}
	r := gating.ProviderRequest{SchemaVersion: 1, RequestID: "selected-scope:" + strconv.FormatInt(document.Revision, 10) + ":" + hash, Subject: facts.Subject, Issuer: facts.Issuer, TenantID: facts.Tenant, AccountID: principal.AccountID, ResourceKind: request.Resource.Kind, ResourceID: request.Resource.ID, ResourceVersion: request.Resource.Version, Action: request.Action, RequirementsRevision: "acl:" + strconv.FormatInt(document.Revision, 10), RequirementKey: permission, ProviderRef: "entity", EntitySelection: selected, EntitySelectionHash: hash}
	checked, err := p.Client.CheckEntityPermission(ctx, r)
	if err != nil {
		return authz.SelectedScopeDecision{}, err
	}
	if !gating.ValidProviderDecision(checked, r, time.Now()) || checked.Effect != "allow" {
		return authz.SelectedScopeDecision{}, authz.ErrDenied
	}
	current, err := p.Principals.ResolvePrincipal(ctx)
	if err != nil {
		return authz.SelectedScopeDecision{}, err
	}
	if !gating.SamePrincipalAuthority(principal, current) || !current.Facts.ValidUntil.After(time.Now()) {
		return authz.SelectedScopeDecision{}, authz.ErrIdentityDenied
	}
	lease := checked.ValidUntil
	for _, bound := range []time.Time{facts.ValidUntil, current.Facts.ValidUntil} {
		if bound.Before(lease) {
			lease = bound
		}
	}
	if !lease.After(time.Now()) {
		return authz.SelectedScopeDecision{}, authz.ErrDenied
	}
	return authz.SelectedScopeDecision{Entities: selected, ValidUntil: lease}, nil
}

var _ authz.SelectedScopeProvider = (*EntityEvaluationScopeProvider)(nil)
