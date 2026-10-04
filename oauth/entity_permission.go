package oauth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"reflect"
	"time"

	"github.com/viant/authz"
	"github.com/viant/authz/gating"
)

// FactEntityPermissionProvider checks the exact named permissions returned by
// a verified identity provider. Entity membership alone is not sufficient.
type FactEntityPermissionProvider struct{ Principals gating.PrincipalResolver }

var _ gating.EntityPermissionProvider = (*FactEntityPermissionProvider)(nil)

func (p *FactEntityPermissionProvider) CheckEntityPermission(ctx context.Context, request gating.ProviderRequest) (gating.Decision, error) {
	if p == nil || p.Principals == nil || ctx == nil || ctx.Err() != nil || request.SchemaVersion != 1 || request.ProviderRef != "entity" || request.RequirementKey == "" || request.RequestID == "" || request.RequirementsRevision == "" || len(request.EntitySelection) == 0 {
		return gating.Decision{}, gating.ErrUnavailable
	}
	selected, hash, err := gating.CanonicalSelection(request.EntitySelection)
	if err != nil || hash != request.EntitySelectionHash || !reflect.DeepEqual(selected, request.EntitySelection) {
		return gating.Decision{}, gating.ErrUnavailable
	}
	principal, err := p.Principals.ResolvePrincipal(ctx)
	if errors.Is(err, authz.ErrDenied) {
		return gating.Decision{}, authz.ErrDenied
	}
	if err != nil {
		return gating.Decision{}, gating.ErrUnavailable
	}
	if principal.Facts.Subject != request.Subject || principal.Facts.Issuer != request.Issuer || principal.Facts.Tenant != request.TenantID || principal.AccountID != request.AccountID || principal.IdentityRevision == "" || !principal.Facts.ValidUntil.After(time.Now()) {
		return gating.Decision{}, gating.ErrUnavailable
	}
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return gating.Decision{}, errors.Join(gating.ErrUnavailable, err)
	}
	result := gating.Decision{SchemaVersion: 1, DecisionID: hex.EncodeToString(id[:]), RequestID: request.RequestID, Subject: request.Subject, Issuer: request.Issuer, TenantID: request.TenantID, AccountID: request.AccountID, ResourceKind: request.ResourceKind, ResourceID: request.ResourceID, ResourceVersion: request.ResourceVersion, Action: request.Action, RequirementsRevision: request.RequirementsRevision, EntitySelectionHash: hash, RequirementKey: request.RequirementKey, ProviderRef: request.ProviderRef, ProviderRevision: principal.IdentityRevision, ValidUntil: principal.Facts.ValidUntil, Effect: "allow"}
	for _, entity := range selected {
		if !authz.HasPermission(principal.Facts.EntityPermissions, entity.Type, authz.EntityID(entity.ID), request.RequirementKey) {
			result.Effect, result.ReasonCode = "deny", "entityDenied"
			break
		}
	}
	return result, nil
}
