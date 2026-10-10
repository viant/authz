package oauth

import (
	"context"
	"github.com/viant/authz"
	"github.com/viant/authz/gating"
	"time"
)

// ResolveIdentityPrincipal grants identity only, never role/feature/entity
// authority. A configured signed account claim permits zero-userinfo template
// delivery; an unproven account cannot silently become a trusted native context.
func (p *HTTPIdentityProvider) ResolveIdentityPrincipal(ctx context.Context) (gating.Principal, error) {
	claims, signed, bearer, e := p.claims(ctx)
	if e != nil {
		return gating.Principal{}, authz.ErrIdentityDenied
	}
	if p.config.Mapping.JWTAccountID == "" {
		return gating.Principal{}, authz.ErrIdentityDenied
	}
	account, e := idAt(signed, p.config.Mapping.JWTAccountID)
	if e != nil {
		return gating.Principal{}, authz.ErrIdentityDenied
	}
	user := ""
	if p.config.Mapping.JWTUserID != "" {
		user, e = idAt(signed, p.config.Mapping.JWTUserID)
		if e != nil {
			return gating.Principal{}, authz.ErrIdentityDenied
		}
	}
	tenant := p.config.TenantForAllAccounts
	if tenant == "" {
		tenant = p.config.TenantByAccount[account]
	}
	if tenant == "" {
		return gating.Principal{}, authz.ErrIdentityDenied
	}
	revision := hashHTTP([]string{hashHTTP(bearer), claims.Subject, claims.Issuer, account, user, tenant})
	deadline := minHTTPTime(claims.ExpiresAt.Time, time.Now().Add(p.lease))
	if !deadline.After(time.Now()) {
		return gating.Principal{}, authz.ErrIdentityDenied
	}
	return gating.Principal{Facts: authz.Facts{Subject: claims.Subject, Issuer: claims.Issuer, Tenant: tenant, AuthorityRevision: revision, ValidUntil: deadline}, AccountID: account, IdentityRevision: revision}, nil
}
