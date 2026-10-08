package oauth

import (
	"context"
	"time"

	"github.com/viant/authz"
)

// Account rechecks the generic signed principal against a consumer's snapshot.
// Account IDs are opaque strings; their meaning is owned by the trusted issuer.
func (p *Provider) Account(ctx context.Context, expected authz.Facts) (string, error) {
	principal, err := p.ResolvePrincipal(ctx)
	if err != nil {
		return "", err
	}
	if !sameVerifiedAccountFacts(principal.Facts, expected) || !expected.ValidUntil.After(time.Now()) {
		return "", authz.ErrDenied
	}
	return principal.AccountID, nil
}

// AuthorityRevision supplies the credential revision and verified expiry for
// the same generic signed account authority used by ACL facts.
func (p *Provider) AuthorityRevision(ctx context.Context, expected authz.Facts, accountID string) (string, time.Time, error) {
	principal, err := p.ResolvePrincipal(ctx)
	if err != nil {
		return "", time.Time{}, err
	}
	if accountID == "" || principal.AccountID != accountID || !sameVerifiedAccountFacts(principal.Facts, expected) || !expected.ValidUntil.After(time.Now()) {
		return "", time.Time{}, authz.ErrDenied
	}
	lease := principal.Facts.ValidUntil
	if expected.ValidUntil.Before(lease) {
		lease = expected.ValidUntil
	}
	return principal.IdentityRevision, lease, nil
}

var _ IdentityAuthority = (*Provider)(nil)
