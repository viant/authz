package oauth

import (
	"context"
	"github.com/viant/authz"
)

// VerifiedUserID supplies the numeric identity binding for selected-entity
// responses after independently verifying the configured ID-token contract.
func (p *AccountUserInfoProvider) VerifiedUserID(ctx context.Context) (int64, error) {
	if p == nil || p.userinfo == nil {
		return 0, authz.ErrDenied
	}
	claims, _, err := p.userinfo.verifiedClaims(ctx)
	if err != nil {
		return 0, err
	}
	return int64(claims.UserID), nil
}
