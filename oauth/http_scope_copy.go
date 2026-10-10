package oauth

import (
	"context"
	"github.com/viant/authz"
)

// CopyDecision preserves the caller's request values while carrying this
// provider's active, credential-bound decision scope. It never copies facts,
// extends the scope lease, or upgrades a metadata-only scope.
func (p *HTTPIdentityProvider) CopyDecision(ctx, scoped context.Context) (context.Context, error) {
	if p == nil || ctx == nil || scoped == nil || ctx.Err() != nil || scoped.Err() != nil {
		return nil, authz.ErrDenied
	}
	state, _ := scoped.Value(httpScopeKey{}).(*httpScope)
	if state == nil || state.provider != p {
		return nil, authz.ErrDenied
	}
	state.Lock()
	metadata := state.metadata
	closed := state.closed
	state.Unlock()
	if metadata || closed {
		return nil, authz.ErrDenied
	}
	if existing, _ := ctx.Value(httpScopeKey{}).(*httpScope); existing != nil && existing != state {
		return nil, authz.ErrDenied
	}
	result := context.WithValue(ctx, httpScopeKey{}, state)
	if _, err := p.profile(result); err != nil {
		return nil, err
	}
	return result, nil
}
