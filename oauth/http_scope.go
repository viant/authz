package oauth

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"github.com/viant/authz"
	"github.com/viant/authz/gating"
	"slices"
	"sync"
)

func decodeHTTPJWT(payload string) (json.RawMessage, error) {
	return base64.RawURLEncoding.DecodeString(payload)
}

type httpScopeKey struct{}
type httpScope struct {
	sync.Mutex
	provider         *HTTPIdentityProvider
	source           context.Context
	profile          httpProfile
	metadata, closed bool
}

func (p *HTTPIdentityProvider) withoutScope(ctx context.Context) context.Context {
	if ctx == nil {
		return nil
	}
	return context.WithValue(ctx, httpScopeKey{}, (*httpScope)(nil))
}
func cloneHTTPProfile(profile httpProfile) httpProfile {
	out := profile
	out.principal.Facts.Roles = slices.Clone(profile.principal.Facts.Roles)
	out.principal.Facts.Exposures = slices.Clone(profile.principal.Facts.Exposures)
	out.principal.Facts.GrantedScopes = slices.Clone(profile.principal.Facts.GrantedScopes)
	out.principal.Facts.Entities = slices.Clone(profile.principal.Facts.Entities)
	out.principal.MembershipGroups = slices.Clone(profile.principal.MembershipGroups)
	out.principal.Facts.EntityPermissions = slices.Clone(profile.principal.Facts.EntityPermissions)
	for i := range out.principal.Facts.EntityPermissions {
		out.principal.Facts.EntityPermissions[i].Permissions = slices.Clone(profile.principal.Facts.EntityPermissions[i].Permissions)
	}
	if profile.principal.Facts.EntityGroups != nil {
		out.principal.Facts.EntityGroups = make(authz.EntityGroups, len(profile.principal.Facts.EntityGroups))
		for kind, ids := range profile.principal.Facts.EntityGroups {
			out.principal.Facts.EntityGroups[kind] = slices.Clone(ids)
		}
	}
	raw, _ := json.Marshal(profile.projection)
	out.projection = nil
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	_ = decoder.Decode(&out.projection)
	return out
}
func (p *HTTPIdentityProvider) profile(ctx context.Context) (httpProfile, error) {
	if ctx == nil || ctx.Err() != nil {
		return httpProfile{}, authz.ErrDenied
	}
	state, _ := ctx.Value(httpScopeKey{}).(*httpScope)
	if state == nil || state.provider != p {
		return p.readProfile(ctx)
	}
	claims, signed, bearer, e := p.claims(ctx)
	if e != nil {
		return httpProfile{}, e
	}
	state.Lock()
	defer state.Unlock()
	profile := state.profile
	if state.closed || state.source == nil || state.source.Err() != nil || profile.bearerHash != hashHTTP(bearer) || !profile.principal.Facts.ValidUntil.After(p.now()) || profile.principal.Facts.Subject != claims.Subject {
		return httpProfile{}, authz.ErrDenied
	}
	if p.config.Mapping.JWTAccountID != "" {
		id, e := idAt(signed, p.config.Mapping.JWTAccountID)
		if e != nil || id != profile.principal.AccountID {
			return httpProfile{}, authz.ErrDenied
		}
	}
	if p.config.Mapping.JWTUserID != "" {
		id, err := idAt(signed, p.config.Mapping.JWTUserID)
		if err != nil || id != profile.userID {
			return httpProfile{}, authz.ErrDenied
		}
	}
	return cloneHTTPProfile(profile), nil
}
func (p *HTTPIdentityProvider) beginScope(ctx context.Context, metadata bool) (context.Context, func() error, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, nil, authz.ErrDenied
	}
	if state, _ := ctx.Value(httpScopeKey{}).(*httpScope); state != nil && state.provider == p {
		if _, e := p.profile(ctx); e != nil {
			return nil, nil, e
		}
		return ctx, func() error { _, e := p.profile(ctx); return e }, nil
	}
	base := p.withoutScope(ctx)
	initial, e := p.readProfile(base)
	if e != nil {
		return nil, nil, e
	}
	state := &httpScope{provider: p, source: base, profile: cloneHTTPProfile(initial), metadata: metadata}
	scoped := context.WithValue(base, httpScopeKey{}, state)
	finish := func() error {
		if p.cacheTTL > 0 {
			_, err := p.profile(scoped)
			state.Lock()
			defer state.Unlock()
			if state.closed {
				return authz.ErrDenied
			}
			state.closed = true
			return err
		}
		state.Lock()
		if state.closed {
			state.Unlock()
			return authz.ErrDenied
		}
		state.closed = true
		state.Unlock()
		current, e := p.readProfile(base)
		if e != nil {
			return e
		}
		if ctx.Err() != nil || !initial.principal.Facts.ValidUntil.After(p.now()) || !current.principal.Facts.ValidUntil.After(p.now()) || initial.bearerHash != current.bearerHash || !gating.SamePrincipalAuthority(initial.principal, current.principal) || current.principal.Facts.ValidUntil.Before(initial.principal.Facts.ValidUntil) {
			return authz.ErrDenied
		}
		return nil
	}
	return scoped, finish, nil
}
func (p *HTTPIdentityProvider) BeginDecision(ctx context.Context) (context.Context, func() error, error) {
	return p.beginScope(ctx, false)
}
func (p *HTTPIdentityProvider) WithoutDecision(ctx context.Context) context.Context {
	return p.withoutScope(ctx)
}
func (p *HTTPIdentityProvider) BeginMetadataRead(ctx context.Context) (context.Context, func() error, error) {
	return p.beginScope(ctx, true)
}
func (p *HTTPIdentityProvider) WithoutMetadataRead(ctx context.Context) context.Context {
	return p.withoutScope(ctx)
}
func (p *HTTPIdentityProvider) MetadataReadActive(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	state, _ := ctx.Value(httpScopeKey{}).(*httpScope)
	if state == nil || state.provider != p {
		return false
	}
	state.Lock()
	active := state.metadata && !state.closed
	state.Unlock()
	if !active {
		return false
	}
	_, e := p.profile(ctx)
	return e == nil
}

// BeginOperation captures one verified userinfo profile for an operation. Local
// identity/display reads reuse it; the actual data producer remains responsible
// for authorizing business requests. Finish closes the scope without fetching
// userinfo again or comparing business roles after a producer call. No profile
// is retained outside this context; token/account/expiry checks still apply.
func (p *HTTPIdentityProvider) BeginOperation(ctx context.Context) (context.Context, func() error, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, nil, authz.ErrDenied
	}
	if state, _ := ctx.Value(httpScopeKey{}).(*httpScope); state != nil && state.provider == p {
		if _, err := p.profile(ctx); err != nil {
			return nil, nil, err
		}
		return ctx, func() error { _, err := p.profile(ctx); return err }, nil
	}
	base := p.withoutScope(ctx)
	initial, err := p.readProfile(base)
	if err != nil {
		return nil, nil, err
	}
	state := &httpScope{provider: p, source: base, profile: cloneHTTPProfile(initial)}
	scoped := context.WithValue(base, httpScopeKey{}, state)
	finish := func() error {
		_, err := p.profile(scoped)
		state.Lock()
		defer state.Unlock()
		if state.closed {
			return authz.ErrDenied
		}
		state.closed = true
		return err
	}
	return scoped, finish, nil
}
