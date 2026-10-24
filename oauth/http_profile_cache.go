package oauth

import (
	"context"
	"encoding/json"
	"github.com/golang-jwt/jwt/v5"
	"github.com/viant/authz"
	"sync"
	"time"
)

type httpProfileEntry struct {
	profile httpProfile
	until   time.Time
	used    uint64
}
type httpProfileFlight struct {
	done    chan struct{}
	profile httpProfile
	until   time.Time
	err     error
}
type httpProfileCache struct {
	sync.Mutex
	entries   map[string]httpProfileEntry
	flights   map[string]*httpProfileFlight
	capacity  int
	partition string
	sequence  uint64
}

func newHTTPProfileCache(capacity int, partition string) *httpProfileCache {
	return &httpProfileCache{entries: map[string]httpProfileEntry{}, flights: map[string]*httpProfileFlight{}, capacity: capacity, partition: partition}
}

func (p *HTTPIdentityProvider) profileKey(claims *jwt.RegisteredClaims, signed json.RawMessage) (string, error) {
	account, err := idAt(signed, p.config.Mapping.JWTAccountID)
	if err != nil {
		return "", authz.ErrDenied
	}
	user := ""
	if p.config.Mapping.JWTUserID != "" {
		user, err = idAt(signed, p.config.Mapping.JWTUserID)
		if err != nil {
			return "", authz.ErrDenied
		}
	}
	tenant := p.config.TenantForAllAccounts
	if tenant == "" {
		tenant = p.config.TenantByAccount[account]
	}
	if tenant == "" {
		return "", authz.ErrDenied
	}
	// Renewed credentials share a profile, but different scope/client/token
	// classes never borrow a more privileged userinfo representation.
	credential := map[string]json.RawMessage{}
	for _, path := range []string{"scope", "scp", "azp", "client_id", "token_use"} {
		value, found, e := rawHTTPPath(signed, path)
		if e != nil {
			return "", authz.ErrDenied
		}
		if found {
			credential[path] = value
		}
	}
	_, idToken, err := rawHTTPPath(signed, "at_hash")
	if err != nil {
		return "", authz.ErrDenied
	}
	return hashHTTP(struct {
		Provider, Issuer, Subject, Tenant, Account, User string
		Credential                                       map[string]json.RawMessage
		IDToken                                          bool
	}{p.profiles.partition, claims.Issuer, claims.Subject, tenant, account, user, credential, idToken}), nil
}
func (p *HTTPIdentityProvider) bindProfile(ctx context.Context, profile httpProfile, until time.Time, claims *jwt.RegisteredClaims, signed json.RawMessage, bearer string) (httpProfile, error) {
	if ctx.Err() != nil || !until.After(p.now()) || !claims.ExpiresAt.After(p.now()) || profile.principal.Facts.Subject != claims.Subject || profile.principal.Facts.Issuer != claims.Issuer {
		return httpProfile{}, authz.ErrDenied
	}
	account, err := idAt(signed, p.config.Mapping.JWTAccountID)
	if err != nil || account != profile.principal.AccountID {
		return httpProfile{}, authz.ErrDenied
	}
	if p.config.Mapping.JWTUserID != "" {
		user, e := idAt(signed, p.config.Mapping.JWTUserID)
		if e != nil || user != profile.userID {
			return httpProfile{}, authz.ErrDenied
		}
	}
	result := cloneHTTPProfile(profile)
	result.bearerHash = hashHTTP(bearer)
	result.principal.Facts.ValidUntil = minHTTPTime(until, claims.ExpiresAt.Time)
	return result, nil
}
func (p *HTTPIdentityProvider) readProfile(ctx context.Context) (httpProfile, error) {
	return p.readProfileWithRefresh(ctx, false)
}

// readProfileFresh verifies current userinfo even while an ordinary profile
// cache entry is valid. Only a successful remote read replaces that entry.
func (p *HTTPIdentityProvider) readProfileFresh(ctx context.Context) (httpProfile, error) {
	return p.readProfileWithRefresh(ctx, true)
}

func (p *HTTPIdentityProvider) readProfileWithRefresh(ctx context.Context, refresh bool) (httpProfile, error) {
	claims, signed, bearer, err := p.claims(ctx)
	if err != nil {
		return httpProfile{}, err
	}
	if p.cacheTTL <= 0 {
		return p.readProfileRemote(ctx, claims, signed, bearer)
	}
	key, err := p.profileKey(claims, signed)
	if err != nil {
		return httpProfile{}, err
	}
	cache := p.profiles
	now := p.now()
	cache.Lock()
	entry, hit := cache.entries[key]
	if hit && !entry.until.After(now) {
		delete(cache.entries, key)
		hit = false
	}
	if hit && !refresh {
		cache.sequence++
		entry.used = cache.sequence
		cache.entries[key] = entry
		cache.Unlock()
		return p.bindProfile(ctx, entry.profile, entry.until, claims, signed, bearer)
	}
	if flight := cache.flights[key]; flight != nil {
		cache.Unlock()
		select {
		case <-ctx.Done():
			return httpProfile{}, authz.ErrDenied
		case <-flight.done:
			if flight.err != nil {
				return httpProfile{}, flight.err
			}
			return p.bindProfile(ctx, flight.profile, flight.until, claims, signed, bearer)
		}
	}
	if len(cache.flights) >= cache.capacity {
		cache.Unlock()
		return httpProfile{}, authz.ErrUnavailable
	}
	flight := &httpProfileFlight{done: make(chan struct{})}
	cache.flights[key] = flight
	cache.Unlock()
	profile, err := p.readProfileRemote(ctx, claims, signed, bearer)
	until := time.Time{}
	if err == nil {
		until = minHTTPTime(p.now().Add(p.cacheTTL), profile.principal.Facts.ValidUntil)
		if ctx.Err() != nil || !until.After(p.now()) {
			err = authz.ErrDenied
		}
	}
	cache.Lock()
	delete(cache.flights, key)
	if err == nil {
		if len(cache.entries) >= cache.capacity {
			for candidate, entry := range cache.entries {
				if !entry.until.After(p.now()) {
					delete(cache.entries, candidate)
				}
			}
		}
		if len(cache.entries) >= cache.capacity {
			var oldest string
			var used uint64
			for k, v := range cache.entries {
				if oldest == "" || v.used < used {
					oldest = k
					used = v.used
				}
			}
			delete(cache.entries, oldest)
		}
		cache.sequence++
		stored := cloneHTTPProfile(profile)
		cache.entries[key] = httpProfileEntry{profile: stored, until: until, used: cache.sequence}
		flight.profile = stored
		flight.until = until
	}
	flight.err = err
	close(flight.done)
	cache.Unlock()
	if err != nil {
		return httpProfile{}, err
	}
	return p.bindProfile(ctx, profile, until, claims, signed, bearer)
}
