package oauth

import (
	"context"
	"errors"
	"net/http"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestUserInfoRefreshAheadKeepsOriginalOperationDeadline(t *testing.T) {
	for _, tc := range []struct {
		ttl         string
		near, after time.Duration
	}{{"15m", 14*time.Minute + 45*time.Second, 16 * time.Second}, {"45s", 44 * time.Second, 2 * time.Second}} {
		t.Run(tc.ttl, func(t *testing.T) {
			f, clock, c := cacheFixture(t)
			c.FactLease = tc.ttl
			c.UserInfoCacheTTL = tc.ttl
			p := cacheIdentity(t, c)
			ctx := WithBearer(context.Background(), cacheToken(t, f, nil))
			oldScope, oldFinish, err := p.BeginOperation(ctx)
			if err != nil {
				t.Fatal(err)
			}
			old, err := p.Resolve(oldScope)
			if err != nil {
				t.Fatal(err)
			}
			clock.add(tc.near)
			stampCacheInfo(f, clock.now(), 15*time.Minute)
			fresh, err := p.Resolve(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if f.userinfoCalls.Load() != 2 || !fresh.ValidUntil.After(old.ValidUntil) {
				t.Fatal("new admission borrowed a nearly expired cache lease")
			}
			retained, err := p.Resolve(oldScope)
			if err != nil || !retained.ValidUntil.Equal(old.ValidUntil) {
				t.Fatal("refresh changed an admitted operation deadline", err)
			}
			newScope, newFinish, err := p.BeginOperation(ctx)
			if err != nil {
				t.Fatal(err)
			}
			clock.add(tc.after)
			if _, err = p.Resolve(oldScope); err == nil {
				t.Fatal("old operation survived its original expiry")
			}
			if err = oldFinish(); err == nil {
				t.Fatal("expired old operation was released")
			}
			if _, err = p.Resolve(newScope); err != nil {
				t.Fatal("new operation did not receive verified fresh lease", err)
			}
			if err = newFinish(); err != nil {
				t.Fatal(err)
			}
			if f.userinfoCalls.Load() != 2 {
				t.Fatal("ordinary scoped reads fetched userinfo")
			}
		})
	}
}

func TestUserInfoRefreshAheadCoalescesConcurrentNewAdmissions(t *testing.T) {
	f, clock, c := cacheFixture(t)
	var refreshing atomic.Bool
	var entered atomic.Int32
	started := make(chan struct{}, 1)
	release := make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	t.Cleanup(unblock)
	c.Client = &http.Client{Transport: cacheRoundTrip(func(r *http.Request) (*http.Response, error) {
		if refreshing.Load() && r.URL.Path == "/userinfo" {
			entered.Add(1)
			select {
			case started <- struct{}{}:
			default:
			}
			select {
			case <-release:
			case <-r.Context().Done():
				return nil, r.Context().Err()
			}
		}
		return http.DefaultTransport.RoundTrip(r)
	})}
	p := cacheIdentity(t, c)
	ctx := WithBearer(context.Background(), cacheToken(t, f, nil))
	if _, err := p.Resolve(ctx); err != nil {
		t.Fatal(err)
	}
	clock.add(14*time.Minute + 45*time.Second)
	stampCacheInfo(f, clock.now(), 15*time.Minute)
	refreshing.Store(true)
	begin := make(chan struct{})
	errs := make(chan error, 24)
	var wg sync.WaitGroup
	for i := 0; i < 24; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); <-begin; _, err := p.Resolve(ctx); errs <- err }()
	}
	close(begin)
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("near-expiry cache was served without a refresh")
	}
	for i := 0; i < 50; i++ {
		runtime.Gosched()
	}
	if entered.Load() != 1 {
		t.Fatal("concurrent refresh was not coalesced")
	}
	unblock()
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if f.userinfoCalls.Load() != 2 || entered.Load() != 1 {
		t.Fatal("refresh performed more than one additional profile read")
	}
}

func TestUserInfoRefreshAheadFailsClosedWithoutStaleFallback(t *testing.T) {
	f, clock, c := cacheFixture(t)
	var fail atomic.Bool
	c.Client = &http.Client{Transport: cacheRoundTrip(func(r *http.Request) (*http.Response, error) {
		if fail.Load() && r.URL.Path == "/userinfo" {
			return nil, errors.New("fixture userinfo unavailable")
		}
		return http.DefaultTransport.RoundTrip(r)
	})}
	p := cacheIdentity(t, c)
	ctx := WithBearer(context.Background(), cacheToken(t, f, nil))
	if _, err := p.Resolve(ctx); err != nil {
		t.Fatal(err)
	}
	clock.add(14*time.Minute + 45*time.Second)
	stampCacheInfo(f, clock.now(), 15*time.Minute)
	fail.Store(true)
	for i := 0; i < 2; i++ {
		if _, err := p.Resolve(ctx); err == nil {
			t.Fatal("failed refresh returned cached grants")
		}
	}
	fail.Store(false)
	f.mu.Lock()
	f.info["roles"] = []string{"viewer"}
	f.mu.Unlock()
	fresh, err := p.Resolve(ctx)
	if err != nil || len(fresh.Roles) != 1 || fresh.Roles[0] != "viewer" {
		t.Fatal("recovery did not use current authority", err)
	}
	if f.userinfoCalls.Load() != 2 {
		t.Fatal("failed profile refresh was retained")
	}
}

func TestUserInfoRefreshAheadUsesShorterSourceLease(t *testing.T) {
	f, clock, c := cacheFixture(t)
	stampCacheInfo(f, clock.now(), 20*time.Second)
	p := cacheIdentity(t, c)
	ctx := WithBearer(context.Background(), cacheToken(t, f, nil))
	first, err := p.Resolve(ctx)
	if err != nil {
		t.Fatal(err)
	}
	clock.add(17 * time.Second)
	if _, err = p.Resolve(ctx); err != nil || f.userinfoCalls.Load() != 1 {
		t.Fatal("short source lease refreshed on an ordinary hit", err)
	}
	clock.add(1500 * time.Millisecond)
	stampCacheInfo(f, clock.now(), 20*time.Second)
	fresh, err := p.Resolve(ctx)
	if err != nil || f.userinfoCalls.Load() != 2 || !fresh.ValidUntil.After(first.ValidUntil) {
		t.Fatal("short source lease did not refresh near expiry", err)
	}
	if fresh.ValidUntil.After(clock.now().Add(20 * time.Second)) {
		t.Fatal("fresh identity exceeded source lease")
	}
}
