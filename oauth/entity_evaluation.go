package oauth

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/viant/authz"
	"github.com/viant/authz/gating"
)

// EntityEvaluationConfig connects a trusted selected-entity authority. The
// authority owns business inheritance; this adapter only validates decisions.
type EntityEvaluationConfig struct {
	URL        string
	Principals gating.PrincipalResolver
	Client     *http.Client
	CacheTTL   time.Duration
	MaxEntries int
}
type EntityEvaluationClient struct {
	config EntityEvaluationConfig
	client http.Client
	mu     sync.Mutex
	cache  map[[32]byte]entityEvaluationInfo
}
type entityEvaluationInfo struct {
	Issuer            string                   `json:"issuer"`
	Subject           string                   `json:"subject"`
	UserID            int64                    `json:"userId"`
	AccountID         int64                    `json:"accountId"`
	EntityType        string                   `json:"entityType"`
	AuthorityRevision string                   `json:"authorityRevision"`
	EvaluatedAt       time.Time                `json:"evaluatedAt"`
	ValidUntil        time.Time                `json:"validUntil"`
	Results           []entityEvaluationResult `json:"results"`
}
type entityEvaluationResult struct {
	EntityID    int64           `json:"entityId"`
	Permissions map[string]bool `json:"permissions"`
}

func NewEntityEvaluationClient(config EntityEvaluationConfig) (*EntityEvaluationClient, error) {
	u, err := url.Parse(config.URL)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Scheme != "https" && !(u.Scheme == "http" && loopbackHost(u.Hostname()))) || config.Principals == nil {
		return nil, fmt.Errorf("invalid entity authority configuration")
	}
	if config.CacheTTL == 0 {
		config.CacheTTL = 5 * time.Minute
	}
	if config.CacheTTL < 0 || config.CacheTTL > 5*time.Minute {
		return nil, fmt.Errorf("entity authority cache lease must be at most five minutes")
	}
	if config.MaxEntries == 0 {
		config.MaxEntries = 256
	}
	if config.MaxEntries < 1 {
		return nil, fmt.Errorf("invalid entity authority cache size")
	}
	client := http.Client{Timeout: 5 * time.Second}
	if config.Client != nil {
		client = *config.Client
		if client.Timeout == 0 {
			client.Timeout = 5 * time.Second
		}
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &EntityEvaluationClient{config: config, client: client, cache: map[[32]byte]entityEvaluationInfo{}}, nil
}

func (c *EntityEvaluationClient) CheckEntityPermission(ctx context.Context, r gating.ProviderRequest) (gating.Decision, error) {
	if c == nil || ctx == nil || ctx.Err() != nil || r.RequirementKey == "" || r.RequestID == "" {
		return gating.Decision{}, authz.ErrDenied
	}
	principal, err := c.config.Principals.ResolvePrincipal(ctx)
	if err != nil {
		return gating.Decision{}, err
	}
	token, _ := ctx.Value(tokenKey{}).(string)
	if token == "" || principal.Facts.Subject != r.Subject || principal.Facts.Issuer != r.Issuer || principal.Facts.Tenant != r.TenantID || principal.AccountID != r.AccountID || principal.IdentityRevision == "" || !principal.Facts.ValidUntil.After(time.Now()) {
		return gating.Decision{}, authz.ErrDenied
	}
	var expectedUserID int64
	if numeric, ok := c.config.Principals.(interface {
		VerifiedUserID(context.Context) (int64, error)
	}); ok {
		expectedUserID, err = numeric.VerifiedUserID(ctx)
		if err != nil || expectedUserID <= 0 {
			return gating.Decision{}, authz.ErrDenied
		}
	}
	selected, hash, err := gating.CanonicalSelection(r.EntitySelection)
	if err != nil || hash != r.EntitySelectionHash || len(selected) == 0 || len(selected) > 500 {
		return gating.Decision{}, authz.ErrDenied
	}
	kind := selected[0].Type
	ids := make([]int64, len(selected))
	for i, e := range selected {
		id, eerr := strconv.ParseInt(e.ID, 10, 64)
		if eerr != nil || id <= 0 || strconv.FormatInt(id, 10) != e.ID || e.Type != kind {
			return gating.Decision{}, authz.ErrDenied
		}
		ids[i] = id
	}
	body, _ := json.Marshal(struct {
		EntityType  string   `json:"entityType"`
		EntityIDs   []int64  `json:"entityIds"`
		Permissions []string `json:"permissions"`
	}{kind, ids, []string{r.RequirementKey}})
	// The verified credential, account and identity revision segregate sessions.
	key := sha256.Sum256([]byte(token + "\x00" + principal.AccountID + "\x00" + principal.IdentityRevision + "\x00" + string(body)))
	started := time.Now()
	c.mu.Lock()
	info, found := c.cache[key]
	c.mu.Unlock()
	if !found || !info.ValidUntil.After(started) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.config.URL, bytes.NewReader(body))
		if err != nil {
			return gating.Decision{}, gating.ErrUnavailable
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")
		resp, err := c.client.Do(req)
		if err != nil {
			return gating.Decision{}, gating.ErrUnavailable
		}
		raw, readErr := io.ReadAll(io.LimitReader(resp.Body, 1<<20+1))
		resp.Body.Close()
		if resp.StatusCode == 401 || resp.StatusCode == 403 {
			return gating.Decision{}, authz.ErrDenied
		}
		if readErr != nil || resp.StatusCode != 200 || len(raw) > 1<<20 {
			return gating.Decision{}, gating.ErrUnavailable
		}
		var envelope struct {
			Status string                `json:"status"`
			Info   *entityEvaluationInfo `json:"info"`
		}
		if validateUniqueJSON(raw) != nil || json.Unmarshal(raw, &envelope) != nil || envelope.Status != "ok" || envelope.Info == nil {
			return gating.Decision{}, gating.ErrUnavailable
		}
		info = *envelope.Info
		if info.Issuer != r.Issuer || info.Subject != r.Subject || strconv.FormatInt(info.AccountID, 10) != r.AccountID || info.UserID <= 0 || (expectedUserID > 0 && info.UserID != expectedUserID) || info.EntityType != kind || strings.TrimSpace(info.AuthorityRevision) == "" || info.EvaluatedAt.IsZero() || info.EvaluatedAt.After(time.Now()) || !info.ValidUntil.After(info.EvaluatedAt) || !info.ValidUntil.After(time.Now()) || len(info.Results) != len(ids) {
			return gating.Decision{}, gating.ErrUnavailable
		}
		expected := map[int64]bool{}
		for _, id := range ids {
			expected[id] = true
		}
		for _, item := range info.Results {
			_, hasPermission := item.Permissions[r.RequirementKey]
			if !expected[item.EntityID] || !hasPermission || len(item.Permissions) != 1 {
				return gating.Decision{}, gating.ErrUnavailable
			}
			delete(expected, item.EntityID)
		}
		for _, lease := range []time.Time{started.Add(c.config.CacheTTL), info.EvaluatedAt.Add(c.config.CacheTTL), principal.Facts.ValidUntil} {
			if lease.Before(info.ValidUntil) {
				info.ValidUntil = lease
			}
		}
		if !info.ValidUntil.After(time.Now()) {
			return gating.Decision{}, authz.ErrDenied
		}
		c.mu.Lock()
		if len(c.cache) >= c.config.MaxEntries {
			for k, v := range c.cache {
				if !v.ValidUntil.After(time.Now()) {
					delete(c.cache, k)
				}
			}
			if len(c.cache) >= c.config.MaxEntries {
				for k := range c.cache {
					delete(c.cache, k)
					break
				}
			}
		}
		c.cache[key] = info
		c.mu.Unlock()
	}
	current, err := c.config.Principals.ResolvePrincipal(ctx)
	if err != nil {
		return gating.Decision{}, err
	}
	if ctx.Err() != nil || !gating.SamePrincipalAuthority(principal, current) || !current.Facts.ValidUntil.After(time.Now()) || !info.ValidUntil.After(time.Now()) {
		return gating.Decision{}, authz.ErrDenied
	}
	if current.Facts.ValidUntil.Before(info.ValidUntil) {
		info.ValidUntil = current.Facts.ValidUntil
	}
	effect := "allow"
	for _, item := range info.Results {
		if !item.Permissions[r.RequirementKey] {
			effect = "deny"
		}
	}
	return gating.Decision{SchemaVersion: 1, DecisionID: hex.EncodeToString(key[:12]) + ":" + r.RequestID, RequestID: r.RequestID, Subject: r.Subject, Issuer: r.Issuer, TenantID: r.TenantID, AccountID: r.AccountID, ResourceKind: r.ResourceKind, ResourceID: r.ResourceID, ResourceVersion: r.ResourceVersion, Action: r.Action, RequirementsRevision: r.RequirementsRevision, EntitySelectionHash: hash, Effect: effect, ValidUntil: info.ValidUntil, ProviderRevision: info.AuthorityRevision, RequirementKey: r.RequirementKey, ProviderRef: r.ProviderRef}, nil
}

// Permission adapts selected checks to consumers projecting one capability.
// The supplied facts must match the independently verified current principal.
func (c *EntityEvaluationClient) Permission(ctx context.Context, facts authz.Facts, entity authz.Entity, permission string) (bool, error) {
	allowed, _, err := c.PermissionWithLease(ctx, facts, entity, permission)
	return allowed, err
}

func (c *EntityEvaluationClient) CapabilityResolver(bindings []CapabilityPermissionBinding) (func(context.Context, authz.Facts, authz.Entity, string) (bool, error), error) {
	if _, err := NewCapabilityPermissionResolver(bindings); err != nil {
		return nil, err
	}
	permissions := map[capabilityKey]string{}
	for _, binding := range bindings {
		permissions[capabilityKey{binding.EntityType, binding.Capability}] = binding.Permission
	}
	return func(ctx context.Context, facts authz.Facts, entity authz.Entity, capability string) (bool, error) {
		permission := permissions[capabilityKey{entity.Type, capability}]
		if permission == "" {
			return false, nil
		}
		return c.Permission(ctx, facts, entity, permission)
	}, nil
}
