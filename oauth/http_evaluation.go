package oauth

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/viant/authz"
	"github.com/viant/authz/gating"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"time"
)

type HTTPEvaluationProvider struct {
	identity *HTTPIdentityProvider
	config   HTTPEvaluationConfig
	client   *http.Client
	lease    time.Duration
	skew     time.Duration
}

func newHTTPEvaluation(p *HTTPIdentityProvider, c HTTPEvaluationConfig) (*HTTPEvaluationProvider, error) {
	if _, e := httpEndpoint(c.URL); e != nil {
		return nil, e
	}
	lease := 5 * time.Minute
	var e error
	if c.CacheTTL != "" {
		lease, e = time.ParseDuration(c.CacheTTL)
		if e != nil || lease <= 0 || lease > 5*time.Minute {
			return nil, fmt.Errorf("evaluation lease must be positive and at most five minutes")
		}
	}
	skew := time.Duration(0)
	if c.SourceClockSkew != "" {
		skew, e = time.ParseDuration(c.SourceClockSkew)
		if e != nil || skew < 0 || skew > 5*time.Second {
			return nil, fmt.Errorf("evaluation source clock skew must be zero to five seconds")
		}
	}
	if c.MaxEntries < 0 {
		return nil, fmt.Errorf("negative cache capacity")
	}
	m := c.Mapping
	for _, path := range []string{m.RequestEntityType, m.RequestEntityIDs, m.RequestPermissions, m.Issuer, m.Subject, m.AccountID, m.EntityType, m.Results, m.ResultEntityID, m.ResultPermissions, m.AuthorityRevision, m.EvaluatedAt, m.ValidUntil} {
		if !validHTTPPath(path) {
			return nil, fmt.Errorf("explicit evaluation mapping paths required")
		}
	}
	for _, path := range []string{m.RequestScope, m.RequestResourceType, m.Status, m.UserID, m.Scope, m.ResourceType, m.Permissions} {
		if path != "" && !validHTTPPath(path) {
			return nil, fmt.Errorf("invalid evaluation mapping path")
		}
	}
	if (m.Status == "") != (m.StatusValue == "") || p.config.Mapping.UserID != "" && m.UserID == "" {
		return nil, fmt.Errorf("evaluation status/user binding missing")
	}
	bindings := map[string]HTTPAccountRequirement{}
	for key, value := range c.Entitlements {
		if key == "" || value.ResourceType == "" || value.Permission == "" || strings.TrimSpace(key) != key || strings.TrimSpace(value.Permission) != value.Permission {
			return nil, fmt.Errorf("invalid account requirement")
		}
		bindings[key] = value
	}
	c.Entitlements = bindings
	if len(bindings) > 0 && (c.EntitlementProviderRef == "" || m.RequestScope == "" || m.RequestResourceType == "" || m.Scope == "" || m.ResourceType == "" || m.Permissions == "") {
		return nil, fmt.Errorf("account entitlement mappings required")
	}
	return &HTTPEvaluationProvider{identity: p, config: c, client: authorityClient(c.Client), lease: lease, skew: skew}, nil
}
func setHTTPPath(root map[string]any, path string, value any) error {
	parts := strings.Split(path, ".")
	current := root
	for _, part := range parts[:len(parts)-1] {
		if old, found := current[part]; found {
			child, ok := old.(map[string]any)
			if !ok {
				return authz.ErrDenied
			}
			current = child
		} else {
			child := map[string]any{}
			current[part] = child
			current = child
		}
	}
	leaf := parts[len(parts)-1]
	if _, found := current[leaf]; found {
		return authz.ErrDenied
	}
	current[leaf] = value
	return nil
}
func (e *HTTPEvaluationProvider) CheckEntityPermission(ctx context.Context, r gating.ProviderRequest) (gating.Decision, error) {
	return e.check(ctx, r, false)
}
func (e *HTTPEvaluationProvider) CheckEntitlement(ctx context.Context, r gating.ProviderRequest) (gating.Decision, error) {
	return e.check(ctx, r, true)
}
func (e *HTTPEvaluationProvider) check(ctx context.Context, r gating.ProviderRequest, account bool) (gating.Decision, error) {
	if e == nil || ctx == nil || ctx.Err() != nil || r.RequestID == "" || r.RequirementKey == "" || r.RequirementsRevision == "" || (r.SchemaVersion != 1 && r.SchemaVersion != 2) {
		return gating.Decision{}, authz.ErrDenied
	}
	selected, selectionHash, err := gating.CanonicalSelection(r.EntitySelection)
	if err != nil || selectionHash != r.EntitySelectionHash || !reflect.DeepEqual(selected, r.EntitySelection) || len(selected) > 500 {
		return gating.Decision{}, authz.ErrDenied
	}
	m := e.config.Mapping
	body := map[string]any{}
	permission := r.RequirementKey
	kind := ""
	if account {
		binding, found := e.config.Entitlements[r.RequirementKey]
		if !found || len(selected) != 0 || r.ProviderRef != e.config.EntitlementProviderRef {
			return gating.Decision{}, authz.ErrDenied
		}
		kind, permission = binding.ResourceType, binding.Permission
		if setHTTPPath(body, m.RequestScope, "account") != nil || setHTTPPath(body, m.RequestResourceType, kind) != nil {
			return gating.Decision{}, authz.ErrDenied
		}
	} else {
		if len(selected) == 0 || r.ProviderRef != "entity" {
			return gating.Decision{}, authz.ErrDenied
		}
		kind = selected[0].Type
		ids := []any{}
		for _, entity := range selected {
			if entity.Type != kind {
				return gating.Decision{}, authz.ErrDenied
			}
			var id any = entity.ID
			if m.IntegerEntityIDs {
				integer, err := strconv.ParseInt(entity.ID, 10, 64)
				if err != nil || integer <= 0 || strconv.FormatInt(integer, 10) != entity.ID {
					return gating.Decision{}, authz.ErrDenied
				}
				id = integer
			}
			ids = append(ids, id)
		}
		if setHTTPPath(body, m.RequestEntityType, kind) != nil || setHTTPPath(body, m.RequestEntityIDs, ids) != nil {
			return gating.Decision{}, authz.ErrDenied
		}
	}
	if setHTTPPath(body, m.RequestPermissions, []string{permission}) != nil {
		return gating.Decision{}, authz.ErrDenied
	}
	base := e.identity.withoutScope(ctx)
	before, err := e.identity.readProfile(base)
	if err != nil {
		return gating.Decision{}, err
	}
	principal := before.principal
	if principal.Facts.Subject != r.Subject || principal.Facts.Issuer != r.Issuer || principal.Facts.Tenant != r.TenantID || principal.AccountID != r.AccountID || !principal.Facts.ValidUntil.After(time.Now()) {
		return gating.Decision{}, authz.ErrDenied
	}
	raw, _ := json.Marshal(body)
	started := time.Now()
	req, err := http.NewRequestWithContext(base, "POST", e.config.URL, bytes.NewReader(raw))
	if err != nil {
		return gating.Decision{}, authz.ErrUnavailable
	}
	req.Header.Set("Authorization", "Bearer "+Bearer(base))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Cache-Control", "no-cache")
	resp, err := e.client.Do(req)
	if err != nil {
		return gating.Decision{}, authz.ErrUnavailable
	}
	response, err := decodeHTTPBody(resp, 1<<20)
	if err != nil {
		return gating.Decision{}, err
	}
	if m.Status != "" {
		status, err := stringAt(response, m.Status)
		if err != nil || status != m.StatusValue {
			return gating.Decision{}, authz.ErrDenied
		}
	}
	issuer, err := stringAt(response, m.Issuer)
	if err != nil || issuer != r.Issuer {
		return gating.Decision{}, authz.ErrDenied
	}
	subject, err := stringAt(response, m.Subject)
	if err != nil || subject != r.Subject {
		return gating.Decision{}, authz.ErrDenied
	}
	accountID, err := idAt(response, m.AccountID)
	if err != nil || accountID != r.AccountID {
		return gating.Decision{}, authz.ErrDenied
	}
	if m.UserID != "" {
		user, err := idAt(response, m.UserID)
		if err != nil || user != before.userID {
			return gating.Decision{}, authz.ErrDenied
		}
	}
	revision, err := stringAt(response, m.AuthorityRevision)
	if err != nil {
		return gating.Decision{}, authz.ErrDenied
	}
	allowed := true
	if account {
		if results, found, err := rawHTTPPath(response, m.Results); err != nil || found && !bytes.Equal(results, []byte("null")) {
			return gating.Decision{}, authz.ErrDenied
		}
		scope, err := stringAt(response, m.Scope)
		if err != nil || scope != "account" {
			return gating.Decision{}, authz.ErrDenied
		}
		resource, err := stringAt(response, m.ResourceType)
		if err != nil || resource != kind {
			return gating.Decision{}, authz.ErrDenied
		}
		v, err := requiredHTTPPath(response, m.Permissions)
		var permissions map[string]bool
		if err != nil || json.Unmarshal(v, &permissions) != nil || len(permissions) != 1 {
			return gating.Decision{}, authz.ErrDenied
		}
		value, found := permissions[permission]
		if !found {
			return gating.Decision{}, authz.ErrDenied
		}
		allowed = value
	} else {
		if m.Scope != "" {
			if value, found, err := rawHTTPPath(response, m.Scope); err != nil {
				return gating.Decision{}, authz.ErrDenied
			} else if found && !bytes.Equal(value, []byte("null")) {
				scope, err := httpString(value)
				if err != nil || scope != "entity" {
					return gating.Decision{}, authz.ErrDenied
				}
			}
		}
		if m.Permissions != "" {
			if value, found, err := rawHTTPPath(response, m.Permissions); err != nil || found && !bytes.Equal(value, []byte("null")) {
				return gating.Decision{}, authz.ErrDenied
			}
		}
		responseKind, err := stringAt(response, m.EntityType)
		if err != nil || responseKind != kind {
			return gating.Decision{}, authz.ErrDenied
		}
		v, err := requiredHTTPPath(response, m.Results)
		var results []json.RawMessage
		if err != nil || json.Unmarshal(v, &results) != nil || len(results) != len(selected) {
			return gating.Decision{}, authz.ErrDenied
		}
		expected := map[string]bool{}
		for _, entity := range selected {
			expected[entity.ID] = true
		}
		for _, result := range results {
			id, err := idAt(result, m.ResultEntityID)
			if err != nil || !expected[id] {
				return gating.Decision{}, authz.ErrDenied
			}
			delete(expected, id)
			v, err := requiredHTTPPath(result, m.ResultPermissions)
			var permissions map[string]bool
			if err != nil || json.Unmarshal(v, &permissions) != nil || len(permissions) != 1 {
				return gating.Decision{}, authz.ErrDenied
			}
			value, found := permissions[permission]
			if !found {
				return gating.Decision{}, authz.ErrDenied
			}
			allowed = allowed && value
		}
	}
	deadline, err := deadlineHTTP(started, time.Now(), principal.Facts.ValidUntil, e.lease, e.skew, response, m.EvaluatedAt, m.ValidUntil, true)
	if err != nil {
		return gating.Decision{}, err
	}
	after, err := e.identity.readProfile(base)
	if err != nil {
		return gating.Decision{}, err
	}
	deadline = minHTTPTime(deadline, after.principal.Facts.ValidUntil)
	if ctx.Err() != nil || !deadline.After(time.Now()) || before.bearerHash != after.bearerHash || !gating.SamePrincipalAuthority(before.principal, after.principal) {
		return gating.Decision{}, authz.ErrDenied
	}
	var random [16]byte
	if _, err = rand.Read(random[:]); err != nil {
		return gating.Decision{}, authz.ErrUnavailable
	}
	effect := "deny"
	if allowed {
		effect = "allow"
	}
	return gating.Decision{SchemaVersion: r.SchemaVersion, DecisionID: hex.EncodeToString(random[:]), RequestID: r.RequestID, Subject: r.Subject, Issuer: r.Issuer, TenantID: r.TenantID, AccountID: r.AccountID, ResourceKind: r.ResourceKind, ResourceID: r.ResourceID, ResourceVersion: r.ResourceVersion, Action: r.Action, RequirementsRevision: r.RequirementsRevision, EntitySelectionHash: r.EntitySelectionHash, RequirementKey: r.RequirementKey, ProviderRef: r.ProviderRef, ProviderRevision: revision, ValidUntil: deadline, Effect: effect}, nil
}
func (e *HTTPEvaluationProvider) PermissionWithLease(ctx context.Context, facts authz.Facts, entity authz.Entity, permission string) (bool, time.Time, error) {
	principal, err := e.identity.ResolvePrincipal(e.identity.withoutScope(ctx))
	if err != nil {
		return false, time.Time{}, err
	}
	if !sameVerifiedAccountFacts(principal.Facts, facts) || !facts.ValidUntil.After(time.Now()) {
		return false, time.Time{}, authz.ErrDenied
	}
	selected, hash, err := gating.CanonicalSelection([]authz.Entity{entity})
	if err != nil {
		return false, time.Time{}, err
	}
	decision, err := e.CheckEntityPermission(ctx, gating.ProviderRequest{SchemaVersion: 1, RequestID: "capability-" + hashHTTP([]string{entity.Type, entity.ID, permission}), Subject: facts.Subject, Issuer: facts.Issuer, TenantID: facts.Tenant, AccountID: principal.AccountID, ResourceKind: "capability", ResourceID: entity.ID, ResourceVersion: "current", Action: permission, RequirementsRevision: "host-capability", RequirementKey: permission, ProviderRef: "entity", EntitySelection: selected, EntitySelectionHash: hash})
	if err != nil {
		return false, time.Time{}, err
	}
	return decision.Effect == "allow", minHTTPTime(facts.ValidUntil, decision.ValidUntil), nil
}
