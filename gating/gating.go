// Package gating composes account and entity requirements with authz ACLs.
// Providers and mappings are trusted host dependencies, never request payloads.
package gating

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/viant/authz"
)

var ErrUnavailable = errors.New("authorization gate unavailable")

type Principal struct {
	Facts            authz.Facts `json:"facts"`
	AccountID        string      `json:"accountId"`
	MembershipGroups []string    `json:"membershipGroups,omitempty"`
	IdentityRevision string      `json:"identityRevision"`
}

type PrincipalResolver interface {
	ResolvePrincipal(context.Context) (Principal, error)
}

type EntityRequirement struct {
	Type               string `json:"type"`
	Permission         string `json:"permission"`
	SelectionParameter string `json:"selectionParameter,omitempty"`
	SelectionMode      string `json:"selectionMode"` // single or multiple
}

type EntitlementRequirement struct {
	ProviderRef string `json:"providerRef"`
	Key         string `json:"key"`
	Scope       string `json:"scope"` // account or entity
}

type Requirements struct {
	SchemaVersion     int                     `json:"schemaVersion"`
	RequiredExposures []string                `json:"requiredExposures,omitempty"`
	AllowedRoles      []string                `json:"allowedRoles,omitempty"`
	Entity            *EntityRequirement      `json:"entity,omitempty"`
	Entitlement       *EntitlementRequirement `json:"entitlement,omitempty"`
}

type RequirementsDocument struct {
	Revision     string       `json:"revision"`
	Requirements Requirements `json:"requirements"`
}

type RequirementsStore interface {
	GetRequirements(context.Context, authz.Resource, string) (RequirementsDocument, error)
}

// ProviderRequest contains only server-assembled, verified fields.
type ProviderRequest struct {
	SchemaVersion        int            `json:"schemaVersion"`
	RequestID            string         `json:"requestId"`
	Subject              string         `json:"subject"`
	Issuer               string         `json:"issuer"`
	TenantID             string         `json:"tenantId"`
	AccountID            string         `json:"accountId"`
	ResourceKind         string         `json:"resourceKind"`
	ResourceID           string         `json:"resourceId"`
	ResourceVersion      string         `json:"resourceVersion"`
	Action               string         `json:"action"`
	RequirementsRevision string         `json:"requirementsRevision"`
	RequirementKey       string         `json:"requirementKey"`
	ProviderRef          string         `json:"providerRef,omitempty"`
	EntitySelection      []authz.Entity `json:"entitySelection,omitempty"`
	EntitySelectionHash  string         `json:"entitySelectionHash"`
}

type Decision struct {
	SchemaVersion        int       `json:"schemaVersion"`
	DecisionID           string    `json:"decisionId"`
	RequestID            string    `json:"requestId"`
	Subject              string    `json:"subject"`
	Issuer               string    `json:"issuer"`
	TenantID             string    `json:"tenantId"`
	AccountID            string    `json:"accountId"`
	ResourceKind         string    `json:"resourceKind"`
	ResourceID           string    `json:"resourceId"`
	ResourceVersion      string    `json:"resourceVersion"`
	Action               string    `json:"action"`
	RequirementsRevision string    `json:"requirementsRevision"`
	EntitySelectionHash  string    `json:"entitySelectionHash"`
	Effect               string    `json:"effect"`
	ReasonCode           string    `json:"reasonCode,omitempty"`
	ValidUntil           time.Time `json:"validUntil"`
	ProviderRevision     string    `json:"providerRevision"`
	RequirementKey       string    `json:"requirementKey,omitempty"`
	ProviderRef          string    `json:"providerRef,omitempty"`
}

type EntityPermissionProvider interface {
	CheckEntityPermission(context.Context, ProviderRequest) (Decision, error)
}

type EntitlementProvider interface {
	CheckEntitlement(context.Context, ProviderRequest) (Decision, error)
}

type Request struct {
	RequestID string
	Resource  authz.Resource
	Action    string
	Selected  []authz.Entity
}

type Evaluator struct {
	ACL          *authz.Service
	Principals   PrincipalResolver
	Requirements RequirementsStore
	Entities     EntityPermissionProvider
	Entitlements map[string]EntitlementProvider // trusted providerRef registry
	Now          func() time.Time
}

func (e *Evaluator) Evaluate(ctx context.Context, req Request) (Decision, error) {
	return e.evaluate(ctx, req, true)
}

// EvaluateRequirementsOnly checks mandatory requirements for a child whose ACL
// is inherited or whose explicit publicConsumption grant was established by a
// trusted host. Its allow result is never an ACL grant by itself.
func (e *Evaluator) EvaluateRequirementsOnly(ctx context.Context, req Request) (Decision, error) {
	return e.evaluate(ctx, req, false)
}

func (e *Evaluator) evaluate(ctx context.Context, req Request, withACL bool) (Decision, error) {
	if e == nil || withACL && e.ACL == nil || e.Principals == nil || e.Requirements == nil || ctx == nil || ctx.Err() != nil {
		return Decision{}, ErrUnavailable
	}
	if req.RequestID == "" || req.Resource.Kind == "" || req.Resource.ID == "" || req.Action == "" {
		return Decision{}, authz.ErrDenied
	}
	now := time.Now()
	if e.Now != nil {
		now = e.Now()
	}
	p, err := e.Principals.ResolvePrincipal(ctx)
	if errors.Is(err, authz.ErrDenied) {
		return Decision{}, authz.ErrDenied
	}
	if err != nil {
		return Decision{}, ErrUnavailable
	}
	if p.AccountID == "" || p.IdentityRevision == "" || p.Facts.Subject == "" || p.Facts.Issuer == "" || p.Facts.Tenant == "" || !p.Facts.ValidUntil.After(now) || (req.Resource.Tenant != "*" && p.Facts.Tenant != req.Resource.Tenant) {
		return Decision{}, authz.ErrDenied
	}
	doc, err := e.Requirements.GetRequirements(ctx, req.Resource, req.Action)
	if errors.Is(err, authz.ErrDenied) || errors.Is(err, sql.ErrNoRows) {
		return Decision{}, authz.ErrDenied
	}
	if err != nil {
		return Decision{}, ErrUnavailable
	}
	if doc.Revision == "" {
		return Decision{}, authz.ErrDenied
	}
	if !validRequirements(doc.Requirements) {
		return Decision{}, ErrUnavailable
	}
	selected, hash, err := CanonicalSelection(req.Selected)
	if err != nil {
		return Decision{}, authz.ErrDenied
	}
	base := ProviderRequest{SchemaVersion: 1, RequestID: req.RequestID, Subject: p.Facts.Subject, Issuer: p.Facts.Issuer, TenantID: p.Facts.Tenant, AccountID: p.AccountID, ResourceKind: req.Resource.Kind, ResourceID: req.Resource.ID, ResourceVersion: req.Resource.Version, Action: req.Action, RequirementsRevision: doc.Revision, EntitySelection: selected, EntitySelectionHash: hash}
	var decisionID [16]byte
	if _, err := rand.Read(decisionID[:]); err != nil {
		return Decision{}, ErrUnavailable
	}
	identityRevision := sha256.Sum256([]byte(p.IdentityRevision))
	result := Decision{SchemaVersion: 1, DecisionID: hex.EncodeToString(decisionID[:]), RequestID: base.RequestID, Subject: base.Subject, Issuer: base.Issuer, TenantID: base.TenantID, AccountID: base.AccountID, ResourceKind: base.ResourceKind, ResourceID: base.ResourceID, ResourceVersion: base.ResourceVersion, Action: base.Action, RequirementsRevision: base.RequirementsRevision, EntitySelectionHash: hash, Effect: "deny", ValidUntil: p.Facts.ValidUntil, ProviderRevision: "local:" + doc.Revision + ":identity:" + hex.EncodeToString(identityRevision[:12])}
	deny := func(reason string) (Decision, error) { result.ReasonCode = reason; return result, nil }
	if withACL {
		acl, facts, policyRevision, err := e.ACL.AuthorizeWithStatus(ctx, authz.Request{Resource: req.Resource, Action: req.Action})
		if err != nil {
			if errors.Is(err, authz.ErrUnavailable) {
				return Decision{}, ErrUnavailable
			}
			if errors.Is(err, authz.ErrIdentityDenied) {
				return Decision{}, authz.ErrDenied
			}
			if policyRevision > 0 {
				result.ProviderRevision += ":policy:" + strconv.FormatInt(policyRevision, 10)
			}
			return deny("policyDenied")
		}
		result.ProviderRevision += ":policy:" + strconv.FormatInt(policyRevision, 10)
		if facts.Subject != "" && (facts.Subject != p.Facts.Subject || facts.Issuer != p.Facts.Issuer || facts.Tenant != p.Facts.Tenant || !facts.ValidUntil.After(now) || !reflect.DeepEqual(facts.Roles, p.Facts.Roles) || !reflect.DeepEqual(facts.Exposures, p.Facts.Exposures) || !reflect.DeepEqual(facts.EntityGroups, p.Facts.EntityGroups) || !reflect.DeepEqual(facts.Entities, p.Facts.Entities) || !reflect.DeepEqual(facts.EntityPermissions, p.Facts.EntityPermissions) || !reflect.DeepEqual(facts.GrantedScopes, p.Facts.GrantedScopes)) {
			return Decision{}, ErrUnavailable
		}
		if facts.Subject != "" && facts.ValidUntil.Before(result.ValidUntil) {
			result.ValidUntil = facts.ValidUntil
		}
		if acl.Bounded {
			if len(selected) == 0 {
				return deny("needsEntity")
			}
			allowed := map[authz.Entity]bool{}
			for _, item := range acl.Entities {
				allowed[item] = true
			}
			for _, item := range selected {
				if !allowed[item] {
					return deny("entityDenied")
				}
			}
		}
	}
	r := doc.Requirements
	for _, exposure := range r.RequiredExposures {
		if !contains(p.Facts.Exposures, exposure) {
			return deny("featureDisabled")
		}
	}
	if len(r.AllowedRoles) != 0 {
		matched := false
		for _, role := range r.AllowedRoles {
			matched = matched || contains(p.Facts.Roles, role)
		}
		if !matched {
			return deny("roleDenied")
		}
	}
	if r.Entity != nil {
		if len(selected) == 0 {
			return deny("needsEntity")
		}
		if r.Entity.SelectionMode == "single" && len(selected) != 1 {
			return deny("entityDenied")
		}
		for _, item := range selected {
			if item.Type != r.Entity.Type {
				return deny("entityDenied")
			}
		}
		if e.Entities == nil {
			return Decision{}, ErrUnavailable
		}
		base.RequirementKey = r.Entity.Permission
		base.ProviderRef = "entity"
		checked, err := e.Entities.CheckEntityPermission(ctx, base)
		if errors.Is(err, authz.ErrDenied) {
			return Decision{}, authz.ErrDenied
		}
		if err != nil || !validProviderDecision(checked, base, now) {
			return Decision{}, ErrUnavailable
		}
		if checked.ValidUntil.Before(result.ValidUntil) {
			result.ValidUntil = checked.ValidUntil
		}
		result.ProviderRevision += ":entity:" + checked.ProviderRevision
		if checked.Effect == "deny" {
			return deny("entityDenied")
		}
	}
	if r.Entitlement != nil {
		if r.Entitlement.Scope == "entity" && len(selected) == 0 {
			return deny("needsEntity")
		}
		provider := e.Entitlements[r.Entitlement.ProviderRef]
		if provider == nil {
			return Decision{}, ErrUnavailable
		}
		base.RequirementKey = r.Entitlement.Key
		base.ProviderRef = r.Entitlement.ProviderRef
		checked, err := provider.CheckEntitlement(ctx, base)
		if errors.Is(err, authz.ErrDenied) {
			return Decision{}, authz.ErrDenied
		}
		if err != nil || !validProviderDecision(checked, base, now) {
			return Decision{}, ErrUnavailable
		}
		if checked.ValidUntil.Before(result.ValidUntil) {
			result.ValidUntil = checked.ValidUntil
		}
		result.ProviderRevision += ":entitlement:" + checked.ProviderRevision
		if checked.Effect == "deny" {
			if checked.ReasonCode == "subscriptionExpired" {
				return deny("subscriptionExpired")
			}
			return deny("subscriptionRequired")
		}
	}
	if ctx.Err() != nil {
		return Decision{}, ErrUnavailable
	}
	if !withACL || r.Entity != nil || r.Entitlement != nil {
		current, err := e.Principals.ResolvePrincipal(ctx)
		if errors.Is(err, authz.ErrDenied) {
			return Decision{}, authz.ErrDenied
		}
		if err != nil || !samePrincipalAuthority(p, current) || !current.Facts.ValidUntil.After(now) {
			return Decision{}, ErrUnavailable
		}
		if current.Facts.ValidUntil.Before(result.ValidUntil) {
			result.ValidUntil = current.Facts.ValidUntil
		}
	}
	if !result.ValidUntil.After(now) {
		return Decision{}, authz.ErrDenied
	}
	result.Effect = "allow"
	return result, nil
}

func samePrincipalAuthority(a, b Principal) bool {
	return a.IdentityRevision == b.IdentityRevision &&
		a.AccountID == b.AccountID &&
		a.Facts.Subject == b.Facts.Subject &&
		a.Facts.Issuer == b.Facts.Issuer &&
		a.Facts.Tenant == b.Facts.Tenant &&
		reflect.DeepEqual(a.MembershipGroups, b.MembershipGroups) &&
		reflect.DeepEqual(a.Facts.Roles, b.Facts.Roles) &&
		reflect.DeepEqual(a.Facts.Exposures, b.Facts.Exposures) &&
		reflect.DeepEqual(a.Facts.EntityGroups, b.Facts.EntityGroups) &&
		reflect.DeepEqual(a.Facts.Entities, b.Facts.Entities) &&
		reflect.DeepEqual(a.Facts.EntityPermissions, b.Facts.EntityPermissions) &&
		reflect.DeepEqual(a.Facts.GrantedScopes, b.Facts.GrantedScopes)
}

// SamePrincipalAuthority compares the verified identity and account facts that
// bind one authorization operation. Leases are checked separately by callers.
func SamePrincipalAuthority(a, b Principal) bool { return samePrincipalAuthority(a, b) }

// Check is the narrow in-process host bridge. Primitive return fields keep a
// consumer independent of the gating package version while retaining the
// identity, account, revision and lease bindings it must verify.
func (e *Evaluator) Check(ctx context.Context, resource authz.Resource, action string, selected []authz.Entity) (bool, string, time.Time, string, string, string, string, error) {
	return e.check(ctx, resource, action, selected, true)
}

// CheckRequirementsOnly is the narrow host bridge for inherited and public
// consumption ACL modes. Its allow result must be intersected with a separately
// established workspace/child grant; it cannot authorize consumption alone.
func (e *Evaluator) CheckRequirementsOnly(ctx context.Context, resource authz.Resource, action string, selected []authz.Entity) (bool, string, time.Time, string, string, string, string, error) {
	return e.check(ctx, resource, action, selected, false)
}

func (e *Evaluator) check(ctx context.Context, resource authz.Resource, action string, selected []authz.Entity, withACL bool) (bool, string, time.Time, string, string, string, string, error) {
	var requestID [16]byte
	if _, err := rand.Read(requestID[:]); err != nil {
		return false, "", time.Time{}, "", "", "", "", ErrUnavailable
	}
	request := Request{RequestID: hex.EncodeToString(requestID[:]), Resource: resource, Action: action, Selected: selected}
	var decision Decision
	var err error
	if withACL {
		decision, err = e.Evaluate(ctx, request)
	} else {
		decision, err = e.EvaluateRequirementsOnly(ctx, request)
	}
	if err != nil {
		return false, "", time.Time{}, "", "", "", "", err
	}
	if decision.ResourceKind != resource.Kind || decision.ResourceID != resource.ID || decision.ResourceVersion != resource.Version || decision.Action != action || decision.RequirementsRevision == "" || decision.ProviderRevision == "" {
		return false, "", time.Time{}, "", "", "", "", ErrUnavailable
	}
	return decision.Effect == "allow", decision.RequirementsRevision + ":" + decision.ProviderRevision, decision.ValidUntil, decision.Subject, decision.Issuer, decision.TenantID, decision.AccountID, nil
}

func validRequirements(r Requirements) bool {
	if r.SchemaVersion != 1 {
		return false
	}
	for _, values := range [][]string{r.RequiredExposures, r.AllowedRoles} {
		for _, value := range values {
			if value == "" || strings.TrimSpace(value) != value {
				return false
			}
		}
	}
	if r.Entity != nil && (r.Entity.Type == "" || r.Entity.Permission == "" || (r.Entity.SelectionMode != "single" && r.Entity.SelectionMode != "multiple")) {
		return false
	}
	if r.Entitlement != nil && (r.Entitlement.ProviderRef == "" || r.Entitlement.Key == "" || (r.Entitlement.Scope != "account" && r.Entitlement.Scope != "entity") || (r.Entitlement.Scope == "entity" && r.Entity == nil)) {
		return false
	}
	return true
}

// CanonicalSelection preserves exact entity strings while sorting and
// deduplicating typed tuples for provider request binding.
func CanonicalSelection(input []authz.Entity) ([]authz.Entity, string, error) {
	selected := append([]authz.Entity(nil), input...)
	for _, item := range selected {
		if item.Type == "" || item.ID == "" || strings.TrimSpace(item.Type) != item.Type || strings.TrimSpace(item.ID) != item.ID {
			return nil, "", authz.ErrDenied
		}
	}
	sort.Slice(selected, func(i, j int) bool {
		if selected[i].Type == selected[j].Type {
			return selected[i].ID < selected[j].ID
		}
		return selected[i].Type < selected[j].Type
	})
	unique := selected[:0]
	for _, item := range selected {
		if len(unique) == 0 || unique[len(unique)-1] != item {
			unique = append(unique, item)
		}
	}
	if unique == nil {
		unique = []authz.Entity{}
	}
	raw, _ := json.Marshal(unique)
	sum := sha256.Sum256(raw)
	return unique, hex.EncodeToString(sum[:]), nil
}

func contains(values []string, sought string) bool {
	for _, value := range values {
		if value == sought {
			return true
		}
	}
	return false
}

func validProviderDecision(d Decision, r ProviderRequest, now time.Time) bool {
	return d.SchemaVersion == 1 && d.DecisionID != "" && d.RequestID == r.RequestID && d.Subject == r.Subject && d.Issuer == r.Issuer && d.TenantID == r.TenantID && d.AccountID == r.AccountID && d.ResourceKind == r.ResourceKind && d.ResourceID == r.ResourceID && d.ResourceVersion == r.ResourceVersion && d.Action == r.Action && d.RequirementsRevision == r.RequirementsRevision && d.EntitySelectionHash == r.EntitySelectionHash && d.RequirementKey == r.RequirementKey && d.ProviderRef == r.ProviderRef && d.ProviderRevision != "" && d.ValidUntil.After(now) && (d.Effect == "allow" || d.Effect == "deny")
}
