package gating

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/viant/authz"
)

type principalSource struct{ value Principal }

func (s *principalSource) ResolvePrincipal(context.Context) (Principal, error) { return s.value, nil }
func (s *principalSource) Resolve(context.Context) (authz.Facts, error)        { return s.value.Facts, nil }

type failingPrincipal struct{ err error }

func (p failingPrincipal) ResolvePrincipal(context.Context) (Principal, error) {
	return Principal{}, p.err
}

type failingFactsProvider struct{ err error }

func (p failingFactsProvider) Resolve(context.Context) (authz.Facts, error) {
	return authz.Facts{}, p.err
}

type changingPrincipal struct {
	first, next Principal
	reads       int
}

func (p *changingPrincipal) ResolvePrincipal(context.Context) (Principal, error) {
	p.reads++
	if p.reads == 1 {
		return p.first, nil
	}
	return p.next, nil
}

type policyStore struct{ doc authz.Document }

func (s policyStore) Get(context.Context, authz.Resource) (authz.Document, error) { return s.doc, nil }
func (s policyStore) Replace(context.Context, authz.Document, int64, string) (authz.Document, error) {
	return authz.Document{}, authz.ErrDenied
}

type unavailablePolicyStore struct{}

func (unavailablePolicyStore) Get(context.Context, authz.Resource) (authz.Document, error) {
	return authz.Document{}, ErrUnavailable
}
func (unavailablePolicyStore) Replace(context.Context, authz.Document, int64, string) (authz.Document, error) {
	return authz.Document{}, authz.ErrDenied
}

type requirementStore struct{ doc RequirementsDocument }

func (s requirementStore) GetRequirements(context.Context, authz.Resource, string) (RequirementsDocument, error) {
	return s.doc, nil
}

type failingRequirementStore struct{ err error }

func (s failingRequirementStore) GetRequirements(context.Context, authz.Resource, string) (RequirementsDocument, error) {
	return RequirementsDocument{}, s.err
}

type writableRequirements struct {
	doc    RequirementsDocument
	writes int
}

type editorChoicesFunc func(context.Context, authz.Resource, string) (EditorChoices, error)

func (f editorChoicesFunc) ResolveChoices(ctx context.Context, resource authz.Resource, action string) (EditorChoices, error) {
	return f(ctx, resource, action)
}

func (s *writableRequirements) GetRequirements(context.Context, authz.Resource, string) (RequirementsDocument, error) {
	return s.doc, nil
}
func (s *writableRequirements) ReplaceRequirements(_ context.Context, _ authz.Resource, _ string, expected string, value Requirements) (RequirementsDocument, error) {
	if s.doc.Revision != expected {
		return RequirementsDocument{}, authz.ErrConflict
	}
	s.writes++
	s.doc = RequirementsDocument{Revision: "r2", Requirements: value}
	return s.doc, nil
}

type entityProvider func(ProviderRequest) Decision

func (f entityProvider) CheckEntityPermission(_ context.Context, r ProviderRequest) (Decision, error) {
	return f(r), nil
}

type entityProviderError struct{ err error }

func (p entityProviderError) CheckEntityPermission(context.Context, ProviderRequest) (Decision, error) {
	return Decision{}, p.err
}

type entitlementProvider func(ProviderRequest) Decision

func (f entitlementProvider) CheckEntitlement(_ context.Context, r ProviderRequest) (Decision, error) {
	return f(r), nil
}

type entitlementProviderError struct{ err error }

func (p entitlementProviderError) CheckEntitlement(context.Context, ProviderRequest) (Decision, error) {
	return Decision{}, p.err
}

func providerAllow(r ProviderRequest) Decision {
	return Decision{SchemaVersion: 1, DecisionID: "decision", RequestID: r.RequestID, Subject: r.Subject, Issuer: r.Issuer, TenantID: r.TenantID, AccountID: r.AccountID, ResourceKind: r.ResourceKind, ResourceID: r.ResourceID, ResourceVersion: r.ResourceVersion, Action: r.Action, RequirementsRevision: r.RequirementsRevision, EntitySelectionHash: r.EntitySelectionHash, RequirementKey: r.RequirementKey, ProviderRef: r.ProviderRef, Effect: "allow", ValidUntil: time.Now().Add(time.Minute), ProviderRevision: "p1"}
}

func setup() (*Evaluator, *principalSource, Request) {
	resource := authz.Resource{Kind: "window", ID: "orders", Version: "1", Tenant: "tenant"}
	p := &principalSource{Principal{Facts: authz.Facts{Subject: "alice", Issuer: "issuer", Tenant: "tenant", Roles: []string{"reader"}, Exposures: []string{"feature"}, EntityGroups: authz.EntityGroups{"customer": {"123", "456"}}, ValidUntil: time.Now().Add(time.Hour)}, AccountID: "account-1", IdentityRevision: "identity-1"}}
	e := &Evaluator{ACL: &authz.Service{Store: policyStore{authz.Document{Resource: resource, Revision: 1, Policies: map[string]authz.Policy{"execute": {Mode: "protected", Rule: &authz.Rule{Kind: "role", Value: "reader"}, EntityType: "customer"}}}}, Provider: p}, Principals: p, Requirements: requirementStore{RequirementsDocument{Revision: "requirements-1", Requirements: Requirements{SchemaVersion: 1, RequiredExposures: []string{"feature"}, AllowedRoles: []string{"reader"}, Entity: &EntityRequirement{Type: "customer", Permission: "read", SelectionMode: "multiple"}}}}, Entities: entityProvider(providerAllow)}
	return e, p, Request{RequestID: "request-1", Resource: resource, Action: "execute", Selected: []authz.Entity{{Type: "customer", ID: "123"}, {Type: "customer", ID: "456"}}}
}

func TestRequirementsAreIndependentAndAccountBound(t *testing.T) {
	e, p, req := setup()
	assert := func(want string) {
		t.Helper()
		got, err := e.Evaluate(context.Background(), req)
		if err != nil || got.Effect != want {
			t.Fatalf("effect=%q reason=%q err=%v", got.Effect, got.ReasonCode, err)
		}
	}
	assert("allow")
	p.value.Facts.Exposures = nil
	assert("deny")
	p.value.Facts.Exposures = []string{"feature"}
	p.value.Facts.Roles = []string{"other"}
	assert("deny")
	p.value.Facts.Roles = []string{"reader"}
	p.value.AccountID = "account-2"
	// The account value returned by the trusted principal source is echoed; a
	// provider bound to the old account cannot be replayed for the new one.
	e.Entities = entityProvider(func(r ProviderRequest) Decision { d := providerAllow(r); d.AccountID = "account-1"; return d })
	if _, err := e.Evaluate(context.Background(), req); err != ErrUnavailable {
		t.Fatalf("cross-account provider response: %v", err)
	}
}

func TestRequirementsOnlySupportsInheritedACLWithoutCreatingGrant(t *testing.T) {
	e, principal, request := setup()
	e.ACL = nil
	e.Requirements = requirementStore{RequirementsDocument{Revision: "requirements-1", Requirements: Requirements{SchemaVersion: 1, RequiredExposures: []string{"feature"}, AllowedRoles: []string{"reader"}}}}
	request.Selected = nil
	decision, err := e.EvaluateRequirementsOnly(context.Background(), request)
	if err != nil || decision.Effect != "allow" || !strings.Contains(decision.ProviderRevision, "identity:") {
		t.Fatalf("inherited requirements=%+v err=%v", decision, err)
	}
	if _, err := e.Evaluate(context.Background(), request); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("requirements-only result became full ACL grant: %v", err)
	}
	allowed, revision, lease, subject, issuer, tenant, account, err := e.CheckRequirementsOnly(context.Background(), request.Resource, request.Action, nil)
	if err != nil || !allowed || revision == "" || !lease.After(time.Now()) || subject != "alice" || issuer != "issuer" || tenant != "tenant" || account != "account-1" {
		t.Fatalf("requirements bridge allow=%v revision=%q identity=%s/%s/%s/%s err=%v", allowed, revision, subject, issuer, tenant, account, err)
	}
	principal.value.Facts.Exposures = nil
	decision, err = e.EvaluateRequirementsOnly(context.Background(), request)
	if err != nil || decision.Effect != "deny" || decision.ReasonCode != "featureDisabled" {
		t.Fatalf("mandatory exposure was skipped: %+v err=%v", decision, err)
	}
	principal.value.Facts.Exposures = []string{"feature"}
	changed := principal.value
	changed.AccountID = "other-account"
	e.Principals = &changingPrincipal{first: principal.value, next: changed}
	if _, err := e.EvaluateRequirementsOnly(context.Background(), request); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("requirements-only identity switch=%v", err)
	}
}

func TestCheckBridgeReturnsVerifiedIdentityAndLease(t *testing.T) {
	e, _, req := setup()
	allow, revision, lease, subject, issuer, tenant, account, err := e.Check(context.Background(), req.Resource, req.Action, req.Selected)
	if err != nil || !allow || revision == "" || !lease.After(time.Now()) || subject != "alice" || issuer != "issuer" || tenant != "tenant" || account != "account-1" {
		t.Fatalf("bridge: allow=%v revision=%q lease=%v identity=%q/%q/%q/%q err=%v", allow, revision, lease, subject, issuer, tenant, account, err)
	}
}

func TestProviderBackedAllowRejectsPrincipalDrift(t *testing.T) {
	e, principal, req := setup()
	changed := principal.value
	changed.IdentityRevision = "identity-2"
	e.Principals = &changingPrincipal{first: principal.value, next: changed}
	if decision, err := e.Evaluate(context.Background(), req); decision.Effect != "" || err != ErrUnavailable {
		t.Fatalf("identity drift permitted provider-backed gate: %+v %v", decision, err)
	}
	shorter := principal.value
	shorter.Facts.ValidUntil = time.Now().Add(10 * time.Second)
	e.Principals = &changingPrincipal{first: principal.value, next: shorter}
	decision, err := e.Evaluate(context.Background(), req)
	if err != nil || decision.Effect != "allow" || !decision.ValidUntil.Equal(shorter.Facts.ValidUntil) {
		t.Fatalf("last verified lease not applied: %+v %v", decision, err)
	}
}

func TestOrdinaryGateRevisionTracksVerifiedIdentityChange(t *testing.T) {
	e, principal, req := setup()
	e.ACL.Store = policyStore{authz.Document{Resource: req.Resource, Revision: 1, Policies: map[string]authz.Policy{"execute": {Mode: "protected", Rule: &authz.Rule{Kind: "role", Value: "reader"}}}}}
	e.Requirements = requirementStore{RequirementsDocument{Revision: "requirements-1", Requirements: Requirements{SchemaVersion: 1, RequiredExposures: []string{"feature"}}}}
	req.Selected = nil
	first, err := e.Evaluate(context.Background(), req)
	if err != nil || first.Effect != "allow" || strings.Contains(first.ProviderRevision, "identity-1") {
		t.Fatalf("first decision=%+v err=%v", first, err)
	}
	firstAllow, firstRevision, _, _, _, _, _, err := e.Check(context.Background(), req.Resource, req.Action, nil)
	if err != nil || !firstAllow {
		t.Fatalf("first bridge revision=%q err=%v", firstRevision, err)
	}
	principal.value.IdentityRevision = "identity-2"
	second, err := e.Evaluate(context.Background(), req)
	if err != nil || second.Effect != "allow" || second.ProviderRevision == first.ProviderRevision {
		t.Fatalf("identity revision did not change: first=%q second=%q err=%v", first.ProviderRevision, second.ProviderRevision, err)
	}
	secondAllow, secondRevision, _, _, _, _, _, err := e.Check(context.Background(), req.Resource, req.Action, nil)
	if err != nil || !secondAllow || secondRevision == firstRevision {
		t.Fatalf("bridge reused old identity revision: %q %q %v", firstRevision, secondRevision, err)
	}
}

func TestGatePropagatesPolicyInfrastructureOutage(t *testing.T) {
	e, _, req := setup()
	e.ACL.Store = unavailablePolicyStore{}
	if _, err := e.Evaluate(context.Background(), req); err != ErrUnavailable {
		t.Fatalf("policy outage was treated as explicit denial: %v", err)
	}
}

func TestDeniedGateVersionTracksLoadedPolicyRevision(t *testing.T) {
	e, _, req := setup()
	deniedPolicy := func(revision int64) authz.Document {
		return authz.Document{Resource: req.Resource, Revision: revision, Policies: map[string]authz.Policy{
			"execute": {Mode: "protected", Rule: &authz.Rule{Kind: "role", Value: "administrator"}},
		}}
	}
	e.ACL.Store = policyStore{deniedPolicy(1)}
	first, err := e.Evaluate(context.Background(), req)
	if err != nil || first.ReasonCode != "policyDenied" || !strings.Contains(first.ProviderRevision, ":policy:1") {
		t.Fatalf("first policy denial=%+v err=%v", first, err)
	}
	e.ACL.Store = policyStore{deniedPolicy(2)}
	second, err := e.Evaluate(context.Background(), req)
	if err != nil || second.ReasonCode != "policyDenied" || !strings.Contains(second.ProviderRevision, ":policy:2") || second.ProviderRevision == first.ProviderRevision {
		t.Fatalf("edited denied policy reused gate version: first=%q second=%+v err=%v", first.ProviderRevision, second, err)
	}
}

func TestGateDistinguishesRejectedIdentityFromProviderOutage(t *testing.T) {
	e, _, req := setup()
	e.ACL.Provider = failingFactsProvider{authz.ErrDenied}
	if decision, err := e.Evaluate(context.Background(), req); decision.Effect != "" || err != authz.ErrDenied {
		t.Fatalf("second identity rejection became policy decision: %+v %v", decision, err)
	}
	e.ACL.Provider = failingFactsProvider{errors.New("identity network outage")}
	if decision, err := e.Evaluate(context.Background(), req); decision.Effect != "" || err != ErrUnavailable {
		t.Fatalf("second identity outage became policy denial: %+v %v", decision, err)
	}
	e.Principals = failingPrincipal{authz.ErrDenied}
	if _, err := e.Evaluate(context.Background(), req); err != authz.ErrDenied {
		t.Fatalf("rejected identity=%v", err)
	}
	e.Principals = failingPrincipal{authz.ErrUnavailable}
	if _, err := e.Evaluate(context.Background(), req); err != ErrUnavailable {
		t.Fatalf("identity outage=%v", err)
	}
	e.Principals = failingPrincipal{errors.New("network failed")}
	if _, err := e.Evaluate(context.Background(), req); err != ErrUnavailable {
		t.Fatalf("unknown provider failure=%v", err)
	}
	e.Principals = &principalSource{Principal{Facts: authz.Facts{Subject: "alice", Issuer: "issuer", Tenant: "other", ValidUntil: time.Now().Add(time.Minute)}, AccountID: "another-account", IdentityRevision: "revision"}}
	if _, err := e.Evaluate(context.Background(), req); err != authz.ErrDenied {
		t.Fatalf("cross-tenant identity=%v", err)
	}
}

func TestGateRejectsNamedPermissionAndScopeDrift(t *testing.T) {
	e, principal, req := setup()
	changed := &principalSource{value: principal.value}
	changed.value.Facts.EntityPermissions = []authz.EntityPermission{{Type: "customer", ID: "123", Permissions: []string{"write"}}}
	e.ACL.Provider = changed
	if _, err := e.Evaluate(context.Background(), req); err != ErrUnavailable {
		t.Fatalf("permission drift=%v", err)
	}
	changed.value.Facts.EntityPermissions = nil
	changed.value.Facts.GrantedScopes = []string{"export:run"}
	if _, err := e.Evaluate(context.Background(), req); err != ErrUnavailable {
		t.Fatalf("scope drift=%v", err)
	}
}

func TestProviderErrorsDoNotBecomeOptionalDenialDecisions(t *testing.T) {
	e, _, req := setup()
	e.Entities = entityProviderError{authz.ErrDenied}
	if decision, err := e.Evaluate(context.Background(), req); decision.Effect != "" || err != authz.ErrDenied {
		t.Fatalf("entity identity rejection became decision: %+v %v", decision, err)
	}
	e.Entities = entityProviderError{errors.New("entity outage")}
	if decision, err := e.Evaluate(context.Background(), req); decision.Effect != "" || err != ErrUnavailable {
		t.Fatalf("entity outage became decision: %+v %v", decision, err)
	}
	e.ACL.Store = policyStore{authz.Document{Resource: req.Resource, Revision: 1, Policies: map[string]authz.Policy{"execute": {Mode: "protected", Rule: &authz.Rule{Kind: "role", Value: "reader"}}}}}
	e.Requirements = requirementStore{RequirementsDocument{Revision: "r1", Requirements: Requirements{SchemaVersion: 1, Entitlement: &EntitlementRequirement{ProviderRef: "configured", Key: "premium", Scope: "account"}}}}
	req.Selected = nil
	e.Entitlements = map[string]EntitlementProvider{"configured": entitlementProviderError{authz.ErrDenied}}
	if decision, err := e.Evaluate(context.Background(), req); decision.Effect != "" || err != authz.ErrDenied {
		t.Fatalf("entitlement identity rejection became decision: %+v %v", decision, err)
	}
}

func TestMissingGateDocumentDenies(t *testing.T) {
	e, _, req := setup()
	e.Requirements = requirementStore{RequirementsDocument{Requirements: Requirements{SchemaVersion: 1}}}
	if _, err := e.Evaluate(context.Background(), req); err != authz.ErrDenied {
		t.Fatalf("missing requirements=%v", err)
	}
}

func TestExactSelectionAndProviderBindings(t *testing.T) {
	e, _, req := setup()
	entityLease := time.Now().Add(15 * time.Second)
	e.Entities = entityProvider(func(r ProviderRequest) Decision {
		d := providerAllow(r)
		d.Effect = "deny"
		d.ValidUntil = entityLease
		return d
	})
	if d, err := e.Evaluate(context.Background(), req); err != nil || d.ReasonCode != "entityDenied" || !d.ValidUntil.Equal(entityLease) || !strings.Contains(d.ProviderRevision, ":entity:p1") {
		t.Fatalf("entity denial lost provider binding: %+v %v", d, err)
	}
	req.Selected = nil
	if d, err := e.Evaluate(context.Background(), req); err != nil || d.ReasonCode != "needsEntity" {
		t.Fatalf("missing entity: %+v %v", d, err)
	}
	req.Selected = []authz.Entity{{Type: "customer", ID: "123"}, {Type: "customer", ID: "999"}}
	if d, err := e.Evaluate(context.Background(), req); err != nil || d.ReasonCode != "entityDenied" {
		t.Fatalf("partial coverage: %+v %v", d, err)
	}
	req.Selected = []authz.Entity{{Type: "customer", ID: "123"}}
	e.Entities = entityProvider(func(r ProviderRequest) Decision { d := providerAllow(r); d.EntitySelectionHash = "wrong"; return d })
	if _, err := e.Evaluate(context.Background(), req); err != ErrUnavailable {
		t.Fatalf("selection mismatch: %v", err)
	}
	e.Entities = entityProvider(func(r ProviderRequest) Decision { d := providerAllow(r); d.RequirementKey = "write"; return d })
	if _, err := e.Evaluate(context.Background(), req); err != ErrUnavailable {
		t.Fatalf("permission mismatch: %v", err)
	}
}

func TestPublicACLStillRequiresAccountFeatureAndRole(t *testing.T) {
	e, p, req := setup()
	req.Resource.Tenant = "*"
	e.ACL.Store = policyStore{authz.Document{Resource: req.Resource, Revision: 1, Policies: map[string]authz.Policy{"execute": {Mode: "public"}}}}
	e.Requirements = requirementStore{RequirementsDocument{Revision: "requirements-2", Requirements: Requirements{SchemaVersion: 1, RequiredExposures: []string{"feature"}, AllowedRoles: []string{"reader"}}}}
	req.Selected = nil
	p.value.Facts.Exposures = nil
	if d, err := e.Evaluate(context.Background(), req); err != nil || d.ReasonCode != "featureDisabled" {
		t.Fatalf("public feature gate: %+v %v", d, err)
	}
	p.value.Facts.Exposures = []string{"feature"}
	p.value.Facts.Roles = []string{"other"}
	if d, err := e.Evaluate(context.Background(), req); err != nil || d.ReasonCode != "roleDenied" {
		t.Fatalf("public role gate: %+v %v", d, err)
	}
	p.value.Facts.Roles = []string{"reader"}
	if d, err := e.Evaluate(context.Background(), req); err != nil || d.Effect != "allow" {
		t.Fatalf("public gate allow: %+v %v", d, err)
	}
}

func TestEntitlementProviderIsOptionalAndLeaseBound(t *testing.T) {
	e, _, req := setup()
	req.Selected = nil
	e.ACL.Store = policyStore{authz.Document{Resource: req.Resource, Revision: 1, Policies: map[string]authz.Policy{"execute": {Mode: "protected", Rule: &authz.Rule{Kind: "role", Value: "reader"}}}}}
	e.Requirements = requirementStore{RequirementsDocument{Revision: "requirements-3", Requirements: Requirements{SchemaVersion: 1}}}
	e.Entitlements = map[string]EntitlementProvider{"configured": entitlementProvider(func(ProviderRequest) Decision {
		t.Fatal("ungated resource called entitlement provider")
		return Decision{}
	})}
	if d, err := e.Evaluate(context.Background(), req); err != nil || d.Effect != "allow" {
		t.Fatalf("ordinary resource: %+v %v", d, err)
	}
	e.Requirements = requirementStore{RequirementsDocument{Revision: "requirements-4", Requirements: Requirements{SchemaVersion: 1, Entitlement: &EntitlementRequirement{ProviderRef: "configured", Key: "premium", Scope: "account"}}}}
	lease := time.Now().Add(20 * time.Second)
	e.Entitlements = map[string]EntitlementProvider{"configured": entitlementProvider(func(r ProviderRequest) Decision { d := providerAllow(r); d.ValidUntil = lease; return d })}
	if d, err := e.Evaluate(context.Background(), req); err != nil || d.Effect != "allow" || !d.ValidUntil.Equal(lease) {
		t.Fatalf("entitlement lease: %+v %v", d, err)
	}
	e.Requirements = requirementStore{RequirementsDocument{Revision: "requirements-5", Requirements: Requirements{SchemaVersion: 1, Entitlement: &EntitlementRequirement{ProviderRef: "unknown", Key: "premium", Scope: "account"}}}}
	if _, err := e.Evaluate(context.Background(), req); err != ErrUnavailable {
		t.Fatalf("unknown providerRef: %v", err)
	}
	e.Requirements = requirementStore{RequirementsDocument{Revision: "requirements-4", Requirements: Requirements{SchemaVersion: 1, Entitlement: &EntitlementRequirement{ProviderRef: "configured", Key: "premium", Scope: "account"}}}}
	e.Entitlements = map[string]EntitlementProvider{"configured": entitlementProvider(func(r ProviderRequest) Decision {
		d := providerAllow(r)
		d.Effect = "deny"
		d.ReasonCode = "subscriptionExpired"
		d.ValidUntil = lease
		return d
	})}
	if d, err := e.Evaluate(context.Background(), req); err != nil || d.ReasonCode != "subscriptionExpired" || !d.ValidUntil.Equal(lease) || !strings.Contains(d.ProviderRevision, ":entitlement:p1") {
		t.Fatalf("expired entitlement: %+v %v", d, err)
	}
	e.Entitlements = map[string]EntitlementProvider{"configured": entitlementProvider(func(r ProviderRequest) Decision { d := providerAllow(r); d.AccountID = "other-account"; return d })}
	if _, err := e.Evaluate(context.Background(), req); err != ErrUnavailable {
		t.Fatalf("cross-account entitlement result: %v", err)
	}
}

func TestGateAdministrationRequiresManagementAndCAS(t *testing.T) {
	_, source, request := setup()
	role := &authz.Rule{Kind: "role", Value: "administrator"}
	acl := &authz.Service{Provider: source, Store: policyStore{authz.Document{Resource: request.Resource, Revision: 1, Policies: map[string]authz.Policy{"viewAccess": {Mode: "protected", Rule: role}, "manageAccess": {Mode: "protected", Rule: role}}}}}
	store := &writableRequirements{doc: RequirementsDocument{Revision: "r1", Requirements: Requirements{SchemaVersion: 1}}}
	admin := &Administration{ACL: acl, Store: store, Writer: store}
	if _, err := admin.Replace(context.Background(), request.Resource, "execute", "r1", Requirements{SchemaVersion: 1, RequiredExposures: []string{"feature"}}); err != authz.ErrDenied || store.writes != 0 {
		t.Fatalf("non-admin edit: %v writes=%d", err, store.writes)
	}
	source.value.Facts.Roles = []string{"administrator"}
	if _, err := admin.Replace(context.Background(), request.Resource, "execute", "stale", Requirements{SchemaVersion: 1}); err != authz.ErrConflict || store.writes != 0 {
		t.Fatalf("stale edit: %v writes=%d", err, store.writes)
	}
	updated, err := admin.Replace(context.Background(), request.Resource, "execute", "r1", Requirements{SchemaVersion: 1, RequiredExposures: []string{"feature"}})
	if err != nil || updated.Revision != "r2" || store.writes != 1 {
		t.Fatalf("authorized edit: %+v %v writes=%d", updated, err, store.writes)
	}
	updated.Requirements.RequiredExposures[0] = "forged"
	if store.doc.Requirements.RequiredExposures[0] != "feature" {
		t.Fatal("returned document aliases persisted requirements")
	}
}

func TestGateAdministrationSeparatesDeniedFromUnavailable(t *testing.T) {
	_, source, request := setup()
	source.value.Facts.Roles = []string{"administrator"}
	role := &authz.Rule{Kind: "role", Value: "administrator"}
	acl := &authz.Service{Provider: source, Store: policyStore{authz.Document{Resource: request.Resource, Revision: 1, Policies: map[string]authz.Policy{"viewAccess": {Mode: "protected", Rule: role}, "manageAccess": {Mode: "protected", Rule: role}}}}}
	admin := &Administration{ACL: acl, Store: failingRequirementStore{err: errors.New("database unavailable")}, Writer: &writableRequirements{}}
	if _, err := admin.Get(context.Background(), request.Resource, "execute"); err != ErrUnavailable {
		t.Fatalf("get outage=%v", err)
	}
	if _, err := admin.Replace(context.Background(), request.Resource, "execute", "r1", Requirements{SchemaVersion: 1}); err != ErrUnavailable {
		t.Fatalf("replace outage=%v", err)
	}
	admin.Store = failingRequirementStore{err: authz.ErrDenied}
	if _, err := admin.Get(context.Background(), request.Resource, "execute"); err != authz.ErrDenied {
		t.Fatalf("missing gate=%v", err)
	}
	admin.Store = requirementStore{RequirementsDocument{Revision: "r1", Requirements: Requirements{SchemaVersion: 1}}}
	acl.Store = unavailablePolicyStore{}
	if _, err := admin.Context(context.Background(), request.Resource, "execute"); err != ErrUnavailable {
		t.Fatalf("policy outage=%v", err)
	}
}

func TestGateEditorContextUsesServerAuthorityAndChoices(t *testing.T) {
	_, source, request := setup()
	acl := &authz.Service{Provider: source, Store: policyStore{authz.Document{Resource: request.Resource, Revision: 1, Policies: map[string]authz.Policy{
		"viewAccess":   {Mode: "protected", Rule: &authz.Rule{Kind: "role", Value: "reader"}},
		"manageAccess": {Mode: "protected", Rule: &authz.Rule{Kind: "role", Value: "administrator"}},
	}}}}
	store := &writableRequirements{doc: RequirementsDocument{Revision: "r1", Requirements: Requirements{SchemaVersion: 1}}}
	admin := &Administration{ACL: acl, Store: store, Writer: store, Choices: editorChoicesFunc(func(context.Context, authz.Resource, string) (EditorChoices, error) {
		return EditorChoices{Roles: []Choice{{ID: "reader", Label: "Reader"}}}, nil
	})}
	contextValue, err := admin.Context(context.Background(), request.Resource, "execute")
	if err != nil || contextValue.CanManage || contextValue.Choices.Roles[0].ID != "reader" {
		t.Fatalf("reader editor context: %+v %v", contextValue, err)
	}
	contextValue.Choices.Roles[0].ID = "forged"
	source.value.Facts.Roles = []string{"reader", "administrator"}
	contextValue, err = admin.Context(context.Background(), request.Resource, "execute")
	if err != nil || !contextValue.CanManage || contextValue.Choices.Roles[0].ID != "reader" {
		t.Fatalf("manager editor context: %+v %v", contextValue, err)
	}
	admin.Writer = nil
	contextValue, err = admin.Context(context.Background(), request.Resource, "execute")
	if err != nil || contextValue.CanManage {
		t.Fatalf("read-only store advertised edit access: %+v %v", contextValue, err)
	}
}
