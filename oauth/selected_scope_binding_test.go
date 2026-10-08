package oauth

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/viant/authz"
	"github.com/viant/authz/gating"
)

type opaqueAuthority struct{ principal gating.Principal }

func (p *opaqueAuthority) Resolve(context.Context) (authz.Facts, error) {
	return p.principal.Facts, nil
}
func (p *opaqueAuthority) ResolvePrincipal(context.Context) (gating.Principal, error) {
	return p.principal, nil
}
func (p *opaqueAuthority) Account(context.Context, authz.Facts) (string, error) {
	return p.principal.AccountID, nil
}
func (p *opaqueAuthority) AuthorityRevision(context.Context, authz.Facts, string) (string, time.Time, error) {
	return p.principal.IdentityRevision, p.principal.Facts.ValidUntil, nil
}

type selectedAuthority func(gating.ProviderRequest) gating.Decision

func (f selectedAuthority) CheckEntityPermission(_ context.Context, r gating.ProviderRequest) (gating.Decision, error) {
	return f(r), nil
}
func boundSelectedDecision(r gating.ProviderRequest) gating.Decision {
	return gating.Decision{SchemaVersion: 1, DecisionID: "test", RequestID: r.RequestID, Subject: r.Subject, Issuer: r.Issuer, TenantID: r.TenantID, AccountID: r.AccountID, ResourceKind: r.ResourceKind, ResourceID: r.ResourceID, ResourceVersion: r.ResourceVersion, Action: r.Action, RequirementsRevision: r.RequirementsRevision, EntitySelectionHash: r.EntitySelectionHash, RequirementKey: r.RequirementKey, ProviderRef: r.ProviderRef, ProviderRevision: "opaque-authority-revision", Effect: "allow", ValidUntil: time.Now().Add(time.Hour)}
}
func TestGenericSelectedScopeBindsOpaqueAuthorityAndEveryDecisionField(t *testing.T) {
	identity := &opaqueAuthority{gating.Principal{AccountID: "opaque-account/abc", IdentityRevision: "session:r1", Facts: authz.Facts{Subject: "subject:abc", Issuer: "issuer", Tenant: "policy-team", ValidUntil: time.Now().Add(time.Minute)}}}
	selected := []authz.Entity{{Type: "document", ID: "opaque/doc:xyz"}}
	req := authz.Request{Resource: authz.Resource{Kind: "report", ID: "test", Version: "working", Tenant: "policy-team"}, Action: "execute", Selection: &selected}
	provider := EntityEvaluationScopeProvider{Principals: identity, Permission: func(authz.Request, authz.Document) (string, error) { return "inspect", nil }}
	for _, field := range []string{"none", "subject", "account", "resource", "revision", "selection", "permission", "provider", "expiry", "effect", "changed authority"} {
		t.Run(field, func(t *testing.T) {
			original := identity.principal
			defer func() { identity.principal = original }()
			provider.Client = selectedAuthority(func(r gating.ProviderRequest) gating.Decision {
				d := boundSelectedDecision(r)
				switch field {
				case "subject":
					d.Subject = "other"
				case "account":
					d.AccountID = "other"
				case "resource":
					d.ResourceID = "other"
				case "revision":
					d.RequirementsRevision = "other"
				case "selection":
					d.EntitySelectionHash = "other"
				case "permission":
					d.RequirementKey = "other"
				case "provider":
					d.ProviderRef = "other"
				case "expiry":
					d.ValidUntil = time.Now().Add(-time.Second)
				case "effect":
					d.Effect = "deny"
				case "changed authority":
					identity.principal.IdentityRevision = "session:r2"
				}
				return d
			})
			result, err := provider.ResolveSelectedScope(context.Background(), req, authz.Document{Revision: 1}, original.Facts)
			if field == "none" {
				if err != nil || len(result.Entities) != 1 || result.Entities[0].ID != selected[0].ID || result.ValidUntil.After(original.Facts.ValidUntil) {
					t.Fatalf("generic bound result: %+v %v", result, err)
				}
			} else if err == nil {
				t.Fatalf("accepted mismatched authority %s", field)
			}
		})
	}
}
func TestStaticAuthorizationRequiresExplicitAuthorityAndNamespace(t *testing.T) {
	identity := &opaqueAuthority{}
	for _, config := range []StaticAuthorizationConfig{{}, {Identity: identity}, {AllowsTenant: func(string) bool { return true }}} {
		if _, err := NewStaticAuthorization(config); err == nil {
			t.Fatal("implicit authority accepted")
		}
	}
	resource := authz.Resource{Kind: "report", ID: "r", Version: "1", Tenant: "team"}
	config := StaticAuthorizationConfig{Identity: identity, AllowsTenant: func(tenant string) bool { return tenant == "team" }, Policies: []authz.Document{{Resource: resource, Revision: 1, Policies: map[string]authz.Policy{"execute": {Mode: "public"}}}}}
	if _, err := NewStaticAuthorization(config); err != nil {
		t.Fatal(err)
	}
	config.Policies[0].Resource.Tenant = "unmapped"
	if _, err := NewStaticAuthorization(config); err == nil {
		t.Fatal("unmapped policy namespace accepted")
	}
}

func TestGenericSignedAuthoritySupportsStaticGateWithOpaqueAccount(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	identity, err := New(Config{Issuer: "generic-issuer", Audience: "host", Algorithms: []string{"EdDSA"}, Keyfunc: func(*jwt.Token) (any, error) { return public, nil }})
	if err != nil {
		t.Fatal(err)
	}
	resource := authz.Resource{Kind: "window", ID: "opaque-window", Version: "working", Tenant: "team"}
	bundle, err := NewStaticAuthorization(StaticAuthorizationConfig{Identity: identity, AllowsTenant: func(tenant string) bool { return tenant == "team" }, Policies: []authz.Document{{Resource: resource, Revision: 1, Policies: map[string]authz.Policy{"execute": {Mode: "protected", Rule: &authz.Rule{Kind: "role", Value: "reader"}}}}}, Requirements: []gating.Binding{{Resource: resource, Action: "execute", Document: gating.RequirementsDocument{Revision: "r1", Requirements: gating.Requirements{SchemaVersion: 1}}}}})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := jwt.NewWithClaims(jwt.SigningMethodEdDSA, Claims{RegisteredClaims: jwt.RegisteredClaims{Issuer: "generic-issuer", Audience: []string{"host"}, Subject: "opaque-person", ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Minute))}, Tenant: "team", AccountID: "opaque-account", Roles: []string{"reader"}}).SignedString(private)
	if err != nil {
		t.Fatal(err)
	}
	ctx := WithBearer(context.Background(), raw)
	decision, err := bundle.Gates.Evaluate(ctx, gating.Request{RequestID: "r1", Resource: resource, Action: "execute"})
	if err != nil || decision.Effect != "allow" || decision.AccountID != "opaque-account" {
		t.Fatalf("generic signed gate: %+v %v", decision, err)
	}
	facts, err := identity.Resolve(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if account, err := identity.Account(ctx, facts); err != nil || account != "opaque-account" {
		t.Fatalf("generic account=%s %v", account, err)
	}
	facts.Subject = "different"
	if _, err := identity.Account(ctx, facts); err == nil {
		t.Fatal("different facts accepted")
	}
}
