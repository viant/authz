package oauth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/viant/authz"
	"github.com/viant/authz/gating"
)

func TestStaticAuthorizationCombinesVerifiedIdPACLAndEntityGate(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	secondToken := ""
	aliceInfo := `{"status":"ok","info":{"subject":"alice","userId":7,"accountId":21,"roles":["reader"],"features":["FEATURE"],"entityPermissions":[{"type":"customer","id":"42","permissions":["read"]}]}}`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/jwks":
			_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{rsaJWK(key, "current")}})
		case "/userinfo":
			if secondToken != "" && r.Header.Get("Authorization") == "Bearer "+secondToken {
				_, _ = w.Write([]byte(`{"status":"ok","info":{"subject":"bob","userId":8,"accountId":22,"roles":["reader"],"features":[],"entityPermissions":[{"type":"customer","id":"42","permissions":["read"]}]}}`))
				return
			}
			_, _ = w.Write([]byte(aliceInfo))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	resource := authz.Resource{Kind: "window", ID: "orders", Version: "1", Tenant: "tenant"}
	config := StaticAuthorizationConfig{
		Identity:              AccountUserInfoConfig{Issuer: server.URL, Audience: "host", Algorithms: []string{"RS256"}, UserInfoURL: server.URL + "/userinfo", JWKSURL: server.URL + "/jwks", JWKSRefreshInterval: time.Minute, FactLease: time.Minute, TenantByAccount: map[int]string{21: "tenant"}},
		Policies:              []authz.Document{{Resource: resource, Revision: 1, Policies: map[string]authz.Policy{"execute": {Mode: "protected", Rule: &authz.Rule{Kind: "role", Value: "reader"}, EntityType: "customer"}}}},
		Requirements:          []gating.Binding{{Resource: resource, Action: "execute", Document: gating.RequirementsDocument{Revision: "r1", Requirements: gating.Requirements{SchemaVersion: 1, RequiredExposures: []string{"FEATURE"}, AllowedRoles: []string{"reader"}, Entity: &gating.EntityRequirement{Type: "customer", Permission: "read", SelectionParameter: "CustomerID", SelectionMode: "single"}}}}},
		CapabilityPermissions: []CapabilityPermissionBinding{{EntityType: "customer", Capability: "read", Permission: "read"}},
		EntityRoles:           []EntityRoleBinding{{EntityType: "customer", Permission: "read", Role: "entityReader"}},
	}
	bundle, err := NewStaticAuthorization(config)
	if err != nil {
		t.Fatal(err)
	}
	unreachable := config
	unreachable.Policies = append([]authz.Document(nil), config.Policies...)
	unreachable.Requirements = append([]gating.Binding(nil), config.Requirements...)
	unreachable.Policies[0].Resource.Tenant = "unmapped"
	unreachable.Requirements[0].Resource.Tenant = "unmapped"
	if _, err := NewStaticAuthorization(unreachable); err == nil {
		t.Fatal("policy namespace unreachable from IdP mapping passed startup")
	}
	claims := userInfoClaims{RegisteredClaims: jwt.RegisteredClaims{Issuer: server.URL, Audience: []string{"host"}, Subject: "alice", ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour))}, UserID: 7, AccountID: 21}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = "current"
	raw, err := token.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	request := gating.Request{RequestID: "request-1", Resource: resource, Action: "execute", Selected: []authz.Entity{{Type: "customer", ID: "42"}}}
	decision, err := bundle.Gates.Evaluate(WithBearer(context.Background(), raw), request)
	if err != nil || decision.Effect != "allow" || decision.AccountID != "21" || decision.TenantID != "tenant" || decision.ProviderRevision == "" {
		t.Fatalf("configured gate: %+v %v", decision, err)
	}
	facts, err := bundle.Identity.Resolve(WithBearer(context.Background(), raw))
	if err != nil {
		t.Fatal(err)
	}
	if allowed, err := bundle.EntityCapability(context.Background(), facts, authz.Entity{Type: "customer", ID: "42"}, "read"); err != nil || !allowed {
		t.Fatalf("mapped capability: %v %v", allowed, err)
	}
	if roles, err := bundle.EntityRoleProjection(context.Background(), facts, authz.Entity{Type: "customer", ID: "42"}); err != nil || len(roles) != 1 || roles[0] != "entityReader" {
		t.Fatalf("mapped entity roles=%v %v", roles, err)
	}
	firstPrincipal, err := bundle.Identity.ResolvePrincipal(WithBearer(context.Background(), raw))
	if err != nil {
		t.Fatal(err)
	}
	aliceInfo = `{"status":"ok","info":{"subject":"alice","userId":7,"accountId":21,"roles":["reader"],"features":[],"entityPermissions":[{"type":"customer","id":"42","permissions":["read"]}]}}`
	changedPrincipal, err := bundle.Identity.ResolvePrincipal(WithBearer(context.Background(), raw))
	if err != nil || changedPrincipal.IdentityRevision == firstPrincipal.IdentityRevision {
		t.Fatalf("same-token fact change retained identity revision: %+v %v", changedPrincipal, err)
	}
	changedDecision, err := bundle.Gates.Evaluate(WithBearer(context.Background(), raw), request)
	if err != nil || changedDecision.Effect != "deny" || changedDecision.ReasonCode != "featureDisabled" || changedDecision.ProviderRevision == decision.ProviderRevision {
		t.Fatalf("same-token feature revocation: %+v %v", changedDecision, err)
	}
	aliceInfo = `{"status":"ok","info":{"subject":"alice","userId":7,"accountId":21,"roles":["reader"],"features":["FEATURE"],"entityPermissions":[{"type":"customer","id":"42","permissions":["read"]}]}}`
	shared := config
	shared.Identity.TenantByAccount = nil
	shared.Identity.TenantForAllAccounts = "tenant"
	sharedBundle, err := NewStaticAuthorization(shared)
	if err != nil {
		t.Fatal(err)
	}
	secondClaims := userInfoClaims{RegisteredClaims: jwt.RegisteredClaims{Issuer: server.URL, Audience: []string{"host"}, Subject: "bob", ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour))}, UserID: 8, AccountID: 22}
	secondJWT := jwt.NewWithClaims(jwt.SigningMethodRS256, secondClaims)
	secondJWT.Header["kid"] = "current"
	secondToken, err = secondJWT.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	decision, err = sharedBundle.Gates.Evaluate(WithBearer(context.Background(), secondToken), request)
	if err != nil || decision.Effect != "deny" || decision.ReasonCode != "featureDisabled" || decision.AccountID != "22" || decision.TenantID != "tenant" {
		t.Fatalf("shared tenant crossed account feature: %+v %v", decision, err)
	}
	shared.Identity.TenantByAccount = map[int]string{21: "tenant"}
	if _, err := NewStaticAuthorization(shared); err == nil {
		t.Fatal("ambiguous account and shared tenant mappings accepted")
	}
	shared.Identity.TenantByAccount = nil
	shared.Identity.TenantForAllAccounts = "*"
	if _, err := NewStaticAuthorization(shared); err == nil {
		t.Fatal("wildcard shared tenant accepted")
	}
	request.Selected[0].ID = "43"
	decision, err = bundle.Gates.Evaluate(WithBearer(context.Background(), raw), request)
	if err != nil || decision.Effect != "deny" {
		t.Fatalf("ungranted entity: %+v %v", decision, err)
	}
	config.Requirements[0].Action = "missing"
	if _, err := NewStaticAuthorization(config); err == nil {
		t.Fatal("requirement without ACL policy accepted")
	}
}
