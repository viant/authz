package oauth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"github.com/golang-jwt/jwt/v5"
	"github.com/viant/authz"
	"github.com/viant/authz/gating"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type authorityHTTPFixture struct {
	mu                             sync.Mutex
	key                            *rsa.PrivateKey
	server                         *httptest.Server
	info                           map[string]any
	userinfoCalls, evaluationCalls atomic.Int32
	duringEvaluation               func()
	overrideEvaluation             func(map[string]any)
	redirect                       string
}

func newAuthorityHTTPFixture(t *testing.T) *authorityHTTPFixture {
	t.Helper()
	key, e := rsa.GenerateKey(rand.Reader, 2048)
	if e != nil {
		t.Fatal(e)
	}
	f := &authorityHTTPFixture{key: key}
	f.server = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.server.Close)
	f.info = map[string]any{"subject": "reader", "userId": 7, "accountId": 21, "roles": []string{"editor"}, "features": []string{"authoring"}, "entityPermissions": []any{map[string]any{"type": "document", "id": 101, "permissions": []string{"read", "write"}}}, "businessModelContext": 1, "authorityRevision": "profile-1", "evaluatedAt": time.Now().Add(-time.Second).UTC().Format(time.RFC3339Nano), "validUntil": time.Now().Add(time.Minute).UTC().Format(time.RFC3339Nano)}
	return f
}
func (f *authorityHTTPFixture) serve(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/jwks" {
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]any{"kty": "RSA", "kid": "key", "alg": "RS256", "use": "sig", "n": base64.RawURLEncoding.EncodeToString(f.key.PublicKey.N.Bytes()), "e": "AQAB"}}})
		return
	}
	if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
		w.WriteHeader(401)
		return
	}
	if r.Header.Get("Cache-Control") != "no-cache" {
		w.WriteHeader(400)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.URL.Path == "/userinfo" {
		f.userinfoCalls.Add(1)
		if f.redirect != "" {
			http.Redirect(w, r, f.redirect, 302)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "ok", "info": f.info})
		return
	}
	if r.URL.Path == "/evaluate" {
		f.evaluationCalls.Add(1)
		var body map[string]json.RawMessage
		if json.NewDecoder(r.Body).Decode(&body) != nil {
			w.WriteHeader(400)
			return
		}
		var permissions []string
		_ = json.Unmarshal(body["permissions"], &permissions)
		if len(permissions) != 1 {
			w.WriteHeader(400)
			return
		}
		info := map[string]any{"issuer": f.server.URL, "subject": "reader", "userId": 7, "accountId": 21, "authorityRevision": "decision-1", "evaluatedAt": time.Now().Add(-time.Millisecond).UTC().Format(time.RFC3339Nano), "validUntil": time.Now().Add(time.Minute).UTC().Format(time.RFC3339Nano)}
		if body["scope"] != nil {
			info["scope"] = "account"
			var kind string
			_ = json.Unmarshal(body["resourceType"], &kind)
			info["resourceType"] = kind
			info["permissions"] = map[string]bool{permissions[0]: true}
		} else {
			var kind string
			var ids []int
			_ = json.Unmarshal(body["entityType"], &kind)
			_ = json.Unmarshal(body["entityIds"], &ids)
			info["entityType"] = kind
			results := []any{}
			for _, id := range ids {
				results = append(results, map[string]any{"entityId": id, "permissions": map[string]bool{permissions[0]: true}})
			}
			info["results"] = results
		}
		if f.overrideEvaluation != nil {
			f.overrideEvaluation(info)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "ok", "info": info})
		if f.duringEvaluation != nil {
			f.duringEvaluation()
		}
		return
	}
	w.WriteHeader(404)
}
func (f *authorityHTTPFixture) token(t *testing.T, account int, issuer, audience string) string {
	t.Helper()
	claims := jwt.MapClaims{"iss": issuer, "aud": audience, "sub": "reader", "user_id": 7, "account_id": account, "iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix()}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = "key"
	raw, e := token.SignedString(f.key)
	if e != nil {
		t.Fatal(e)
	}
	return raw
}
func (f *authorityHTTPFixture) config() HTTPIdentityConfig {
	return HTTPIdentityConfig{Kind: "oidc-userinfo", Issuer: f.server.URL, Audience: "configured-client", Algorithms: []string{"RS256"}, JWKSURL: f.server.URL + "/jwks", JWKSRefreshInterval: "1ms", UserInfoURL: f.server.URL + "/userinfo", FactLease: "30s", TenantByAccount: map[string]string{"21": "workspace"}, Mapping: HTTPIdentityMapping{Subject: "info.subject", UserID: "info.userId", AccountID: "info.accountId", JWTUserID: "user_id", JWTAccountID: "account_id", Roles: "info.roles", Exposures: "info.features", EntityPermissions: "info.entityPermissions", Status: "status", StatusValue: "ok", AuthorityRevision: "info.authorityRevision", EvaluatedAt: "info.evaluatedAt", ValidUntil: "info.validUntil", RequireSourceLease: true, AccountProjection: map[string]string{"displayMode": "info.businessModelContext"}}}
}
func (f *authorityHTTPFixture) evaluation() HTTPEvaluationConfig {
	return HTTPEvaluationConfig{URL: f.server.URL + "/evaluate", CacheTTL: "30s", EntitlementProviderRef: "configured-account", Entitlements: map[string]HTTPAccountRequirement{"document.create": {ResourceType: "document", Permission: "create"}}, Mapping: HTTPEvaluationMapping{RequestEntityType: "entityType", RequestEntityIDs: "entityIds", RequestPermissions: "permissions", RequestScope: "scope", RequestResourceType: "resourceType", IntegerEntityIDs: true, Status: "status", StatusValue: "ok", Issuer: "info.issuer", Subject: "info.subject", UserID: "info.userId", AccountID: "info.accountId", EntityType: "info.entityType", Results: "info.results", ResultEntityID: "entityId", ResultPermissions: "permissions", Scope: "info.scope", ResourceType: "info.resourceType", Permissions: "info.permissions", AuthorityRevision: "info.authorityRevision", EvaluatedAt: "info.evaluatedAt", ValidUntil: "info.validUntil"}}
}
func authorityRequest(p gating.Principal, selected []authz.Entity) gating.ProviderRequest {
	selected, hash, _ := gating.CanonicalSelection(selected)
	return gating.ProviderRequest{SchemaVersion: 1, RequestID: "operation", Subject: p.Facts.Subject, Issuer: p.Facts.Issuer, TenantID: p.Facts.Tenant, AccountID: p.AccountID, ResourceKind: "window", ResourceID: "editor", ResourceVersion: "1", Action: "consume", RequirementsRevision: "rules-1", RequirementKey: "read", ProviderRef: "entity", EntitySelection: selected, EntitySelectionHash: hash}
}
func TestHTTPProvidersDeployedShapeAndNativeIdentityNoUserInfo(t *testing.T) {
	f := newAuthorityHTTPFixture(t)
	evaluation := f.evaluation()
	providers, e := NewHTTPProviders(context.Background(), f.config(), &evaluation)
	if e != nil {
		t.Fatal(e)
	}
	ctx := WithBearer(context.Background(), f.token(t, 21, f.server.URL, "configured-client"))
	for i := 0; i < 76; i++ {
		p, e := providers.NativeWindowIdentity(ctx)
		if e != nil || p.AccountID != "21" || len(p.Facts.Roles) != 0 || p.Facts.EntityGroups != nil {
			t.Fatal("native identity must be verified but not entitlement authority")
		}
	}
	if f.userinfoCalls.Load() != 0 {
		t.Fatal("native static delivery fetched userinfo")
	}
	p, e := providers.Identity.ResolvePrincipal(ctx)
	if e != nil || p.AccountID != "21" || p.Facts.Tenant != "workspace" || len(p.Facts.Roles) != 1 {
		t.Fatal(e)
	}
	projection, e := providers.AccountProjection(ctx, p.Facts, "21")
	if e != nil || projection["id"] != "21" || projection["displayMode"].(json.Number).String() != "1" {
		t.Fatal("verified projection failed", e)
	}
	decision, e := providers.EntityPermissions.CheckEntityPermission(ctx, authorityRequest(p, []authz.Entity{{Type: "document", ID: "101"}}))
	if e != nil || decision.Effect != "allow" || decision.ValidUntil.After(p.Facts.ValidUntil) {
		t.Fatal("bound entity response failed", e)
	}
	request := authorityRequest(p, nil)
	request.ProviderRef = "configured-account"
	request.RequirementKey = "document.create"
	decision, e = providers.Entitlements["configured-account"].CheckEntitlement(ctx, request)
	if e != nil || decision.Effect != "allow" {
		t.Fatal("configured entitlement mapping failed", e)
	}
}
func TestHTTPIdentityRejectsTokenAndProfileMismatches(t *testing.T) {
	for _, mode := range []string{"issuer", "audience", "account", "userinfo-subject", "userinfo-account", "userinfo-user", "expired-source", "future-source", "roles-malformed", "ambiguous-grant"} {
		t.Run(mode, func(t *testing.T) {
			f := newAuthorityHTTPFixture(t)
			c := f.config()
			issuer, audience, account := f.server.URL, "configured-client", 21
			switch mode {
			case "issuer":
				issuer = "https://wrong.example"
			case "audience":
				audience = "other-client"
			case "account":
				account = 22
			case "userinfo-subject":
				f.info["subject"] = "another"
			case "userinfo-account":
				f.info["accountId"] = 22
			case "userinfo-user":
				f.info["userId"] = 8
			case "expired-source":
				f.info["evaluatedAt"] = time.Now().Add(-time.Minute).Format(time.RFC3339Nano)
				f.info["validUntil"] = time.Now().Add(-time.Second).Format(time.RFC3339Nano)
			case "future-source":
				f.info["evaluatedAt"] = time.Now().Add(time.Second).Format(time.RFC3339Nano)
			case "roles-malformed":
				f.info["roles"] = []string{"editor", "editor"}
			case "ambiguous-grant":
				f.info["entityPermissions"] = []any{map[string]any{"type": "document", "id": 101, "ID": 102, "permissions": []string{"read"}}}
			}
			p, e := NewHTTPProviders(context.Background(), c, nil)
			if e != nil {
				t.Fatal(e)
			}
			_, e = p.Identity.ResolvePrincipal(WithBearer(context.Background(), f.token(t, account, issuer, audience)))
			if e == nil {
				t.Fatal("unproven authority accepted")
			}
			if (mode == "issuer" || mode == "audience") && f.userinfoCalls.Load() != 0 {
				t.Fatal("unverified credential forwarded")
			}
		})
	}
}
func TestHTTPPureReadScopeReusesOnlyWithinDecisionAndDetectsRevocation(t *testing.T) {
	f := newAuthorityHTTPFixture(t)
	providers, e := NewHTTPProviders(context.Background(), f.config(), nil)
	if e != nil {
		t.Fatal(e)
	}
	ctx := WithBearer(context.Background(), f.token(t, 21, f.server.URL, "configured-client"))
	scoped, finish, e := providers.MetadataScope.BeginMetadataRead(ctx)
	if e != nil {
		t.Fatal(e)
	}
	for i := 0; i < 10; i++ {
		if _, e = providers.Identity.ResolvePrincipal(scoped); e != nil {
			t.Fatal(e)
		}
	}
	if f.userinfoCalls.Load() != 1 {
		t.Fatal("read scope not coalesced")
	}
	f.mu.Lock()
	f.info["roles"] = []string{}
	f.mu.Unlock()
	if finish() == nil {
		t.Fatal("role revocation escaped release")
	}
	if _, e = providers.Identity.ResolvePrincipal(scoped); e == nil {
		t.Fatal("closed snapshot reusable")
	}
	if _, e = providers.Identity.ResolvePrincipal(providers.MetadataScope.WithoutMetadataRead(scoped)); e != nil {
		t.Fatal(e)
	}
}
func TestHTTPEvaluationRejectsSelectionAndPostCallDrift(t *testing.T) {
	for _, mode := range []string{"wrong-account", "wrong-subject", "extra-result", "missing-permission", "expired", "changed-role"} {
		t.Run(mode, func(t *testing.T) {
			f := newAuthorityHTTPFixture(t)
			evaluation := f.evaluation()
			providers, e := NewHTTPProviders(context.Background(), f.config(), &evaluation)
			if e != nil {
				t.Fatal(e)
			}
			ctx := WithBearer(context.Background(), f.token(t, 21, f.server.URL, "configured-client"))
			p, e := providers.Identity.ResolvePrincipal(ctx)
			if e != nil {
				t.Fatal(e)
			}
			f.mu.Lock()
			if mode == "changed-role" {
				f.duringEvaluation = func() { f.info["roles"] = []string{} }
			} else {
				f.overrideEvaluation = func(info map[string]any) {
					switch mode {
					case "wrong-account":
						info["accountId"] = 22
					case "wrong-subject":
						info["subject"] = "other"
					case "extra-result":
						info["results"] = []any{map[string]any{"entityId": 101, "permissions": map[string]bool{"read": true}}, map[string]any{"entityId": 102, "permissions": map[string]bool{"read": true}}}
					case "missing-permission":
						info["results"] = []any{map[string]any{"entityId": 101, "permissions": map[string]bool{"other": true}}}
					case "expired":
						info["evaluatedAt"] = time.Now().Add(-time.Minute).Format(time.RFC3339Nano)
						info["validUntil"] = time.Now().Add(-time.Second).Format(time.RFC3339Nano)
					}
				}
			}
			f.mu.Unlock()
			if _, e = providers.EntityPermissions.CheckEntityPermission(ctx, authorityRequest(p, []authz.Entity{{Type: "document", ID: "101"}})); e == nil {
				t.Fatal("mismatched/stale authority accepted")
			}
		})
	}
}
func TestHTTPProviderBlocksCredentialRedirect(t *testing.T) {
	f := newAuthorityHTTPFixture(t)
	var leaked atomic.Int32
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked.Add(1); w.WriteHeader(200) }))
	defer receiver.Close()
	f.redirect = receiver.URL
	p, e := NewHTTPProviders(context.Background(), f.config(), nil)
	if e != nil {
		t.Fatal(e)
	}
	_, e = p.Identity.Resolve(WithBearer(context.Background(), f.token(t, 21, f.server.URL, "configured-client")))
	if e == nil || leaked.Load() != 0 {
		t.Fatal("redirect forwarded credential")
	}
}

func TestHTTPEvaluationRejectsMixedAccountAndEntityEnvelopes(t *testing.T) {
	for _, mode := range []string{"account-with-results", "entity-with-account-scope", "entity-with-account-permissions"} {
		t.Run(mode, func(t *testing.T) {
			f := newAuthorityHTTPFixture(t)
			evaluation := f.evaluation()
			providers, err := NewHTTPProviders(context.Background(), f.config(), &evaluation)
			if err != nil {
				t.Fatal(err)
			}
			ctx := WithBearer(context.Background(), f.token(t, 21, f.server.URL, "configured-client"))
			principal, err := providers.Identity.ResolvePrincipal(ctx)
			if err != nil {
				t.Fatal(err)
			}
			f.mu.Lock()
			f.overrideEvaluation = func(info map[string]any) {
				switch mode {
				case "account-with-results":
					info["results"] = []any{}
				case "entity-with-account-scope":
					info["scope"] = "account"
				case "entity-with-account-permissions":
					info["permissions"] = map[string]bool{"read": true}
				}
			}
			f.mu.Unlock()
			if mode == "account-with-results" {
				request := authorityRequest(principal, nil)
				request.ProviderRef = "configured-account"
				request.RequirementKey = "document.create"
				_, err = providers.Entitlements["configured-account"].CheckEntitlement(ctx, request)
			} else {
				_, err = providers.EntityPermissions.CheckEntityPermission(ctx, authorityRequest(principal, []authz.Entity{{Type: "document", ID: "101"}}))
			}
			if err == nil {
				t.Fatal("mixed account/entity envelope accepted")
			}
		})
	}
}
