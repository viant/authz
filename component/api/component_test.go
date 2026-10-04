package api

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	jwtlib "github.com/golang-jwt/jwt/v5"
	"github.com/viant/authz"
	"github.com/viant/authz/component/schema"
	policystore "github.com/viant/authz/component/store/sql"
	"github.com/viant/authz/gating"
	"github.com/viant/authz/oauth"
	gateway "github.com/viant/datly/gateway/http"
	"github.com/viant/datly/mcp"
	mcpserver "github.com/viant/datly/mcp/server"
	druntime "github.com/viant/datly/runtime"
	nativeauth "github.com/viant/datly/runtime/auth"
	"github.com/viant/mcp-protocol/authorization"
	"github.com/viant/mcp-protocol/oauth2/meta"
	mcpschema "github.com/viant/mcp-protocol/schema"
	"github.com/viant/scy"
	"github.com/viant/scy/auth/jwt/verifier"
	_ "modernc.org/sqlite"
)

type testGatePrincipal struct{ provider authz.Provider }

func (p testGatePrincipal) ResolvePrincipal(ctx context.Context) (gating.Principal, error) {
	facts, err := p.provider.Resolve(ctx)
	if err != nil {
		return gating.Principal{}, err
	}
	return gating.Principal{Facts: facts, AccountID: "account-1", IdentityRevision: "test-identity"}, nil
}

type unavailableGateRequirements struct{}

func (unavailableGateRequirements) GetRequirements(context.Context, authz.Resource, string) (gating.RequirementsDocument, error) {
	return gating.RequirementsDocument{}, gating.ErrUnavailable
}

type unavailableAuthorizationFacts struct{}

func (unavailableAuthorizationFacts) Resolve(context.Context) (authz.Facts, error) {
	return authz.Facts{}, authz.ErrUnavailable
}

type unavailableCatalogStore struct{}

func (unavailableCatalogStore) Get(context.Context, authz.Resource) (authz.Document, error) {
	return authz.Document{}, errors.New("policy store unavailable")
}
func (unavailableCatalogStore) Replace(context.Context, authz.Document, int64, string) (authz.Document, error) {
	return authz.Document{}, authz.ErrDenied
}

type changingCatalogStore struct {
	next  authz.Store
	reads int
}

func (s *changingCatalogStore) Get(ctx context.Context, resource authz.Resource) (authz.Document, error) {
	doc, err := s.next.Get(ctx, resource)
	s.reads++
	if s.reads > 1 {
		doc.Revision++
	}
	return doc, err
}
func (s *changingCatalogStore) Replace(ctx context.Context, doc authz.Document, revision int64, actor string) (authz.Document, error) {
	return s.next.Replace(ctx, doc, revision, actor)
}

type switchingCatalogPrincipal struct {
	next  gating.PrincipalResolver
	reads int
}

func (p *switchingCatalogPrincipal) ResolvePrincipal(ctx context.Context) (gating.Principal, error) {
	principal, err := p.next.ResolvePrincipal(ctx)
	p.reads++
	if p.reads > 1 {
		principal.AccountID = "other-account"
	}
	return principal, err
}

type unavailableGatePrincipal struct{}

func (unavailableGatePrincipal) ResolvePrincipal(context.Context) (gating.Principal, error) {
	return gating.Principal{}, gating.ErrUnavailable
}

func TestSDKComponentsHTTPAndMCP(t *testing.T) {
	ctx := context.Background()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "authz.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	migration, _ := schema.New("sqlite")
	if err = migration.Up(ctx, db); err != nil {
		t.Fatal(err)
	}
	store := &policystore.Store{DB: db}
	defer store.Close(ctx)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	codecs, err := nativeauth.New(ctx, &nativeauth.Config{JWTValidator: &verifier.Config{RSA: []*scy.Resource{{URL: "authz-fixture", Data: pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: raw})}}}})
	if err != nil {
		t.Fatal(err)
	}
	facts, err := oauth.New(oauth.Config{Issuer: "authz-test", Audience: "authz", Algorithms: []string{"RS256"}, Keyfunc: func(*jwtlib.Token) (any, error) { return &key.PublicKey, nil }})
	if err != nil {
		t.Fatal(err)
	}
	resource := authz.Resource{Kind: "component", ID: "forecasting", Version: "1", Tenant: "one"}
	gateBindings := []gating.Binding{{Resource: resource, Action: "execute", Document: gating.RequirementsDocument{Revision: "r1", Requirements: gating.Requirements{SchemaVersion: 1, AllowedRoles: []string{"reader"}}}}}
	gateRoot := t.TempDir()
	gateStore, err := gating.NewFileStore(gateRoot, gateBindings)
	if err != nil {
		t.Fatal(err)
	}
	gateChoices, err := gating.NewStaticChoices([]gating.ChoiceBinding{{Resource: resource, Action: "execute", Choices: gating.EditorChoices{Roles: []gating.Choice{{ID: "reader", Label: "Reader"}}}}})
	if err != nil {
		t.Fatal(err)
	}
	aclService := &authz.Service{Store: store, Provider: facts}
	services := &Services{Authorization: aclService, Policies: &authz.Administration{Store: store, Provider: facts, EditorRoles: []string{"policy_admin"}}, Gates: &gating.Evaluator{ACL: aclService, Principals: testGatePrincipal{facts}, Requirements: gateStore}, Requirements: &gating.Administration{ACL: aclService, Store: gateStore, Writer: gateStore, Choices: gateChoices}, Catalog: CatalogFunc(func(context.Context) ([]CatalogEntry, error) {
		return []CatalogEntry{{Name: "Forecasting", Resource: resource, Actions: []string{"execute", "viewAccess"}, GateActions: []string{"execute"}}}, nil
	})}
	base, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	registrations, err := Registrations(ctx, base, services, codecs)
	if err != nil {
		t.Fatal(err)
	}
	if len(registrations) != 10 {
		t.Fatalf("registered %d SDK endpoints", len(registrations))
	}
	linked, err := LinkedRegistrations(services, codecs)
	if err != nil {
		t.Fatal(err)
	}
	if len(linked) != len(registrations) {
		t.Fatalf("linked registration count=%d, source count=%d", len(linked), len(registrations))
	}
	for index := range registrations {
		original, embedded := registrations[index].Component, linked[index].Component
		if original.Key != embedded.Key || len(original.Routes) != len(embedded.Routes) || original.Routes[0].Method != embedded.Routes[0].Method || original.Routes[0].Path != embedded.Routes[0].Path {
			t.Fatalf("linked route %d differs from source route: %+v %+v", index, original, embedded)
		}
	}
	registrations = linked // Exercise the source-free path through HTTP and MCP.
	runtime, err := druntime.NewRuntime(registrations, druntime.WithExposedPackages([]string{Package}, nil))
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Shutdown(ctx)
	handler, err := (gateway.Config{}).NewHandler(runtime, nil, "1")
	if err != nil {
		t.Fatal(err)
	}
	httpServer := httptest.NewServer(handler)
	defer httpServer.Close()
	mcpService, err := mcp.New(mcp.Config{Components: registrations, Invoker: runtime, Authorization: &authorization.Policy{Global: &authorization.Authorization{ProtectedResourceMetadata: &meta.ProtectedResourceMetadata{Resource: "http://authz.test/mcp"}}}})
	if err != nil {
		t.Fatal(err)
	}
	protocol, err := mcpserver.New(mcpserver.Config{Service: mcpService, Implementation: mcpschema.Implementation{Name: "authz-test", Version: "1"}, Transport: mcpserver.TransportConfig{Kind: mcpserver.TransportStreamable, Address: "127.0.0.1:0"}})
	if err != nil {
		t.Fatal(err)
	}
	mcpHTTP, err := protocol.HTTP()
	if err != nil {
		t.Fatal(err)
	}
	mcpHost := httptest.NewServer(mcpHTTP.Handler)
	defer mcpHost.Close()
	sign := func(subject string, roles []string, scope string) string {
		t.Helper()
		token, err := jwtlib.NewWithClaims(jwtlib.SigningMethodRS256, oauth.Claims{RegisteredClaims: jwtlib.RegisteredClaims{Issuer: "authz-test", Audience: []string{"authz"}, Subject: subject, ExpiresAt: jwtlib.NewNumericDate(time.Now().Add(time.Minute))}, Tenant: "one", Roles: roles, Scope: scope, EntityGroups: authz.EntityGroups{"publisher": {"127"}}}).SignedString(key)
		if err != nil {
			t.Fatal(err)
		}
		return token
	}
	admin := sign("admin", []string{"policy_admin"}, "")
	reader := sign("reader", []string{"reader"}, "forecast:execute")
	outsider := sign("outsider", []string{"unrelated"}, "")
	unscopedReader := sign("reader", []string{"reader"}, "")
	call := func(url, token string, input any) (int, []byte) {
		t.Helper()
		body, _ := json.Marshal(input)
		request, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Accept", "application/json, text/event-stream")
		if token != "" {
			request.Header.Set("Authorization", "Bearer "+token)
		}
		request.Header.Set("Mcp-Protocol-Version", mcpschema.LatestProtocolVersion)
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		out, err := io.ReadAll(response.Body)
		if err != nil {
			t.Fatal(err)
		}
		return response.StatusCode, out
	}
	status, body := call(httpServer.URL+"/v1/authz/sdk/policies.get", "", map[string]any{"resource": resource})
	if status != http.StatusUnauthorized {
		t.Fatalf("missing credential status=%d body=%s", status, body)
	}
	document := authz.Document{Resource: resource, Policies: map[string]authz.Policy{"execute": {Mode: "protected", Rule: &authz.Rule{Kind: "role", Value: "reader"}, RequiredScopes: []string{"forecast:execute"}, EntityType: "publisher"}, "viewAccess": {Mode: "protected", Rule: &authz.Rule{Kind: "any", Rules: []authz.Rule{{Kind: "role", Value: "reader"}, {Kind: "role", Value: "policy_admin"}}}}, "manageAccess": {Mode: "protected", Rule: &authz.Rule{Kind: "role", Value: "policy_admin"}}}}
	status, body = call(httpServer.URL+"/v1/authz/sdk/policies.create", reader, map[string]any{"document": document, "roles": []string{"policy_admin"}})
	if status != 403 {
		t.Fatalf("forged role created policy: %d %s", status, body)
	}
	status, body = call(httpServer.URL+"/v1/authz/sdk/policies.create", admin, map[string]any{"document": document})
	if status != 200 {
		t.Fatalf("create: %d %s", status, body)
	}
	status, body = call(httpServer.URL+"/v1/authz/sdk/policies.get", reader, map[string]any{"resource": resource})
	if status != 200 || !bytes.Contains(body, []byte(`"revision":1`)) {
		t.Fatalf("reader policy read: %d %s", status, body)
	}
	status, body = call(httpServer.URL+"/v1/authz/sdk/catalog.list", reader, map[string]any{})
	if status != 200 || !bytes.Contains(body, []byte(`"Forecasting"`)) || !bytes.Contains(body, []byte(`"gateActions":["execute"]`)) {
		t.Fatalf("reader catalog: %d %s", status, body)
	}
	status, body = call(httpServer.URL+"/v1/authz/sdk/catalog.list", outsider, map[string]any{})
	if status != 200 || bytes.Contains(body, []byte(`"Forecasting"`)) {
		t.Fatalf("outsider catalog: %d %s", status, body)
	}
	currentStore := services.Authorization.Store
	services.Authorization.Store = unavailableCatalogStore{}
	status, body = call(httpServer.URL+"/v1/authz/sdk/catalog.list", reader, map[string]any{})
	services.Authorization.Store = currentStore
	if status != 503 || bytes.Contains(body, []byte("Forecasting")) || bytes.Contains(body, []byte("policy store unavailable")) {
		t.Fatalf("catalog policy outage: %d %s", status, body)
	}
	services.Authorization.Store = &changingCatalogStore{next: currentStore}
	status, body = call(httpServer.URL+"/v1/authz/sdk/catalog.list", reader, map[string]any{})
	services.Authorization.Store = currentStore
	if status != 503 || bytes.Contains(body, []byte("Forecasting")) {
		t.Fatalf("catalog policy revision changed: %d %s", status, body)
	}
	currentCatalogPrincipal := services.Gates.Principals
	services.Gates.Principals = &switchingCatalogPrincipal{next: currentCatalogPrincipal}
	status, body = call(httpServer.URL+"/v1/authz/sdk/catalog.list", reader, map[string]any{})
	services.Gates.Principals = currentCatalogPrincipal
	if status != 503 || bytes.Contains(body, []byte("Forecasting")) {
		t.Fatalf("catalog account switch: %d %s", status, body)
	}
	status, body = call(httpServer.URL+"/v1/authz/sdk/policies.get", outsider, map[string]any{"resource": resource})
	if status != 403 {
		t.Fatalf("same-tenant outsider read protected policy: %d %s", status, body)
	}
	status, body = call(httpServer.URL+"/v1/authz/sdk/policies.context", reader, map[string]any{"resource": resource})
	if status != 200 || !bytes.Contains(body, []byte(`"canManage":false`)) || !bytes.Contains(body, []byte(`"reader"`)) {
		t.Fatalf("reader policy editor context: %d %s", status, body)
	}
	status, body = call(httpServer.URL+"/v1/authz/sdk/policies.context", admin, map[string]any{"resource": resource})
	if status != 200 || !bytes.Contains(body, []byte(`"canManage":true`)) {
		t.Fatalf("admin policy editor context: %d %s", status, body)
	}
	services.Policies.EditorRoles = []string{"reader"}
	status, body = call(httpServer.URL+"/v1/authz/sdk/policies.context", reader, map[string]any{"resource": resource})
	if status != 200 || !bytes.Contains(body, []byte(`"canManage":true`)) {
		t.Fatalf("editor role context did not match write rule: %d %s", status, body)
	}
	status, body = call(httpServer.URL+"/v1/authz/sdk/policies.context", admin, map[string]any{"resource": resource})
	if status != 200 || !bytes.Contains(body, []byte(`"canManage":false`)) {
		t.Fatalf("non-editor context inherited manageAccess: %d %s", status, body)
	}
	services.Policies.EditorRoles = []string{"policy_admin"}
	services.Policies.Management = aclService
	services.Policies.EditorRoles = []string{"reader"}
	status, body = call(httpServer.URL+"/v1/authz/sdk/policies.context", reader, map[string]any{"resource": resource})
	if status != 200 || !bytes.Contains(body, []byte(`"canManage":false`)) {
		t.Fatalf("manage-access context accepted editor role: %d %s", status, body)
	}
	status, body = call(httpServer.URL+"/v1/authz/sdk/policies.context", admin, map[string]any{"resource": resource})
	if status != 200 || !bytes.Contains(body, []byte(`"canManage":true`)) {
		t.Fatalf("manage-access context rejected policy manager: %d %s", status, body)
	}
	services.Policies.Management = nil
	services.Policies.EditorRoles = []string{"policy_admin"}
	currentPolicyProvider := services.Policies.Provider
	services.Policies.Provider = unavailableAuthorizationFacts{}
	status, body = call(httpServer.URL+"/v1/authz/sdk/policies.replace", admin, map[string]any{"document": document})
	services.Policies.Provider = currentPolicyProvider
	if status != 503 {
		t.Fatalf("policy management outage became denial: %d %s", status, body)
	}
	status, body = call(httpServer.URL+"/v1/authz/sdk/authorization.check", reader, map[string]any{"resource": resource, "action": "execute"})
	if status != 200 || !bytes.Contains(body, []byte(`"127"`)) {
		t.Fatalf("scope check: %d %s", status, body)
	}
	status, body = call(httpServer.URL+"/v1/authz/sdk/authorization.check", unscopedReader, map[string]any{"resource": resource, "action": "execute"})
	if status != 403 {
		t.Fatalf("unscoped token authorized: %d %s", status, body)
	}
	currentProvider := services.Authorization.Provider
	services.Authorization.Provider = unavailableAuthorizationFacts{}
	status, body = call(httpServer.URL+"/v1/authz/sdk/authorization.check", reader, map[string]any{"resource": resource, "action": "execute"})
	contextStatus, contextBody := call(httpServer.URL+"/v1/authz/sdk/policies.context", reader, map[string]any{"resource": resource})
	services.Authorization.Provider = currentProvider
	if status != 503 {
		t.Fatalf("identity outage became policy denial: %d %s", status, body)
	}
	if contextStatus != 503 {
		t.Fatalf("editor context outage became denial: %d %s", contextStatus, contextBody)
	}
	selected := []authz.Entity{{Type: "publisher", ID: "127"}}
	status, body = call(httpServer.URL+"/v1/authz/sdk/gates.check", reader, map[string]any{"resource": resource, "action": "execute", "selected": selected})
	if status != 200 || !bytes.Contains(body, []byte(`"effect":"allow"`)) || !bytes.Contains(body, []byte(`"accountId":"account-1"`)) || !bytes.Contains(body, []byte(`"requestId":"`)) {
		t.Fatalf("gate check: %d %s", status, body)
	}
	currentPrincipal := services.Gates.Principals
	services.Gates.Principals = unavailableGatePrincipal{}
	status, body = call(httpServer.URL+"/v1/authz/sdk/gates.check", reader, map[string]any{"resource": resource, "action": "execute", "selected": selected})
	services.Gates.Principals = currentPrincipal
	if status != 503 {
		t.Fatalf("gate principal outage became denial: %d %s", status, body)
	}
	status, body = call(httpServer.URL+"/v1/authz/sdk/gates.check", reader, map[string]any{"requestId": "forged", "resource": resource, "action": "execute"})
	if status != 200 || !bytes.Contains(body, []byte(`"reasonCode":"needsEntity"`)) || bytes.Contains(body, []byte(`"requestId":"forged"`)) {
		t.Fatalf("bounded gate with no entity: %d %s", status, body)
	}
	missingTenant, err := jwtlib.NewWithClaims(jwtlib.SigningMethodRS256, oauth.Claims{RegisteredClaims: jwtlib.RegisteredClaims{Issuer: "authz-test", Audience: []string{"authz"}, Subject: "reader", ExpiresAt: jwtlib.NewNumericDate(time.Now().Add(time.Minute))}, Roles: []string{"reader"}}).SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	status, body = call(httpServer.URL+"/v1/authz/sdk/authorization.check", missingTenant, map[string]any{"resource": resource, "action": "execute"})
	if status != 401 {
		t.Fatalf("rejected identity became policy denial: %d %s", status, body)
	}
	status, body = call(httpServer.URL+"/v1/authz/sdk/policies.context", missingTenant, map[string]any{"resource": resource})
	if status != 401 {
		t.Fatalf("rejected editor identity became policy denial: %d %s", status, body)
	}
	status, body = call(httpServer.URL+"/v1/authz/sdk/gates.check", missingTenant, map[string]any{"requestId": "invalid-identity", "resource": resource, "action": "execute", "selected": selected})
	if status != 403 {
		t.Fatalf("rejected identity returned outage: %d %s", status, body)
	}
	status, body = call(httpServer.URL+"/v1/authz/sdk/gates.check", admin, map[string]any{"requestId": "forged", "resource": resource, "action": "execute", "selected": selected, "roles": []string{"reader"}, "accountId": "account-1"})
	if status != 200 || !bytes.Contains(body, []byte(`"effect":"deny"`)) {
		t.Fatalf("caller assertions widened gate: %d %s", status, body)
	}
	currentRequirements := services.Gates.Requirements
	services.Gates.Requirements = unavailableGateRequirements{}
	status, body = call(httpServer.URL+"/v1/authz/sdk/gates.check", reader, map[string]any{"requestId": "outage", "resource": resource, "action": "execute", "selected": selected})
	services.Gates.Requirements = currentRequirements
	if status != 503 {
		t.Fatalf("gate store outage treated as denial: %d %s", status, body)
	}
	status, body = call(httpServer.URL+"/v1/authz/sdk/gates.get", reader, map[string]any{"resource": resource, "action": "execute"})
	if status != 200 || !bytes.Contains(body, []byte(`"revision":"r1"`)) {
		t.Fatalf("gate read: %d %s", status, body)
	}
	status, body = call(httpServer.URL+"/v1/authz/sdk/gates.context", reader, map[string]any{"resource": resource, "action": "execute"})
	if status != 200 || !bytes.Contains(body, []byte(`"canManage":false`)) || !bytes.Contains(body, []byte(`"id":"reader"`)) {
		t.Fatalf("reader gate editor context: %d %s", status, body)
	}
	status, body = call(httpServer.URL+"/v1/authz/sdk/gates.context", admin, map[string]any{"resource": resource, "action": "execute"})
	if status != 200 || !bytes.Contains(body, []byte(`"canManage":true`)) {
		t.Fatalf("admin gate editor context: %d %s", status, body)
	}
	status, body = call(httpServer.URL+"/v1/authz/sdk/gates.replace", reader, map[string]any{"resource": resource, "action": "execute", "expectedRevision": "r1", "requirements": map[string]any{"schemaVersion": 1}})
	if status != 403 {
		t.Fatalf("non-admin gate edit: %d %s", status, body)
	}
	status, body = call(httpServer.URL+"/v1/authz/sdk/gates.replace", admin, map[string]any{"resource": resource, "action": "execute", "expectedRevision": "r1", "requirements": map[string]any{"schemaVersion": 1}})
	var replacement GateDocumentOutput
	if status != 200 || json.Unmarshal(body, &replacement) != nil || replacement.Document.Revision == "" || replacement.Document.Revision == "r1" {
		t.Fatalf("admin gate edit: %d %s", status, body)
	}
	gateRevision := replacement.Document.Revision
	reopened, err := gating.NewFileStore(gateRoot, gateBindings)
	if err != nil {
		t.Fatal(err)
	}
	persisted, err := reopened.GetRequirements(ctx, resource, "execute")
	if err != nil || persisted.Revision != gateRevision {
		t.Fatalf("gate edit did not persist: %+v %v", persisted, err)
	}
	status, body = call(httpServer.URL+"/v1/authz/sdk/gates.replace", admin, map[string]any{"resource": resource, "action": "execute", "expectedRevision": "r1", "requirements": map[string]any{"schemaVersion": 1}})
	if status != 409 {
		t.Fatalf("stale gate edit: %d %s", status, body)
	}
	status, body = call(httpServer.URL+"/v1/authz/sdk/policies.get", "", map[string]any{"resource": resource})
	if status == 200 {
		t.Fatalf("anonymous policy read unexpectedly accepted: %s", body)
	}
	mcpRequest := func(method, name, token string, input any) (int, []byte) {
		t.Helper()
		payload, _ := json.Marshal(input)
		request, err := http.NewRequest(http.MethodPost, mcpHost.URL+"/mcp", bytes.NewReader(payload))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Accept", "application/json, text/event-stream")
		request.Header.Set("Authorization", "Bearer "+token)
		request.Header.Set("Mcp-Protocol-Version", mcpschema.LatestProtocolVersion)
		request.Header.Set("Mcp-Method", method)
		if name != "" {
			request.Header.Set("Mcp-Name", name)
		}
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		body, err := io.ReadAll(response.Body)
		if err != nil {
			t.Fatal(err)
		}
		return response.StatusCode, body
	}
	mcpCall := func(method, name string, args any, token string) (int, []byte) {
		params := map[string]any{}
		if name != "" {
			params = map[string]any{"name": name, "arguments": args}
		}
		// Protocol routing headers are required by the selected native MCP transport.
		params["_meta"] = map[string]any{"io.modelcontextprotocol/protocolVersion": mcpschema.LatestProtocolVersion, "io.modelcontextprotocol/clientCapabilities": map[string]any{}}
		return mcpRequest(method, name, token, map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
	}
	status, body = mcpCall("tools/list", "", nil, reader)
	if status != 200 || !bytes.Contains(body, []byte("authz.sdk.policies.get")) || !bytes.Contains(body, []byte("authz.sdk.policies.context")) || !bytes.Contains(body, []byte("authz.sdk.gates.check")) || !bytes.Contains(body, []byte("authz.sdk.gates.context")) || !bytes.Contains(body, []byte("authz.sdk.gates.replace")) {
		t.Fatalf("MCP SDK discovery: %d %s", status, body)
	}
	status, body = mcpCall("tools/call", "authz.sdk.policies.get", map[string]any{"resource": resource}, reader)
	if status != 200 || bytes.Contains(body, []byte(`"isError":true`)) || !bytes.Contains(body, []byte(`"revision":1`)) {
		t.Fatalf("MCP read: %d %s", status, body)
	}
	status, body = mcpCall("tools/call", "authz.sdk.authorization.check", map[string]any{"resource": resource, "action": "execute"}, reader)
	if status != 200 || bytes.Contains(body, []byte(`"isError":true`)) || !bytes.Contains(body, []byte("127")) {
		t.Fatalf("MCP scope: %d %s", status, body)
	}
	status, body = mcpCall("tools/call", "authz.sdk.gates.get", map[string]any{"resource": resource, "action": "execute"}, reader)
	if status != 200 || bytes.Contains(body, []byte(`"isError":true`)) || !bytes.Contains(body, []byte(gateRevision)) {
		t.Fatalf("MCP gate read: %d %s", status, body)
	}
	status, body = mcpCall("tools/call", "authz.sdk.gates.replace", map[string]any{"resource": resource, "action": "execute", "expectedRevision": gateRevision, "requirements": map[string]any{"schemaVersion": 1, "requiredExposures": []string{"FEATURE"}}}, reader)
	if status != 200 || !bytes.Contains(body, []byte(`"isError":true`)) {
		t.Fatalf("non-admin MCP gate edit: %d %s", status, body)
	}
	status, body = mcpCall("tools/call", "authz.sdk.gates.replace", map[string]any{"resource": resource, "action": "execute", "expectedRevision": gateRevision, "requirements": map[string]any{"schemaVersion": 1, "requiredExposures": []string{"FEATURE"}}}, admin)
	if status != 200 || bytes.Contains(body, []byte(`"isError":true`)) {
		t.Fatalf("admin MCP gate edit: %d %s", status, body)
	}
	persisted, err = reopened.GetRequirements(ctx, resource, "execute")
	if err != nil || persisted.Revision == gateRevision || len(persisted.Requirements.RequiredExposures) != 1 || persisted.Requirements.RequiredExposures[0] != "FEATURE" {
		t.Fatalf("MCP gate edit did not persist: %+v %v", persisted, err)
	}
	entries, err := os.ReadDir(gateRoot)
	if err != nil || len(entries) != 1 {
		t.Fatalf("gate history files=%d err=%v", len(entries), err)
	}
	auditRaw, err := os.ReadFile(filepath.Join(gateRoot, entries[0].Name()))
	if err != nil {
		t.Fatal(err)
	}
	var audit struct {
		History []struct {
			Actor string `json:"actor"`
		} `json:"history"`
	}
	if err := json.Unmarshal(auditRaw, &audit); err != nil || len(audit.History) != 3 || audit.History[1].Actor != "admin" || audit.History[2].Actor != "admin" {
		t.Fatalf("verified gate actors=%+v err=%v", audit.History, err)
	}
	document.Revision = 1
	status, body = mcpCall("tools/call", "authz.sdk.policies.replace", map[string]any{"document": document}, reader)
	if status != 200 || !bytes.Contains(body, []byte(`"isError":true`)) {
		t.Fatalf("non-admin MCP replace: %d %s", status, body)
	}
	status, body = mcpCall("tools/call", "authz.sdk.policies.replace", map[string]any{"document": document}, admin)
	if status != 200 || bytes.Contains(body, []byte(`"isError":true`)) || !bytes.Contains(body, []byte(`"revision":2`)) {
		t.Fatalf("admin MCP replace: %d %s", status, body)
	}
	status, body = call(httpServer.URL+"/v1/authz/sdk/policies.replace", admin, map[string]any{"document": document})
	if status != 409 {
		t.Fatalf("stale replace: %d %s", status, body)
	}
}
