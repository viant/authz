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
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	jwtlib "github.com/golang-jwt/jwt/v5"
	"github.com/viant/authz"
	"github.com/viant/authz/datly/schema"
	policystore "github.com/viant/authz/datly/store/sql"
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
	services := &Services{Authorization: &authz.Service{Store: store, Provider: facts}, Policies: &authz.Administration{Store: store, Provider: facts, EditorRoles: []string{"policy_admin"}}}
	base, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	registrations, err := Registrations(ctx, base, services, codecs)
	if err != nil {
		t.Fatal(err)
	}
	if len(registrations) != 4 {
		t.Fatalf("registered %d SDK endpoints", len(registrations))
	}
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
	sign := func(subject string, roles []string) string {
		t.Helper()
		token, err := jwtlib.NewWithClaims(jwtlib.SigningMethodRS256, oauth.Claims{RegisteredClaims: jwtlib.RegisteredClaims{Issuer: "authz-test", Audience: []string{"authz"}, Subject: subject, ExpiresAt: jwtlib.NewNumericDate(time.Now().Add(time.Minute))}, Tenant: "one", Roles: roles, EntityGroups: authz.EntityGroups{"publisher": {"127"}}}).SignedString(key)
		if err != nil {
			t.Fatal(err)
		}
		return token
	}
	admin := sign("admin", []string{"policy_admin"})
	reader := sign("reader", []string{"reader"})
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
	resource := authz.Resource{Kind: "component", ID: "forecasting", Version: "1", Tenant: "one"}
	document := authz.Document{Resource: resource, Policies: map[string]authz.Policy{"execute": {Mode: "protected", Rule: &authz.Rule{Kind: "role", Value: "reader"}, EntityType: "publisher"}}}
	status, body := call(httpServer.URL+"/v1/authz/sdk/policies.create", reader, map[string]any{"document": document, "roles": []string{"policy_admin"}})
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
	status, body = call(httpServer.URL+"/v1/authz/sdk/authorization.check", reader, map[string]any{"resource": resource, "action": "execute"})
	if status != 200 || !bytes.Contains(body, []byte(`"127"`)) {
		t.Fatalf("scope check: %d %s", status, body)
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
	if status != 200 || !bytes.Contains(body, []byte("authz.sdk.policies.get")) {
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
