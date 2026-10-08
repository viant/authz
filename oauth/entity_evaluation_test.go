package oauth

import (
	"context"
	"encoding/json"
	"github.com/viant/authz"
	"github.com/viant/authz/gating"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

type evaluationPrincipal struct{ value gating.Principal }

func (p *evaluationPrincipal) ResolvePrincipal(context.Context) (gating.Principal, error) {
	return p.value, nil
}
func TestEntityEvaluationCacheAndBinding(t *testing.T) {
	p := &evaluationPrincipal{gating.Principal{AccountID: "21", IdentityRevision: "r1", Facts: authz.Facts{Issuer: "issuer", Subject: "alice", Tenant: "owner", ValidUntil: time.Now().Add(time.Minute)}}}
	var calls atomic.Int32
	malformed := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != "POST" || r.Header.Get("Authorization") == "" {
			t.Error("missing bound request")
		}
		var in struct {
			EntityType  string
			EntityIDs   []int64
			Permissions []string
		}
		if json.NewDecoder(r.Body).Decode(&in) != nil {
			t.Error("bad input")
		}
		results := []entityEvaluationResult{}
		for _, id := range in.EntityIDs {
			results = append(results, entityEvaluationResult{EntityID: id, Permissions: map[string]bool{in.Permissions[0]: id == 1}})
		}
		if malformed {
			results = results[:0]
		}
		json.NewEncoder(w).Encode(map[string]any{"status": "ok", "info": entityEvaluationInfo{Issuer: "issuer", Subject: "alice", UserID: 7, AccountID: 21, EntityType: in.EntityType, AuthorityRevision: "v1", EvaluatedAt: time.Now().Add(-time.Second), ValidUntil: time.Now().Add(5 * time.Minute), Results: results}})
	}))
	defer server.Close()
	client, err := NewEntityEvaluationClient(EntityEvaluationConfig{URL: server.URL, Principals: p})
	if err != nil {
		t.Fatal(err)
	}
	selected, hash, _ := gating.CanonicalSelection([]authz.Entity{{Type: "advertiser", ID: "1"}, {Type: "advertiser", ID: "2"}})
	req := gating.ProviderRequest{SchemaVersion: 1, RequestID: "one", Issuer: "issuer", Subject: "alice", TenantID: "owner", AccountID: "21", ResourceKind: "report", ResourceID: "test", Action: "execute", RequirementsRevision: "g1", ProviderRef: "entity", RequirementKey: "read", EntitySelection: selected, EntitySelectionHash: hash}
	ctx := WithBearer(context.Background(), "credential-one")
	for i := 0; i < 2; i++ {
		d, err := client.CheckEntityPermission(ctx, req)
		if err != nil || d.Effect != "deny" || d.ValidUntil.After(p.value.Facts.ValidUntil) {
			t.Fatalf("decision=%+v err=%v", d, err)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("cache misses=%d", calls.Load())
	}
	if _, err := client.CheckEntityPermission(WithBearer(context.Background(), "credential-two"), req); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 2 {
		t.Fatal("credential cache not isolated")
	}
	malformed = true
	if _, err := client.CheckEntityPermission(WithBearer(context.Background(), "credential-three"), req); err == nil {
		t.Fatal("partial matrix accepted")
	}
	if _, err := client.CheckEntityPermission(WithBearer(context.Background(), "credential-three"), req); err == nil {
		t.Fatal("partial matrix accepted on retry")
	}
	if calls.Load() != 4 {
		t.Fatal("malformed result cached")
	}
	req.AccountID = "22"
	if _, err := client.CheckEntityPermission(ctx, req); err == nil {
		t.Fatal("cross-account request accepted")
	}
}
func TestEntityEvaluationRejectsExpiredSourceLease(t *testing.T) {
	p := &evaluationPrincipal{gating.Principal{AccountID: "21", IdentityRevision: "r1", Facts: authz.Facts{Issuer: "issuer", Subject: "alice", Tenant: "owner", ValidUntil: time.Now().Add(time.Minute)}}}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"status": "ok", "info": entityEvaluationInfo{Issuer: "issuer", Subject: "alice", UserID: 7, AccountID: 21, EntityType: "advertiser", AuthorityRevision: "v1", EvaluatedAt: time.Now().Add(-10 * time.Minute), ValidUntil: time.Now().Add(time.Minute), Results: []entityEvaluationResult{{EntityID: 1, Permissions: map[string]bool{"read": true}}}}})
	}))
	defer server.Close()
	c, _ := NewEntityEvaluationClient(EntityEvaluationConfig{URL: server.URL, Principals: p})
	selected, hash, _ := gating.CanonicalSelection([]authz.Entity{{Type: "advertiser", ID: "1"}})
	_, err := c.CheckEntityPermission(WithBearer(context.Background(), "token"), gating.ProviderRequest{RequestID: "one", Issuer: "issuer", Subject: "alice", TenantID: "owner", AccountID: "21", RequirementKey: "read", EntitySelection: selected, EntitySelectionHash: hash})
	if err == nil {
		t.Fatal("source cache lease restarted")
	}
}

func (p *evaluationPrincipal) Resolve(context.Context) (authz.Facts, error) {
	return p.value.Facts, nil
}

func TestSelectedEntityAuthorityComposesWithBoundedACLAndGate(t *testing.T) {
	p := &evaluationPrincipal{gating.Principal{AccountID: "21", IdentityRevision: "r1", Facts: authz.Facts{Issuer: "issuer", Subject: "alice", Tenant: "owner", Roles: []string{"reader"}, ValidUntil: time.Now().Add(time.Minute)}}}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			EntityType  string
			EntityIDs   []int64
			Permissions []string
		}
		json.NewDecoder(r.Body).Decode(&in)
		results := []entityEvaluationResult{}
		for _, id := range in.EntityIDs {
			results = append(results, entityEvaluationResult{EntityID: id, Permissions: map[string]bool{in.Permissions[0]: id == 1}})
		}
		json.NewEncoder(w).Encode(map[string]any{"status": "ok", "info": entityEvaluationInfo{Issuer: "issuer", Subject: "alice", UserID: 7, AccountID: 21, EntityType: in.EntityType, AuthorityRevision: "v1", EvaluatedAt: time.Now(), ValidUntil: time.Now().Add(time.Minute), Results: results}})
	}))
	defer server.Close()
	c, err := NewEntityEvaluationClient(EntityEvaluationConfig{URL: server.URL, Principals: p})
	if err != nil {
		t.Fatal(err)
	}
	resource := authz.Resource{Kind: "report", ID: "report", Version: "1", Tenant: "owner"}
	store, err := authz.NewStaticStore([]authz.Document{{Resource: resource, Revision: 1, Policies: map[string]authz.Policy{"execute": {Mode: "protected", Rule: &authz.Rule{Kind: "role", Value: "reader"}, EntityType: "advertiser"}}}})
	if err != nil {
		t.Fatal(err)
	}
	acl := &authz.Service{Store: store, Provider: p, SelectedScopes: &EntityEvaluationScopeProvider{Client: c, Permission: func(authz.Request, authz.Document) (string, error) { return "read", nil }}}
	requirements, err := gating.NewStaticStore([]gating.Binding{{Resource: resource, Action: "execute", Document: gating.RequirementsDocument{Revision: "g1", Requirements: gating.Requirements{SchemaVersion: 1, Entity: &gating.EntityRequirement{Type: "advertiser", Permission: "read", SelectionMode: "multiple"}}}}})
	if err != nil {
		t.Fatal(err)
	}
	gates := gating.Evaluator{ACL: acl, Principals: p, Requirements: requirements, Entities: c}
	ctx := WithBearer(context.Background(), "verified-token")
	request := gating.Request{RequestID: "one", Resource: resource, Action: "execute", Selected: []authz.Entity{{Type: "advertiser", ID: "1"}}}
	decision, err := gates.Evaluate(ctx, request)
	if err != nil || decision.Effect != "allow" {
		t.Fatalf("selected allow without expanded facts: %+v %v", decision, err)
	}
	request.Selected = append(request.Selected, authz.Entity{Type: "advertiser", ID: "2"})
	decision, err = gates.Evaluate(ctx, request)
	if err == nil && decision.Effect == "allow" {
		t.Fatal("partially authorized selection broadened")
	}
	if len(p.value.Facts.Entities) != 0 || len(p.value.Facts.EntityPermissions) != 0 {
		t.Fatal("selected authority polluted global facts")
	}
	p.value.Facts.Roles = nil
	request.Selected = request.Selected[:1]
	decision, err = gates.Evaluate(ctx, request)
	if err == nil && decision.Effect == "allow" {
		t.Fatal("entity decision bypassed resource ACL")
	}
}
