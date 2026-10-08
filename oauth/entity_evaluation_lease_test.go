package oauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/viant/authz"
	"github.com/viant/authz/gating"
)

func TestCapabilityPermissionRetainsShorterEntityAuthorityLease(t *testing.T) {
	principal := &evaluationPrincipal{gating.Principal{AccountID: "21", IdentityRevision: "identity", Facts: authz.Facts{Issuer: "issuer", Subject: "alice", Tenant: "tenant", ValidUntil: time.Now().Add(5 * time.Minute)}}}
	expiry := time.Now().UTC().Add(time.Minute)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"status": "ok", "info": entityEvaluationInfo{Issuer: "issuer", Subject: "alice", UserID: 7, AccountID: 21, EntityType: "advertiser", AuthorityRevision: "revision", EvaluatedAt: time.Now().Add(-time.Second), ValidUntil: expiry, Results: []entityEvaluationResult{{EntityID: 1, Permissions: map[string]bool{"read": true}}}}})
	}))
	defer server.Close()
	client, err := NewEntityEvaluationClient(EntityEvaluationConfig{URL: server.URL, Principals: principal})
	if err != nil {
		t.Fatal(err)
	}
	resolver, err := client.CapabilityResolverWithLease([]CapabilityPermissionBinding{{EntityType: "advertiser", Capability: "read", Permission: "read"}})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		allow, lease, err := resolver(WithBearer(context.Background(), "credential"), principal.value.Facts, authz.Entity{Type: "advertiser", ID: "1"}, "read")
		if err != nil || !allow || !lease.Equal(expiry) {
			t.Fatalf("capability dropped source expiry: allow=%v lease=%v err=%v", allow, lease, err)
		}
	}
}
