package oauth

import (
	"context"
	"testing"
	"time"

	"github.com/viant/authz"
)

func TestEntityRoleProjectionUsesExactVerifiedPermissionOnly(t *testing.T) {
	resolve, err := NewEntityRoleResolver([]EntityRoleBinding{{EntityType: "customer", Permission: "OWNER", Role: "entityOwner"}, {EntityType: "customer", Permission: "EDITOR", Role: "entityEditor"}})
	if err != nil {
		t.Fatal(err)
	}
	facts := authz.Facts{Subject: "alice", Issuer: "issuer", Tenant: "tenant", Roles: []string{"globalAdmin"}, ValidUntil: time.Now().Add(time.Minute), EntityPermissions: []authz.EntityPermission{{Type: "customer", ID: "42", Permissions: []string{"OWNER", "EDITOR", "unmapped"}}, {Type: "customer", ID: "43", Permissions: []string{"OWNER"}}, {Type: "agency", ID: "42", Permissions: []string{"OWNER"}}}}
	roles, err := resolve(context.Background(), facts, authz.Entity{Type: "customer", ID: "42"})
	if err != nil || len(roles) != 2 || roles[0] != "entityEditor" || roles[1] != "entityOwner" {
		t.Fatalf("exact roles=%v err=%v", roles, err)
	}
	roles, err = resolve(context.Background(), facts, authz.Entity{Type: "customer", ID: "44"})
	if err != nil || len(roles) != 0 {
		t.Fatalf("other entity roles=%v err=%v", roles, err)
	}
	if _, err := NewEntityRoleResolver([]EntityRoleBinding{{EntityType: "customer", Permission: "OWNER", Role: "owner"}, {EntityType: "customer", Permission: "OWNER", Role: "other"}}); err == nil {
		t.Fatal("duplicate permission mapping accepted")
	}
}
