package oauth

import (
	"context"
	"testing"

	"github.com/viant/authz"
)

func TestCapabilityPermissionMappingDoesNotTurnEntityGrantGlobal(t *testing.T) {
	bindings := []CapabilityPermissionBinding{{EntityType: "customer", Capability: "read", Permission: "CUSTOMER_VIEWER"}, {EntityType: "customer", Capability: "write", Permission: "CUSTOMER_OWNER"}}
	resolver, err := NewCapabilityPermissionResolver(bindings)
	if err != nil {
		t.Fatal(err)
	}
	facts := authz.Facts{Subject: "alice", Issuer: "issuer", Tenant: "tenant", EntityPermissions: []authz.EntityPermission{{Type: "customer", ID: "42", Permissions: []string{"CUSTOMER_VIEWER"}}}}
	for _, test := range []struct {
		entity     authz.Entity
		capability string
		allowed    bool
	}{
		{authz.Entity{Type: "customer", ID: "42"}, "read", true},
		{authz.Entity{Type: "customer", ID: "42"}, "write", false},
		{authz.Entity{Type: "customer", ID: "43"}, "read", false},
		{authz.Entity{Type: "other", ID: "42"}, "read", false},
		{authz.Entity{Type: "customer", ID: "42"}, "manageSettings", false},
	} {
		allowed, err := resolver(context.Background(), facts, test.entity, test.capability)
		if err != nil || allowed != test.allowed {
			t.Errorf("%+v %s: allowed=%v err=%v", test.entity, test.capability, allowed, err)
		}
	}
	if _, err := NewCapabilityPermissionResolver([]CapabilityPermissionBinding{bindings[0], bindings[0]}); err == nil {
		t.Fatal("duplicate capability binding accepted")
	}
}
