package oauth

import (
	"context"
	"testing"
	"time"

	"github.com/viant/authz"
	"github.com/viant/authz/gating"
)

type principalFixture struct{ principal gating.Principal }

func (p principalFixture) ResolvePrincipal(context.Context) (gating.Principal, error) {
	return p.principal, nil
}

func TestFactEntityPermissionProviderRequiresEveryExactPermission(t *testing.T) {
	selected, hash, err := gating.CanonicalSelection([]authz.Entity{{Type: "customer", ID: "9007199254740993"}, {Type: "customer", ID: "42"}})
	if err != nil {
		t.Fatal(err)
	}
	principal := gating.Principal{Facts: authz.Facts{Subject: "alice", Issuer: "issuer", Tenant: "tenant", ValidUntil: time.Now().Add(time.Minute), EntityPermissions: []authz.EntityPermission{{Type: "customer", ID: "42", Permissions: []string{"read"}}, {Type: "customer", ID: "9007199254740993", Permissions: []string{"write"}}}}, AccountID: "account", IdentityRevision: "identity-1"}
	provider := &FactEntityPermissionProvider{Principals: principalFixture{principal}}
	request := gating.ProviderRequest{SchemaVersion: 1, RequestID: "request", Subject: "alice", Issuer: "issuer", TenantID: "tenant", AccountID: "account", ResourceKind: "report", ResourceID: "orders", ResourceVersion: "1", Action: "execute", RequirementsRevision: "r1", RequirementKey: "read", ProviderRef: "entity", EntitySelection: selected, EntitySelectionHash: hash}
	decision, err := provider.CheckEntityPermission(context.Background(), request)
	if err != nil || decision.Effect != "deny" || decision.ReasonCode != "entityDenied" {
		t.Fatalf("partial coverage: %+v %v", decision, err)
	}
	principal.Facts.EntityPermissions[1].Permissions = []string{"read", "write"}
	provider.Principals = principalFixture{principal}
	decision, err = provider.CheckEntityPermission(context.Background(), request)
	if err != nil || decision.Effect != "allow" || decision.EntitySelectionHash != hash || decision.ProviderRevision != "identity-1" {
		t.Fatalf("exact allow: %+v %v", decision, err)
	}
	request.AccountID = "another-account"
	if _, err := provider.CheckEntityPermission(context.Background(), request); err != gating.ErrUnavailable {
		t.Fatalf("account replay: %v", err)
	}
	request.AccountID = "account"
	request.EntitySelectionHash = "forged"
	if _, err := provider.CheckEntityPermission(context.Background(), request); err != gating.ErrUnavailable {
		t.Fatalf("selection replay: %v", err)
	}
}
