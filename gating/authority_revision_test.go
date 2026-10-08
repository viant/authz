package gating

import (
	"github.com/viant/authz"
	"testing"
)

func TestSamePrincipalAuthorityIncludesOpaqueFactRevision(t *testing.T) {
	before := Principal{AccountID: "account", IdentityRevision: "identity", Facts: authz.Facts{Subject: "actor", Issuer: "issuer", Tenant: "tenant", AuthorityRevision: "context-1"}}
	after := before
	after.Facts.AuthorityRevision = "context-2"
	if SamePrincipalAuthority(before, after) {
		t.Fatal("changed verified context accepted with stable identity fields")
	}
}
