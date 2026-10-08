package authz

import (
	"encoding/json"
	"testing"
	"time"
)

func TestAuthorityRevisionPreservedAndComparedWithoutChangingGrants(t *testing.T) {
	facts := Facts{Subject: "actor", Issuer: "issuer", Tenant: "tenant", AuthorityRevision: "verified-context-1", ValidUntil: time.Now().Add(time.Minute)}
	raw, err := json.Marshal(facts)
	if err != nil {
		t.Fatal(err)
	}
	var restored Facts
	if err := json.Unmarshal(raw, &restored); err != nil || restored.AuthorityRevision != facts.AuthorityRevision {
		t.Fatal("opaque authority revision lost", err)
	}
	changed := facts
	changed.AuthorityRevision = "verified-context-2"
	if sameManagementFacts(facts, changed) {
		t.Fatal("same actor context drift accepted")
	}
}
