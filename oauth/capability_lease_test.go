package oauth

import (
	"context"
	"github.com/viant/authz"
	"testing"
	"time"
)

func TestInjectedCapabilityCannotOutliveSourceOrIdentity(t *testing.T) {
	facts := authz.Facts{Subject: "opaque-person", Issuer: "issuer", Tenant: "team", ValidUntil: time.Now().Add(time.Minute)}
	sourceUntil := time.Now().Add(time.Hour)
	resolver, err := NewLeasedCapabilityPermissionResolver([]CapabilityPermissionBinding{{EntityType: "document", Capability: "view", Permission: "inspect"}}, func(_ context.Context, _ authz.Facts, _ authz.Entity, permission string) (bool, time.Time, error) {
		if permission != "inspect" {
			t.Fatal("capability was not mapped to explicit permission")
		}
		return true, sourceUntil, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	entity := authz.Entity{Type: "document", ID: "opaque:doc"}
	allowed, until, err := resolver(context.Background(), facts, entity, "view")
	if err != nil || !allowed || !until.Equal(facts.ValidUntil) {
		t.Fatalf("identity lease not retained: %v %v %v", allowed, until, err)
	}
	sourceUntil = time.Now().Add(10 * time.Second)
	allowed, until, err = resolver(context.Background(), facts, entity, "view")
	if err != nil || !allowed || !until.Equal(sourceUntil) {
		t.Fatalf("source lease restarted: %v %v %v", allowed, until, err)
	}
	sourceUntil = time.Now().Add(-time.Second)
	if allowed, _, err := resolver(context.Background(), facts, entity, "view"); allowed || err != authz.ErrDenied {
		t.Fatalf("expired capability accepted: %v %v", allowed, err)
	}
}
