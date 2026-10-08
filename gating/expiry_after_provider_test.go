package gating

import (
	"context"
	"testing"
	"time"
)

func TestProviderLatencyCannotReturnExpiredAllow(t *testing.T) {
	for _, kind := range []string{"entity", "entitlement"} {
		t.Run(kind, func(t *testing.T) {
			evaluator, principal, request := setup()
			now := time.Now()
			principal.value.Facts.ValidUntil = now.Add(time.Second)
			evaluator.Now = func() time.Time { return now }
			delayed := func(r ProviderRequest) Decision {
				now = now.Add(2 * time.Second)
				d := providerAllow(r)
				d.ValidUntil = now.Add(time.Minute)
				return d
			}
			if kind == "entity" {
				evaluator.Entities = entityProvider(delayed)
			} else {
				doc := evaluator.Requirements.(requirementStore).doc
				doc.Requirements.Entity = nil
				doc.Requirements.Entitlement = &EntitlementRequirement{ProviderRef: "subscription", Key: "active", Scope: "account"}
				evaluator.Requirements = requirementStore{doc}
				evaluator.Entitlements = map[string]EntitlementProvider{"subscription": entitlementProvider(delayed)}
			}
			decision, err := evaluator.Evaluate(context.Background(), request)
			if err == nil || decision.Effect == "allow" {
				t.Fatalf("expired authority returned allow: %+v %v", decision, err)
			}
		})
	}
}
