package gating

import (
	"context"
	"testing"
)

func TestPreparedRequirementMembershipRemainsLiteralAndFresh(t *testing.T) {
	e, principal, request := setup()
	request.Selected = nil
	e.ACL = nil
	e.Requirements = requirementStore{RequirementsDocument{Revision: "membership-1", Requirements: Requirements{
		SchemaVersion: 1, AllowedRoles: []string{"other", "reader"}, RequiredExposures: []string{"feature", "second"},
	}}}
	principal.value.Facts.Roles = []string{"reader", "reader"}
	principal.value.Facts.Exposures = []string{"feature", "second", "second"}
	check := func(effect, reason string) {
		t.Helper()
		decision, err := e.EvaluateRequirementsOnly(context.Background(), request)
		if err != nil || decision.Effect != effect || reason != "" && decision.ReasonCode != reason {
			t.Fatalf("effect=%s reason=%s err=%v", decision.Effect, decision.ReasonCode, err)
		}
	}
	check("allow", "")
	principal.value.Facts.Exposures = []string{"*"}
	check("deny", "featureDisabled")
	principal.value.Facts.Exposures = []string{"feature", "second"}
	principal.value.Facts.Roles = []string{"*"}
	check("deny", "roleDenied")
	principal.value.Facts.Roles = []string{"Reader"}
	check("deny", "roleDenied")
	principal.value.Facts.Roles = []string{"reader"}
	check("allow", "")
	// A newly resolved identity cannot reuse the previous request's memberships.
	principal.value.Facts.Roles = nil
	check("deny", "roleDenied")
}
