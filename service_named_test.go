package authz

import (
	"context"
	"errors"
	"testing"
)

type namedCallbackProvider struct {
	facts  Facts
	before func()
}

func (p namedCallbackProvider) Resolve(context.Context) (Facts, error) {
	if p.before != nil {
		p.before()
	}
	return p.facts, nil
}

func TestServiceNamedPoliciesResolveAndFenceForEveryExecutionAPI(t *testing.T) {
	for _, api := range []string{"revision", "status", "selection"} {
		t.Run(api, func(t *testing.T) {
			store, ref, assignment, facts := namedFixture()
			assignment.Resource = Resource{Kind: "component", ID: "supply", Version: "1", Tenant: "tenant"}
			store[assignment.Resource] = assignment
			definition := store[ref]
			definition.Policies[NamedDefinitionAction].Definition.Policies["*"] = Policy{Mode: "protected", Rule: &Rule{Kind: "role", Value: "ROLE_STEWARD_SUPER_USER"}}
			store[ref] = definition
			facts.MembershipGroups = nil
			facts.Roles = []string{"ROLE_STEWARD_SUPER_USER"}
			service := &Service{Store: store, Provider: testProvider{facts}}
			request := Request{Resource: assignment.Resource, Action: "execute"}
			invoke := func() error {
				switch api {
				case "revision":
					_, _, _, err := service.AuthorizeWithRevision(context.Background(), request)
					return err
				case "selection":
					_, _, _, err := service.AuthorizeSelectionWithStatus(context.Background(), request, nil)
					return err
				default:
					_, _, _, err := service.AuthorizeWithStatus(context.Background(), request)
					return err
				}
			}
			if err := invoke(); err != nil {
				t.Fatalf("member denied by named policy: %v", err)
			}
			if store[assignment.Resource].Policies["*"].Named == nil {
				t.Fatal("stored reference was replaced by compiled policy")
			}
			missing := facts
			missing.Roles = nil
			service.Provider = testProvider{missing}
			if !errors.Is(invoke(), ErrDenied) {
				t.Fatal("nonmember was allowed")
			}
			service.Provider = namedCallbackProvider{facts: facts, before: func() { changed := store[ref]; changed.Revision++; store[ref] = changed }}
			if !errors.Is(invoke(), ErrDenied) {
				t.Fatal("named head changed during identity resolution without denying stale decision")
			}
			service.Provider = testProvider{facts}
			changed := store[ref]
			changed.Policies[NamedDefinitionAction].Definition.Policies["*"] = Policy{Mode: "deny"}
			changed.Revision++
			store[ref] = changed
			if !errors.Is(invoke(), ErrDenied) {
				t.Fatal("live named revocation was ignored")
			}
		})
	}
}
