package authz

import (
	"context"
	"errors"
	"testing"
	"time"
)

type directoryFactsProvider struct{ facts Facts }

func (p directoryFactsProvider) Resolve(context.Context) (Facts, error) { return p.facts, nil }

func TestStaticDirectoryRechecksViewAccessAndClonesChoices(t *testing.T) {
	resource := Resource{Kind: "window", ID: "orders", Version: "1", Tenant: "tenant"}
	facts := Facts{Subject: "alice", Issuer: "issuer", Tenant: "tenant", Roles: []string{"manager"}, ValidUntil: time.Now().Add(time.Hour)}
	store, err := NewStaticStore([]Document{{Resource: resource, Revision: 1, Policies: map[string]Policy{"viewAccess": {Mode: "protected", Rule: &Rule{Kind: "role", Value: "manager"}}}}})
	if err != nil {
		t.Fatal(err)
	}
	access := &Service{Store: store, Provider: directoryFactsProvider{facts: facts}}
	directory, err := NewStaticDirectory([]PolicyChoiceBinding{{Resource: resource, Choices: Choices{Roles: []Choice{{ID: "manager", Label: "Manager"}, {ID: "analyst", Label: "Analyst"}}, Entities: []Choice{{Entity: &Entity{Type: "customer", ID: "42"}, Label: "Customer 42"}}, EntityTypes: []string{"customer"}}}}, access)
	if err != nil {
		t.Fatal(err)
	}
	choices, err := directory.Choices(context.Background(), resource, facts)
	if err != nil || len(choices.Roles) != 2 || choices.Roles[1].ID != "analyst" {
		t.Fatalf("directory choices=%+v err=%v", choices, err)
	}
	choices.Roles[1].ID = "forged"
	choices.Entities[0].Entity.ID = "forged"
	current, err := directory.Choices(context.Background(), resource, facts)
	if err != nil || current.Roles[1].ID != "analyst" || current.Entities[0].Entity.ID != "42" {
		t.Fatalf("returned choice mutation changed directory=%+v err=%v", current, err)
	}
	changed := facts
	changed.Roles = []string{"other"}
	if _, err := directory.Choices(context.Background(), resource, changed); !errors.Is(err, ErrDenied) {
		t.Fatalf("fact drift passed directory: %v", err)
	}
	if _, err := directory.Choices(context.Background(), Resource{Kind: "window", ID: "other", Version: "1", Tenant: "tenant"}, facts); !errors.Is(err, ErrDenied) {
		t.Fatalf("unconfigured directory resource passed: %v", err)
	}
	deniedFacts := facts
	deniedFacts.Roles = []string{"viewer"}
	deniedAccess := &Service{Store: store, Provider: directoryFactsProvider{facts: deniedFacts}}
	deniedDirectory, err := NewStaticDirectory([]PolicyChoiceBinding{{Resource: resource, Choices: Choices{Roles: []Choice{{ID: "manager", Label: "Manager"}}}}}, deniedAccess)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := deniedDirectory.Choices(context.Background(), resource, deniedFacts); !errors.Is(err, ErrDenied) {
		t.Fatalf("policy-denied directory read passed: %v", err)
	}
}
