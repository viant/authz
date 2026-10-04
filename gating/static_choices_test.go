package gating

import (
	"context"
	"errors"
	"testing"

	"github.com/viant/authz"
)

func TestStaticChoicesAreExactValidatedAndDetached(t *testing.T) {
	resource := authz.Resource{Kind: "window", ID: "orders", Version: "1", Tenant: "tenant"}
	binding := ChoiceBinding{Resource: resource, Action: "execute", Choices: EditorChoices{Roles: []Choice{{ID: "reader", Label: "Reader"}}, Exposures: []Choice{{ID: "FEATURE"}}, EntityPermissions: map[string][]Choice{"customer": {{ID: "read"}}}}}
	provider, err := NewStaticChoices([]ChoiceBinding{binding})
	if err != nil {
		t.Fatal(err)
	}
	binding.Choices.Roles[0].ID = "forged"
	choices, err := provider.ResolveChoices(context.Background(), resource, "execute")
	if err != nil || choices.Roles[0].ID != "reader" {
		t.Fatalf("choices=%+v err=%v", choices, err)
	}
	choices.EntityPermissions["customer"][0].ID = "forged"
	again, err := provider.ResolveChoices(context.Background(), resource, "execute")
	if err != nil || again.EntityPermissions["customer"][0].ID != "read" {
		t.Fatalf("aliased choices=%+v err=%v", again, err)
	}
	if _, err := provider.ResolveChoices(context.Background(), resource, "update"); !errors.Is(err, authz.ErrDenied) {
		t.Fatalf("unknown action=%v", err)
	}
	if _, err := NewStaticChoices([]ChoiceBinding{binding, binding}); err == nil {
		t.Fatal("duplicate choices accepted")
	}
	binding.Choices.Roles = []Choice{{ID: "reader"}, {ID: "reader"}}
	if _, err := NewStaticChoices([]ChoiceBinding{binding}); err == nil {
		t.Fatal("duplicate role option accepted")
	}
}
