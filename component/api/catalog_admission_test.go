package api

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/viant/authz"
	"github.com/viant/authz/gating"
)

type admissionFacts struct{ value authz.Facts }

func (p admissionFacts) Resolve(context.Context) (authz.Facts, error) { return p.value, nil }

type admissionPrincipal struct{ value gating.Principal }

func (p admissionPrincipal) ResolvePrincipal(context.Context) (gating.Principal, error) {
	return p.value, nil
}

func TestCatalogAdmissionAddsInheritedResourceWithoutWideningStaticEntries(t *testing.T) {
	ctx := context.Background()
	facts := authz.Facts{Subject: "alice", Issuer: "idp", Tenant: "tenant", Roles: []string{"reader"}, ValidUntil: time.Now().Add(time.Minute)}
	static := authz.Resource{Kind: "window", ID: "file-window", Version: "1", Tenant: "tenant"}
	dynamic := authz.Resource{Kind: "report", ID: strings.Repeat("a", 64), Version: "logical", Tenant: "tenant"}
	store, err := authz.NewStaticStore([]authz.Document{{Resource: static, Revision: 1, Policies: map[string]authz.Policy{
		"viewAccess": {Mode: "protected", Rule: &authz.Rule{Kind: "role", Value: "reader"}},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	services := &Services{Authorization: &authz.Service{Store: store, Provider: admissionFacts{facts}},
		Gates: &gating.Evaluator{Principals: admissionPrincipal{gating.Principal{Facts: facts, AccountID: "account", IdentityRevision: "id-1"}}},
		Catalog: CatalogFunc(func(context.Context) ([]CatalogEntry, error) {
			return []CatalogEntry{{Name: "File window", Resource: static, Actions: []string{"viewAccess"}},
				{Name: "Draft report", Resource: dynamic, Actions: []string{"viewAccess"}, Context: "trusted-object-key"}}, nil
		})}
	visible, err := ListAuthorizedCatalog(ctx, services)
	if err != nil || len(visible) != 1 || visible[0].Resource != static {
		t.Fatalf("default catalog widened dynamic resource visible=%+v err=%v", visible, err)
	}
	dynamicChecks := 0
	services.CatalogAdmission = func(_ context.Context, principal gating.Principal, entry CatalogEntry) (bool, bool, error) {
		if entry.Context == nil {
			return false, false, nil
		}
		dynamicChecks++
		if entry.Context != "trusted-object-key" || principal.AccountID != "account" || principal.IdentityRevision != "id-1" {
			return true, false, authz.ErrDenied
		}
		return true, true, nil
	}
	visible, err = ListAuthorizedCatalog(ctx, services)
	if err != nil || len(visible) != 2 || dynamicChecks != 2 || visible[1].Resource != dynamic {
		t.Fatalf("host-admitted catalog visible=%+v checks=%d err=%v", visible, dynamicChecks, err)
	}
	wire, err := json.Marshal(visible)
	if err != nil || strings.Contains(string(wire), "trusted-object-key") {
		t.Fatalf("server-only catalog context leaked: %s err=%v", wire, err)
	}
	dynamicChecks = 0
	services.CatalogAdmission = func(_ context.Context, _ gating.Principal, entry CatalogEntry) (bool, bool, error) {
		if entry.Context == nil {
			return false, false, nil
		}
		dynamicChecks++
		return true, dynamicChecks == 1, nil
	}
	if visible, err := ListAuthorizedCatalog(ctx, services); visible != nil || !errors.Is(err, authz.ErrUnavailable) {
		t.Fatalf("revoked catalog admission returned partial entries=%+v err=%v", visible, err)
	}
	services.CatalogAdmission = func(_ context.Context, _ gating.Principal, _ CatalogEntry) (bool, bool, error) {
		return true, true, nil
	}
	if visible, err := ListAuthorizedCatalog(ctx, services); visible != nil || !errors.Is(err, authz.ErrUnavailable) {
		t.Fatalf("static entry admission override widened catalog=%+v err=%v", visible, err)
	}
}
