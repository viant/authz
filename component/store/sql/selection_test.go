package access

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"

	acl "github.com/viant/authz"
	policySchema "github.com/viant/authz/component/schema"
)

type revisionFacts struct{ roles []string }

func (p *revisionFacts) Resolve(context.Context) (acl.Facts, error) {
	return acl.Facts{Subject: "synthetic-user", Tenant: "synthetic", Issuer: "synthetic-idp", Roles: p.roles, ValidUntil: time.Now().Add(time.Hour)}, nil
}

func TestDatlyRevisionGraphSelectsPolicyPriorityAndRefreshes(t *testing.T) {
	ctx := context.Background()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "graph.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := policySchema.CreatePolicies(ctx, db, "sqlite"); err != nil {
		t.Fatal(err)
	}
	store := &Store{DB: db}
	defer store.Close(ctx)
	family := acl.ResourceFamily{Kind: "report", ID: "synthetic", Tenant: "synthetic"}
	documents := map[string]acl.Document{}
	for _, test := range []struct {
		version, role string
		priority      int
	}{{"1", "diagnostic", 50}, {"2", "internal", 100}} {
		doc := acl.Document{Resource: acl.Resource{Kind: family.Kind, ID: family.ID, Tenant: family.Tenant, Version: test.version}, Policies: map[string]acl.Policy{"execute": {Priority: test.priority, Mode: "protected", Rule: &acl.Rule{Kind: "role", Value: test.role}}}}
		doc, err = store.Provision(ctx, doc, "synthetic-admin")
		if err != nil {
			t.Fatal(err)
		}
		documents[test.version] = doc
	}
	provider := &revisionFacts{}
	source := &RevisionSelections{Store: store, Action: "execute"}
	selector := acl.Selector{Mappings: source, Service: &acl.Service{Store: store, Provider: provider}}
	for _, test := range []struct {
		roles   []string
		version string
	}{{[]string{"diagnostic"}, "1"}, {[]string{"internal"}, "2"}, {[]string{"diagnostic", "internal"}, "2"}} {
		provider.roles = test.roles
		result, err := selector.Authorize(ctx, acl.SelectionRequest{Resource: family, Action: "execute"})
		if err != nil || result.Resource.Version != test.version {
			t.Fatalf("roles=%v resource=%+v err=%v", test.roles, result, err)
		}
	}
	provider.roles = []string{"diagnostic", "internal"}
	before, err := source.GetSelection(ctx, family)
	if err != nil {
		t.Fatal(err)
	}
	// A new immutable policy revision changes priority without recompiling or
	// altering content versions. The reader must not reuse an old policy graph.
	doc := documents["1"]
	policy := doc.Policies["execute"]
	policy.Priority = 200
	doc.Policies["execute"] = policy
	doc, err = store.Replace(ctx, doc, doc.Revision, "synthetic-admin")
	if err != nil {
		t.Fatal(err)
	}
	after, err := source.GetSelection(ctx, family)
	if err != nil {
		t.Fatal(err)
	}
	if before.Revision == after.Revision {
		t.Fatal("graph identity did not observe changed policy revision")
	}
	selected, err := selector.Authorize(ctx, acl.SelectionRequest{Resource: family, Action: "execute"})
	if err != nil || selected.Resource.Version != "1" {
		t.Fatalf("priority update was not observed: %+v %v", selected, err)
	}
	policy.Priority = 100
	doc.Policies["execute"] = policy
	if _, err = store.Replace(ctx, doc, doc.Revision, "synthetic-admin"); err != nil {
		t.Fatal(err)
	}
	selected, err = selector.Authorize(ctx, acl.SelectionRequest{Resource: family, Action: "execute"})
	if err != nil || (selected.Resource.Version != "1" && selected.Resource.Version != "2") {
		t.Fatalf("equal priorities were rejected: %+v %v", selected, err)
	}
	if _, err := source.GetSelection(ctx, acl.ResourceFamily{Kind: family.Kind, ID: family.ID, Tenant: "other"}); !errors.Is(err, acl.ErrDenied) {
		t.Fatalf("cross-tenant graph: %v", err)
	}
	provider.roles = nil
	if _, err := selector.Authorize(ctx, acl.SelectionRequest{Resource: family, Action: "execute"}); !errors.Is(err, acl.ErrDenied) {
		t.Fatalf("unmatched policy: %v", err)
	}
}
