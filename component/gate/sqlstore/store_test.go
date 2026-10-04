package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/viant/authz"
	"github.com/viant/authz/component/schema"
	"github.com/viant/authz/gating"
	_ "modernc.org/sqlite"
)

type verifiedManager struct{ facts authz.Facts }

func (p verifiedManager) Resolve(context.Context) (authz.Facts, error) { return p.facts, nil }

type managementPolicies struct{ doc authz.Document }

func (s managementPolicies) Get(context.Context, authz.Resource) (authz.Document, error) {
	return s.doc, nil
}
func (managementPolicies) Replace(context.Context, authz.Document, int64, string) (authz.Document, error) {
	return authz.Document{}, authz.ErrDenied
}

func testDB(t *testing.T) (*sql.DB, string) {
	t.Helper()
	dsn := "file:" + filepath.Join(t.TempDir(), "authz.db") + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	migration, err := schema.New("sqlite")
	if err != nil {
		t.Fatal(err)
	}
	if err := migration.Up(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	return db, dsn
}

func TestSQLStorePersistsCASAuditAndRetiredAllowlist(t *testing.T) {
	ctx := context.Background()
	db, _ := testDB(t)
	resource := authz.Resource{Kind: "window", ID: "orders", Version: "1", Tenant: "tenant"}
	binding := gating.Binding{Resource: resource, Action: "execute", Document: gating.RequirementsDocument{Revision: "r1", Requirements: gating.Requirements{SchemaVersion: 1}}}
	first, err := New(ctx, db, []gating.Binding{binding})
	if err != nil {
		t.Fatal(err)
	}
	updated, err := first.ReplaceRequirementsAs(ctx, resource, "execute", "r1", gating.Requirements{SchemaVersion: 1, RequiredExposures: []string{"FEATURE"}}, "alice")
	if err != nil || updated.Revision == "" || updated.Revision == "r1" {
		t.Fatalf("replace=%+v err=%v", updated, err)
	}
	second, err := New(ctx, db, []gating.Binding{binding})
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := second.GetRequirements(ctx, resource, "execute")
	if err != nil || loaded.Revision != updated.Revision || loaded.Requirements.RequiredExposures[0] != "FEATURE" {
		t.Fatalf("shared head=%+v err=%v", loaded, err)
	}
	if _, err := second.ReplaceRequirementsAs(ctx, resource, "execute", "r1", gating.Requirements{SchemaVersion: 1}, "bob"); !errors.Is(err, authz.ErrConflict) {
		t.Fatalf("stale CAS=%v", err)
	}
	var count int
	var actor string
	if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM authz_gate_revisions WHERE binding_key = ?", bindingKey(resource, "execute")).Scan(&count); err != nil || count != 2 {
		t.Fatalf("history count=%d err=%v", count, err)
	}
	if err := db.QueryRowContext(ctx, "SELECT actor_id FROM authz_gate_revisions WHERE binding_key = ? AND revision = ?", bindingKey(resource, "execute"), updated.Revision).Scan(&actor); err != nil || actor != "alice" {
		t.Fatalf("audit actor=%q err=%v", actor, err)
	}
	retired, err := New(ctx, db, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := retired.GetRequirements(ctx, resource, "execute"); !errors.Is(err, authz.ErrDenied) {
		t.Fatalf("retired binding active: %v", err)
	}
}

func TestSQLStoreRollsBackHeadWhenHistoryWriteFails(t *testing.T) {
	ctx := context.Background()
	db, _ := testDB(t)
	resource := authz.Resource{Kind: "window", ID: "orders", Version: "1", Tenant: "tenant"}
	binding := gating.Binding{Resource: resource, Action: "execute", Document: gating.RequirementsDocument{Revision: "r1", Requirements: gating.Requirements{SchemaVersion: 1}}}
	store, err := New(ctx, db, []gating.Binding{binding})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, "DROP TABLE authz_gate_revisions"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ReplaceRequirementsAs(ctx, resource, "execute", "r1", gating.Requirements{SchemaVersion: 1}, "alice"); !errors.Is(err, gating.ErrUnavailable) {
		t.Fatalf("history outage=%v", err)
	}
	var revision string
	if err := db.QueryRowContext(ctx, "SELECT revision FROM authz_gate_heads WHERE binding_key = ?", bindingKey(resource, "execute")).Scan(&revision); err != nil || revision != "r1" {
		t.Fatalf("failed history advanced head: revision=%q err=%v", revision, err)
	}
	if _, err := store.GetRequirements(ctx, resource, "execute"); !errors.Is(err, gating.ErrUnavailable) {
		t.Fatalf("missing history was trusted: %v", err)
	}
}

func TestSQLStoreConcurrentHostsCommitOnlyOneRevision(t *testing.T) {
	ctx := context.Background()
	db, dsn := testDB(t)
	db.SetMaxOpenConns(4)
	otherDB, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { otherDB.Close() })
	resource := authz.Resource{Kind: "window", ID: "orders", Version: "1", Tenant: "tenant"}
	binding := gating.Binding{Resource: resource, Action: "execute", Document: gating.RequirementsDocument{Revision: "r1", Requirements: gating.Requirements{SchemaVersion: 1}}}
	first, err := New(ctx, db, []gating.Binding{binding})
	if err != nil {
		t.Fatal(err)
	}
	second, err := New(ctx, otherDB, []gating.Binding{binding})
	if err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	results := make(chan error, 2)
	var wait sync.WaitGroup
	for _, store := range []*Store{first, second} {
		wait.Add(1)
		go func(store *Store) {
			defer wait.Done()
			<-start
			_, err := store.ReplaceRequirementsAs(ctx, resource, "execute", "r1", gating.Requirements{SchemaVersion: 1}, "alice")
			results <- err
		}(store)
	}
	close(start)
	wait.Wait()
	close(results)
	committed, conflicts := 0, 0
	for err := range results {
		switch {
		case err == nil:
			committed++
		case errors.Is(err, authz.ErrConflict):
			conflicts++
		default:
			t.Fatalf("concurrent writer returned outage: %v", err)
		}
	}
	if committed != 1 || conflicts != 1 {
		t.Fatalf("CAS results committed=%d conflict=%d", committed, conflicts)
	}
}

func TestSQLStoreConcurrentHostBootstrapCreatesOneHistory(t *testing.T) {
	ctx := context.Background()
	db, dsn := testDB(t)
	otherDB, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { otherDB.Close() })
	resource := authz.Resource{Kind: "window", ID: "orders", Version: "1", Tenant: "tenant"}
	binding := gating.Binding{Resource: resource, Action: "execute", Document: gating.RequirementsDocument{Revision: "r1", Requirements: gating.Requirements{SchemaVersion: 1}}}
	start := make(chan struct{})
	results := make(chan error, 2)
	var wait sync.WaitGroup
	for _, handle := range []*sql.DB{db, otherDB} {
		wait.Add(1)
		go func(handle *sql.DB) {
			defer wait.Done()
			<-start
			_, err := New(ctx, handle, []gating.Binding{binding})
			results <- err
		}(handle)
	}
	close(start)
	wait.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatalf("concurrent bootstrap=%v", err)
		}
	}
	var count int
	if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM authz_gate_revisions WHERE binding_key = ?", bindingKey(resource, "execute")).Scan(&count); err != nil || count != 1 {
		t.Fatalf("bootstrap history count=%d err=%v", count, err)
	}
}

func TestRequirementsHistoryComparisonAcceptsJSONNormalization(t *testing.T) {
	if !sameRequirementsJSON(`{"schemaVersion":1,"allowedRoles":["reader"]}`, `{"allowedRoles":["reader"], "schemaVersion":1}`) {
		t.Fatal("semantically identical JSON revisions differed")
	}
	if sameRequirementsJSON(`{"schemaVersion":1,"allowedRoles":["reader"]}`, `{"schemaVersion":1,"allowedRoles":["admin"]}`) {
		t.Fatal("changed requirements passed history comparison")
	}
}

func TestSQLStoreAdministrationRecordsVerifiedManager(t *testing.T) {
	ctx := context.Background()
	db, _ := testDB(t)
	resource := authz.Resource{Kind: "window", ID: "orders", Version: "1", Tenant: "tenant"}
	binding := gating.Binding{Resource: resource, Action: "execute", Document: gating.RequirementsDocument{Revision: "r1", Requirements: gating.Requirements{SchemaVersion: 1}}}
	store, err := New(ctx, db, []gating.Binding{binding})
	if err != nil {
		t.Fatal(err)
	}
	rule := &authz.Rule{Kind: "role", Value: "manager"}
	facts := authz.Facts{Subject: "alice", Issuer: "issuer", Tenant: "tenant", Roles: []string{"manager"}, ValidUntil: time.Now().Add(time.Minute)}
	acl := &authz.Service{Provider: verifiedManager{facts}, Store: managementPolicies{authz.Document{Resource: resource, Revision: 1, Policies: map[string]authz.Policy{"manageAccess": {Mode: "protected", Rule: rule}, "viewAccess": {Mode: "protected", Rule: rule}}}}}
	admin := &gating.Administration{ACL: acl, Store: store, Writer: store}
	updated, err := admin.Replace(ctx, resource, "execute", "r1", gating.Requirements{SchemaVersion: 1, RequiredExposures: []string{"FEATURE"}})
	if err != nil || updated.Revision == "r1" {
		t.Fatalf("managed replacement=%+v %v", updated, err)
	}
	var actor string
	if err := db.QueryRowContext(ctx, "SELECT actor_id FROM authz_gate_revisions WHERE binding_key = ? AND revision = ?", bindingKey(resource, "execute"), updated.Revision).Scan(&actor); err != nil || actor != "alice" {
		t.Fatalf("verified actor=%q err=%v", actor, err)
	}
	facts.Roles = []string{"reader"}
	acl.Provider = verifiedManager{facts}
	if _, err := admin.Replace(ctx, resource, "execute", updated.Revision, gating.Requirements{SchemaVersion: 1}); !errors.Is(err, authz.ErrDenied) {
		t.Fatalf("unprivileged edit=%v", err)
	}
}
