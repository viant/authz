package access

import (
	"context"
	"database/sql"
	"encoding/json"
	acl "github.com/viant/authz"
	"os"
	"testing"
)

// This read-only fixture proves native replay without a reachable DB, followed
// by native generation invalidation. No row or authorization map is used.
func TestMySQLNativePolicyCache(t *testing.T) {
	dsn, identity := os.Getenv("AUTHZ_MYSQL_TEST_DSN"), os.Getenv("AUTHZ_NATIVE_CACHE_RESOURCE")
	if dsn == "" || identity == "" {
		t.Skip("authorized MySQL fixture DSN and exact resource JSON required")
	}
	var resource acl.Resource
	if err := json.Unmarshal([]byte(identity), &resource); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store := &Store{DB: db}
	defer store.Close(ctx)
	first, err := store.Get(ctx, resource)
	if err != nil {
		t.Fatal(err)
	}
	if first.Revision < 1 || len(first.Policies) == 0 {
		t.Fatal("expected real policy")
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	for n := 0; n < 100; n++ {
		doc, err := store.Get(ctx, resource)
		if err != nil {
			t.Fatalf("native hit %d reached closed DB: %v", n, err)
		}
		if doc.Revision != first.Revision || len(doc.Policies) != len(first.Policies) {
			t.Fatal("policy replay changed")
		}
		for action := range doc.Policies {
			delete(doc.Policies, action)
		}
	}
	unrelated, err := sql.Open("mysql", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer unrelated.Close()
	other := &Store{DB: unrelated}
	defer other.Close(ctx)
	absent := resource
	absent.ID += "-native-cache-isolation-missing"
	if _, err := other.Get(ctx, absent); err != sql.ErrNoRows {
		t.Fatalf("prepare other pool: %v", err)
	}
	if err := unrelated.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := other.Get(ctx, resource); err == nil {
		t.Fatal("native policy cache crossed database pool identity")
	}
	if err := InvalidateNativePolicyReaders(ctx, unrelated); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get(ctx, resource); err != nil {
		t.Fatal("unrelated pool invalidated policy", err)
	}
	if err := InvalidateNativePolicyReaders(ctx, db); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get(ctx, resource); err == nil {
		t.Fatal("native generation invalidation replayed stale document")
	}
}
