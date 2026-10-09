package access

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	acl "github.com/viant/authz"
	policySchema "github.com/viant/authz/component/schema"
)

func newBorrowedSQLite(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "borrowed.db"))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, db.Close()) })
	ddl, err := policySchema.DDL("sqlite")
	require.NoError(t, err)
	_, err = db.Exec(ddl)
	require.NoError(t, err)
	return db
}

func borrowedPolicy(id string) acl.Document {
	return acl.Document{Resource: acl.Resource{Tenant: "fixture", Kind: "window", ID: id, Version: "working"}, Policies: map[string]acl.Policy{"describe": {Mode: "protected", Rule: &acl.Rule{Kind: "subject", Value: "fixture-reader"}}}}
}

func TestNativeBorrowedPolicyTransactionRetainsCallerOwnership(t *testing.T) {
	for _, operation := range []string{"commit", "rollback", "failure"} {
		t.Run(operation, func(t *testing.T) {
			ctx := context.Background()
			db := newBorrowedSQLite(t)
			tx, err := db.BeginTx(ctx, nil)
			require.NoError(t, err)
			defer tx.Rollback()
			store, err := NewTransactionStore(ctx, db, tx)
			require.NoError(t, err)
			doc := borrowedPolicy("window://example/" + operation)
			_, err = store.Provision(ctx, doc, "operator-fixture")
			require.NoError(t, err)
			loaded, err := store.Get(ctx, doc.Resource)
			require.NoError(t, err)
			require.EqualValues(t, 1, loaded.Revision)
			if operation == "failure" {
				_, err = store.Provision(ctx, doc, "operator-fixture")
				require.Error(t, err, "duplicate native write must fail without completing caller tx")
			}
			require.NoError(t, store.Close(ctx))
			var count int
			require.NoError(t, tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM resource_policies").Scan(&count), "store Close cannot finish caller tx")
			require.Equal(t, 1, count)
			_, err = store.Get(ctx, doc.Resource)
			require.ErrorIs(t, err, acl.ErrDenied, "closed unit cannot reopen cached registrations")
			if operation == "commit" {
				require.NoError(t, tx.Commit())
			} else {
				require.NoError(t, tx.Rollback())
			}
			require.NoError(t, db.QueryRowContext(ctx, "SELECT COUNT(*) FROM resource_policies").Scan(&count), "store Close cannot close DB")
			want := 0
			if operation == "commit" {
				want = 1
			}
			require.Equal(t, want, count)
			require.NoError(t, db.QueryRowContext(ctx, "SELECT COUNT(*) FROM resource_policy_revisions").Scan(&count))
			require.Equal(t, want, count)
			_, err = NewTransactionStore(ctx, db, tx)
			require.ErrorIs(t, err, sql.ErrTxDone)
		})
	}
}

func TestBorrowedPolicyUnitsCannotRebindOrShareRuntime(t *testing.T) {
	ctx := context.Background()
	dbs := []*sql.DB{newBorrowedSQLite(t), newBorrowedSQLite(t)}
	_, err := NewTransactionStore(ctx, dbs[0], nil)
	require.Error(t, err)
	var wg sync.WaitGroup
	errorsCh := make(chan error, 2)
	for i, db := range dbs {
		wg.Add(1)
		go func(i int, db *sql.DB) {
			defer wg.Done()
			tx, err := db.BeginTx(ctx, nil)
			if err != nil {
				errorsCh <- err
				return
			}
			defer tx.Rollback()
			store, err := NewTransactionStore(ctx, db, tx)
			if err != nil {
				errorsCh <- err
				return
			}
			defer store.Close(ctx)
			doc := borrowedPolicy([]string{"window://example/one", "window://example/two"}[i])
			if _, err = store.Provision(ctx, doc, "fixture"); err != nil {
				errorsCh <- err
				return
			}
			store.DB = dbs[1-i]
			if _, err = store.Get(ctx, doc.Resource); !errors.Is(err, acl.ErrDenied) {
				errorsCh <- errors.New("borrowed store accepted DB rebinding")
				return
			}
			store.DB = db
			if err = store.Close(ctx); err != nil {
				errorsCh <- err
				return
			}
			errorsCh <- tx.Commit()
		}(i, db)
	}
	wg.Wait()
	close(errorsCh)
	for err := range errorsCh {
		require.NoError(t, err)
	}
	for i, db := range dbs {
		var count int
		require.NoError(t, db.QueryRow("SELECT COUNT(*) FROM resource_policies WHERE resource_id=?", []string{"window://example/two", "window://example/one"}[i]).Scan(&count))
		require.Zero(t, count, "concurrent borrowed native runtime crossed database units")
	}
}
