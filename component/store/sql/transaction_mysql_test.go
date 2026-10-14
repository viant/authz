package access

import (
	"context"
	"database/sql"
	"os"
	"strings"
	"testing"

	"github.com/go-sql-driver/mysql"
	"github.com/stretchr/testify/require"
	policySchema "github.com/viant/authz/component/schema"
)

// The caller creates a NEW empty owned database; no existing schema is altered
// or dropped, and the fixture rows remain available for independent inspection.
func TestNativeBorrowedPolicyTransactionMySQLFresh(t *testing.T) {
	raw := os.Getenv("AUTHZ_BORROWED_TX_MYSQL_DSN")
	if raw == "" {
		t.Skip("AUTHZ_BORROWED_TX_MYSQL_DSN requires a new owned authz_borrowed_tx_test database on 127.0.0.1:23309")
	}
	config, err := mysql.ParseDSN(raw)
	if err != nil || config.Net != "tcp" || config.Addr != "127.0.0.1:23309" || !strings.HasPrefix(config.DBName, "authz_borrowed_tx_test") {
		t.Fatal("borrowed transaction test requires the guarded disposable endpoint and database")
	}
	config.ParseTime = true
	db, err := sql.Open("mysql", config.FormatDSN())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, db.Close()) })
	ctx := context.Background()
	var existing int
	require.NoError(t, db.QueryRowContext(ctx, "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=DATABASE()").Scan(&existing))
	require.Zero(t, existing, "configured database must be newly created and empty")
	require.NoError(t, policySchema.CreatePolicies(ctx, db, "mysql"))
	for _, mode := range []string{"commit", "rollback", "failure"} {
		t.Run(mode, func(t *testing.T) {
			tx, err := db.BeginTx(ctx, nil)
			require.NoError(t, err)
			defer tx.Rollback()
			store, err := NewTransactionStore(ctx, db, tx)
			require.NoError(t, err)
			doc := borrowedPolicy("window://example/mysql-" + mode)
			_, err = store.Provision(ctx, doc, "operator-fixture")
			require.NoError(t, err)
			loaded, err := store.Get(ctx, doc.Resource)
			require.NoError(t, err)
			require.EqualValues(t, 1, loaded.Revision)
			if mode == "failure" {
				_, err = store.Provision(ctx, doc, "operator-fixture")
				require.Error(t, err)
			}
			require.NoError(t, store.Close(ctx))
			var count int
			require.NoError(t, tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM resource_policies WHERE resource_id=?", doc.Resource.ID).Scan(&count))
			require.Equal(t, 1, count)
			if mode == "commit" {
				require.NoError(t, tx.Commit())
			} else {
				require.NoError(t, tx.Rollback())
			}
			want := 0
			if mode == "commit" {
				want = 1
			}
			for _, table := range []string{"resource_policies", "resource_policy_revisions"} {
				require.NoError(t, db.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+table+" WHERE resource_id=?", doc.Resource.ID).Scan(&count))
				require.Equal(t, want, count, "native component escaped caller transaction")
			}
			_, err = NewTransactionStore(ctx, db, tx)
			require.ErrorIs(t, err, sql.ErrTxDone)
		})
	}
}
