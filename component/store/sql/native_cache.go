package access

import (
	"context"
	"database/sql"
	"sync"
)

// This registry retains compiled runtimes only. SQLX owns all cached rows and
// native generations; no authorization decision is retained here.
var nativePolicyReaders sync.Map // *Store -> host-owned *sql.DB

// InvalidateNativePolicyReaders advances native cache generations after an
// owning metadata transaction commits. It does not compile unused readers.
// A nil db selects every registered pool.
func InvalidateNativePolicyReaders(ctx context.Context, db *sql.DB) error {
	var failure error
	nativePolicyReaders.Range(func(key, value any) bool {
		if db != nil && value != db {
			return true
		}
		store := key.(*Store)
		store.mu.Lock()
		defer store.mu.Unlock()
		if store.runtime == nil {
			return true
		}
		_, failure = store.runtime.InvalidateCache(ctx, store.read, "", "all")
		return failure == nil
	})
	return failure
}
