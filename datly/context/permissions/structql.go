// Package permissions builds the SQL-facing permission lookup view once per
// resolved authorization context. It uses StructQL's typed ARRAY_AGG projection.
package permissions

import (
	"fmt"
	"github.com/viant/authz"
	"github.com/viant/structql"
	"reflect"
)

type idRow struct{ ID string }
type idProjection struct{ IDs []string }

// Index narrows grants first, then materializes typed StructQL ID projections.
// Map construction is a one-time context operation, never a business SQL loop.
func Index(grants []authz.EntityPermission, decision authz.Decision) (authz.EntityPermissionIndex, error) {
	narrowed, err := authz.IndexEntityPermissions(grants, decision)
	if err != nil {
		return nil, err
	}
	query, err := structql.NewQuery("SELECT ARRAY_AGG(ID) AS IDs FROM `/`", reflect.TypeOf([]idRow{}), reflect.TypeOf(idProjection{}))
	if err != nil {
		return nil, fmt.Errorf("compile permission context projection: %w", err)
	}
	result := authz.EntityPermissionIndex{}
	for kind, permissions := range narrowed {
		result[kind] = map[string][]string{}
		for permission, ids := range permissions {
			rows := make([]idRow, len(ids))
			for i, id := range ids {
				rows[i] = idRow{ID: id}
			}
			value, err := query.First(rows)
			if err != nil {
				return nil, fmt.Errorf("project permission IDs: %w", err)
			}
			projected, ok := value.(*idProjection)
			if !ok {
				return nil, fmt.Errorf("unexpected StructQL permission projection %T", value)
			}
			result[kind][permission] = append([]string(nil), projected.IDs...)
		}
	}
	return result, nil
}
