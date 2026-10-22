package access

import (
	"context"
	"github.com/viant/authz"
)

// PolicyResources enumerates current policy identities from existing heads.
// It is used only by checked administration, never on the execution path.
func (s *Store) PolicyResources(ctx context.Context, tenant string) ([]authz.Resource, error) {
	if s == nil || s.DB == nil || ctx == nil || ctx.Err() != nil || tenant == "" || tenant == "*" {
		return nil, authz.ErrDenied
	}
	rows, err := s.DB.QueryContext(ctx, `SELECT resource_kind,resource_id,resource_version FROM resource_policies WHERE tenant_id=? ORDER BY resource_kind,resource_id,resource_version LIMIT 10001`, tenant)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []authz.Resource{}
	for rows.Next() {
		r := authz.Resource{Tenant: tenant}
		if err := rows.Scan(&r.Kind, &r.ID, &r.Version); err != nil {
			return nil, err
		}
		out = append(out, r)
		if len(out) > 10000 {
			return nil, authz.ErrUnavailable
		}
	}
	return out, rows.Err()
}
