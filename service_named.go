package authz

import (
	"context"
	"database/sql"
	"errors"
)

// resolveNamed keeps the stored assignment intact while evaluating its current
// reusable definition. A successful decision is fenced against every input head.
func (s *Service) resolveNamed(ctx context.Context, document Document) (Document, []NamedDependency, error) {
	for _, policy := range document.Policies {
		if policy.Named != nil {
			return ResolveNamedDocument(ctx, s.Store, document)
		}
	}
	return document, nil, nil
}

func (s *Service) fenceNamed(ctx context.Context, dependencies []NamedDependency) error {
	for _, dependency := range dependencies {
		if ctx.Err() != nil {
			return ErrUnavailable
		}
		current, err := s.Store.Get(ctx, dependency.Resource)
		if errors.Is(err, ErrDenied) || errors.Is(err, sql.ErrNoRows) {
			return ErrDenied
		}
		if err != nil {
			return ErrUnavailable
		}
		if current.Resource != dependency.Resource || current.Revision != dependency.Revision {
			return ErrDenied
		}
	}
	return nil
}
