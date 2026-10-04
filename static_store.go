package authz

import (
	"context"
	"fmt"
)

// StaticStore serves immutable, server-owned ACL documents for configured
// resources such as existing file-backed windows. Configuration reloads build a
// new store; policy administration uses a writable CAS store instead.
type StaticStore struct{ documents map[Resource]Document }

func NewStaticStore(documents []Document) (*StaticStore, error) {
	store := &StaticStore{documents: make(map[Resource]Document, len(documents))}
	for _, doc := range documents {
		if doc.Resource.Kind == "" || doc.Resource.ID == "" || doc.Resource.Version == "" || doc.Resource.Tenant == "" || doc.Revision < 1 || len(doc.Policies) == 0 {
			return nil, fmt.Errorf("invalid static policy document")
		}
		if _, exists := store.documents[doc.Resource]; exists {
			return nil, fmt.Errorf("duplicate static policy document")
		}
		for action, policy := range doc.Policies {
			if err := ValidatePolicy(action, policy); err != nil {
				return nil, err
			}
		}
		store.documents[doc.Resource] = cloneStaticDocument(doc)
	}
	return store, nil
}

func (s *StaticStore) Get(ctx context.Context, resource Resource) (Document, error) {
	if s == nil || ctx == nil || ctx.Err() != nil {
		return Document{}, ErrDenied
	}
	doc, ok := s.documents[resource]
	if !ok {
		return Document{}, ErrDenied
	}
	return cloneStaticDocument(doc), nil
}

func (*StaticStore) Replace(context.Context, Document, int64, string) (Document, error) {
	return Document{}, ErrDenied
}

func cloneStaticDocument(doc Document) Document {
	policies := make(map[string]Policy, len(doc.Policies))
	for action, policy := range doc.Policies {
		policy.RequiredScopes = append([]string(nil), policy.RequiredScopes...)
		if policy.Rule != nil {
			rule := cloneStaticRule(*policy.Rule)
			policy.Rule = &rule
		}
		policies[action] = policy
	}
	doc.Policies = policies
	return doc
}

func cloneStaticRule(rule Rule) Rule {
	if rule.Entity != nil {
		entity := *rule.Entity
		rule.Entity = &entity
	}
	if rule.Rules != nil {
		children := make([]Rule, len(rule.Rules))
		for i, child := range rule.Rules {
			children[i] = cloneStaticRule(child)
		}
		rule.Rules = children
	}
	return rule
}
