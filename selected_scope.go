package authz

import (
	"context"
	"errors"
	"fmt"
	"time"
)

var ErrSelectionDenied = fmt.Errorf("%w: selected entity scope rejected", ErrDenied)

var ErrSelectionRequired = fmt.Errorf("%w: explicit entity selection required", ErrDenied)

// SelectedScopeProvider is a host-configured authority for explicit selections.
// It never supplies general Facts or makes a whole-resource grant. Local ACL
// predicates are checked against the original verified facts before it is called.
// Configuring this provider explicitly replaces static entity-list bounds for
// selected requests; ordinary requests keep their existing scope behavior.
type SelectedScopeProvider interface {
	ResolveSelectedScope(context.Context, Request, Document, Facts) (SelectedScopeDecision, error)
}
type SelectedScopeDecision struct {
	Entities   []Entity
	ValidUntil time.Time
}

// AuthorizeSelectionWithStatus applies a caller's explicit selection only when
// the exact loaded policy is entity-bounded. Unbounded ACLs keep their normal
// behavior; gates independently enforce their named entity permissions.
func (s *Service) AuthorizeSelectionWithStatus(ctx context.Context, request Request, selected []Entity) (Decision, Facts, int64, error) {
	selection := append([]Entity{}, selected...)
	decision, facts, doc, err := s.authorizeDocumentWithSelection(ctx, request, &selection)
	return decision, facts, doc.Revision, err
}

func (s *Service) evaluateSelected(ctx context.Context, request Request, doc Document, facts Facts) (Decision, Facts, error) {
	policy := doc.Policies[request.Action]
	if s.SelectedScopes == nil || policy.Mode != "protected" || policy.EntityType == "" || request.Selection == nil {
		decision, err := Evaluate(request, doc.Policies, facts, time.Now())
		if err != nil && policy.EntityType != "" && request.Selection != nil {
			aclPolicy := policy
			aclPolicy.EntityType = ""
			aclRequest := request
			aclRequest.Selection = nil
			if _, aclErr := Evaluate(aclRequest, map[string]Policy{request.Action: aclPolicy}, facts, time.Now()); aclErr == nil {
				err = ErrSelectionDenied
			}
		}
		return decision, facts, err
	}
	if len(*request.Selection) == 0 {
		return Decision{}, Facts{}, ErrDenied
	}
	selection := append([]Entity(nil), (*request.Selection)...)
	seen := map[Entity]bool{}
	for _, e := range selection {
		if e.Type != policy.EntityType || e.ID == "" || seen[e] {
			return Decision{}, Facts{}, ErrDenied
		}
		seen[e] = true
	}
	// A private policy copy separates original ACL predicates from remote bounds.
	// Entity-rule leaves still require original Facts and cannot be satisfied by
	// selected entities returned from a provider.
	aclPolicy := policy
	aclPolicy.EntityType = ""
	aclRequest := request
	aclRequest.Selection = nil
	if _, err := Evaluate(aclRequest, map[string]Policy{request.Action: aclPolicy}, facts, time.Now()); err != nil {
		return Decision{}, Facts{}, ErrDenied
	}
	providerSelection := append([]Entity(nil), selection...)
	request.Selection = &providerSelection
	checked, err := s.SelectedScopes.ResolveSelectedScope(ctx, request, doc, facts)
	if errors.Is(err, ErrIdentityDenied) {
		return Decision{}, Facts{}, err
	}
	if errors.Is(err, ErrDenied) {
		return Decision{}, Facts{}, ErrSelectionDenied
	}
	if err != nil || ctx.Err() != nil {
		return Decision{}, Facts{}, ErrUnavailable
	}
	if !facts.ValidUntil.After(time.Now()) || !checked.ValidUntil.After(time.Now()) || len(checked.Entities) != len(seen) {
		return Decision{}, Facts{}, ErrDenied
	}
	for _, e := range checked.Entities {
		if !seen[e] {
			return Decision{}, Facts{}, ErrDenied
		}
		delete(seen, e)
	}
	if len(seen) != 0 {
		return Decision{}, Facts{}, ErrDenied
	}
	current, identityErr := s.Provider.Resolve(ctx)
	if errors.Is(identityErr, ErrDenied) {
		return Decision{}, Facts{}, ErrIdentityDenied
	}
	if identityErr != nil || ctx.Err() != nil {
		return Decision{}, Facts{}, ErrUnavailable
	}
	if !sameManagementFacts(facts, current) {
		return Decision{}, Facts{}, ErrIdentityDenied
	}
	if current.ValidUntil.Before(facts.ValidUntil) {
		facts.ValidUntil = current.ValidUntil
	}
	if checked.ValidUntil.Before(facts.ValidUntil) {
		facts.ValidUntil = checked.ValidUntil
	}
	if ctx.Err() != nil {
		return Decision{}, Facts{}, ErrUnavailable
	}
	if !facts.ValidUntil.After(time.Now()) {
		return Decision{}, Facts{}, ErrSelectionDenied
	}
	return Decision{Bounded: true, Entities: selection}, facts, nil
}
