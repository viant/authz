package authz

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

var ErrConflict = errors.New("policy revision conflict")
var ErrUnavailable = errors.New("authorization service unavailable")
var ErrIdentityDenied = fmt.Errorf("%w: verified identity rejected", ErrDenied)

type Document struct {
	Resource Resource          `json:"resource"`
	Revision int64             `json:"revision"`
	Policies map[string]Policy `json:"policies"`
}

// Store persists immutable policy revisions. Replace must compare the current
// revision atomically, preventing authorization against a stale policy snapshot.
// Initial policy provisioning is a separate server-owned bootstrap operation.
type Store interface {
	Get(context.Context, Resource) (Document, error)
	Replace(context.Context, Document, int64, string) (Document, error)
}

// Service separates policy inspection from policy administration. The provider
// supplies verified identity/facts; neither operation accepts them from a client.
type Service struct {
	Store          Store
	Provider       Provider
	Directory      Directory
	Decisions      DecisionProvider
	SelectedScopes SelectedScopeProvider
}

// DecisionProvider adds a trusted remote policy decision to local ACL rules.
// It can narrow or deny access; it cannot broaden a local decision.
type DecisionProvider interface {
	Evaluate(context.Context, Request, Document, Facts) (Decision, error)
}

func (s *Service) evaluate(ctx context.Context, request Request, doc Document, facts Facts) (Decision, error) {
	if ctx.Err() != nil {
		return Decision{}, ErrDenied
	}
	local, _, err := s.evaluateSelected(ctx, request, doc, facts)
	if err != nil || s.Decisions == nil || doc.Policies[request.Action].Mode == "public" {
		return local, err
	}
	remote, err := s.Decisions.Evaluate(ctx, request, doc, facts)
	if err != nil || ctx.Err() != nil || !facts.ValidUntil.After(time.Now()) {
		return Decision{}, ErrDenied
	}
	return Intersect(local, remote)
}

func (s *Service) load(ctx context.Context, resource Resource, action string) (Document, Facts, error) {
	if s.Store == nil || s.Provider == nil {
		return Document{}, Facts{}, ErrDenied
	}
	facts, err := s.Provider.Resolve(ctx)
	if err != nil {
		return Document{}, Facts{}, ErrDenied
	}
	doc, err := s.Store.Get(ctx, resource)
	if err != nil {
		return Document{}, Facts{}, ErrDenied
	}
	if doc.Resource != resource || doc.Revision < 1 {
		return Document{}, Facts{}, ErrDenied
	}
	decision, err := s.evaluate(ctx, Request{Resource: resource, Action: action}, doc, facts)
	// Policy management is an operation on the whole resource. Entity-bounded
	// decisions cannot authorize a whole-document policy read or replacement.
	if err != nil || decision.Bounded {
		return Document{}, Facts{}, ErrDenied
	}
	return doc, facts, nil
}

// Authorize evaluates current policy for execution. Callers must apply any
// returned entity scope before releasing data.
func (s *Service) Authorize(ctx context.Context, request Request) (Decision, error) {
	decision, _, err := s.AuthorizeWithFacts(ctx, request)
	return decision, err
}

// AuthorizeWithFacts returns the verified facts used for this exact decision.
// A downstream component can bind the narrowed decision together with its
// principal roles/exposures without resolving a second, potentially different
// identity snapshot. Facts are never accepted from the request payload.
func (s *Service) AuthorizeWithFacts(ctx context.Context, request Request) (Decision, Facts, error) {
	decision, facts, _, err := s.AuthorizeWithRevision(ctx, request)
	return decision, facts, err
}

// AuthorizeWithRevision returns the exact immutable policy revision used for
// this decision so gate leases and UI snapshots can bind to policy changes.
func (s *Service) AuthorizeWithRevision(ctx context.Context, request Request) (Decision, Facts, int64, error) {
	if s.Store == nil {
		return Decision{}, Facts{}, 0, ErrDenied
	}
	doc, err := s.Store.Get(ctx, request.Resource)
	if err != nil || doc.Resource != request.Resource || doc.Revision < 1 {
		return Decision{}, Facts{}, 0, ErrDenied
	}
	p, ok := doc.Policies[request.Action]
	if !ok {
		return Decision{}, Facts{}, 0, ErrDenied
	}
	var facts Facts
	if p.Mode != "public" || request.Resource.Tenant != "*" {
		if s.Provider == nil {
			return Decision{}, Facts{}, 0, ErrDenied
		}
		facts, err = s.Provider.Resolve(ctx)
		if err != nil {
			return Decision{}, Facts{}, 0, ErrDenied
		}
	}
	decision, selectedFacts, err := s.evaluateSelected(ctx, request, doc, facts)
	facts = selectedFacts
	if err == nil && s.Decisions != nil && p.Mode != "public" {
		remote, remoteErr := s.Decisions.Evaluate(ctx, request, doc, facts)
		if remoteErr != nil || ctx.Err() != nil || !facts.ValidUntil.After(time.Now()) {
			err = ErrDenied
		} else {
			decision, err = Intersect(decision, remote)
		}
	}
	if err != nil {
		return Decision{}, Facts{}, 0, err
	}
	return decision, facts, doc.Revision, nil
}

// AuthorizeWithStatus retains denial versus infrastructure failure for hosts
// that must distinguish a missing/denied policy from an unavailable authority.
// The legacy Authorize methods keep their existing denial-shaped behavior.
func (s *Service) AuthorizeWithStatus(ctx context.Context, request Request) (Decision, Facts, int64, error) {
	decision, facts, doc, err := s.authorizeDocumentWithStatus(ctx, request)
	return decision, facts, doc.Revision, err
}

// GetWithStatus checks unbounded viewAccess against the exact document it
// returns, while preserving an authority outage separately from a denial.
func (s *Service) GetWithStatus(ctx context.Context, resource Resource) (Document, error) {
	decision, _, doc, err := s.authorizeDocumentWithStatus(ctx, Request{Resource: resource, Action: "viewAccess"})
	if err != nil {
		return Document{}, err
	}
	if decision.Bounded {
		return Document{}, ErrDenied
	}
	return doc, nil
}

func (s *Service) authorizeDocumentWithStatus(ctx context.Context, request Request) (Decision, Facts, Document, error) {
	return s.authorizeDocumentWithSelection(ctx, request, nil)
}

func (s *Service) authorizeDocumentWithSelection(ctx context.Context, request Request, selected *[]Entity) (Decision, Facts, Document, error) {
	if s == nil || s.Store == nil || ctx == nil || ctx.Err() != nil {
		return Decision{}, Facts{}, Document{}, ErrUnavailable
	}
	doc, err := s.Store.Get(ctx, request.Resource)
	if errors.Is(err, ErrDenied) || errors.Is(err, sql.ErrNoRows) {
		return Decision{}, Facts{}, Document{}, ErrDenied
	}
	if err != nil {
		return Decision{}, Facts{}, Document{}, ErrUnavailable
	}
	if doc.Resource != request.Resource || doc.Revision < 1 {
		return Decision{}, Facts{}, Document{}, ErrDenied
	}
	policy, exists := doc.Policies[request.Action]
	if !exists {
		return Decision{}, Facts{}, doc, ErrDenied
	}
	var facts Facts
	if policy.Mode != "public" || request.Resource.Tenant != "*" {
		if s.Provider == nil {
			return Decision{}, Facts{}, Document{}, ErrUnavailable
		}
		facts, err = s.Provider.Resolve(ctx)
		if err != nil {
			if errors.Is(err, ErrDenied) {
				return Decision{}, Facts{}, doc, ErrIdentityDenied
			}
			return Decision{}, Facts{}, Document{}, ErrUnavailable
		}
		if !facts.ValidUntil.After(time.Now()) {
			return Decision{}, Facts{}, doc, ErrIdentityDenied
		}
	}
	if selected != nil && policy.EntityType != "" {
		request.Selection = selected
		if len(*selected) == 0 {
			return Decision{}, Facts{}, doc, ErrSelectionRequired
		}
	}
	local, facts, err := s.evaluateSelected(ctx, request, doc, facts)
	if err != nil {
		if errors.Is(err, ErrUnavailable) {
			return Decision{}, Facts{}, Document{}, ErrUnavailable
		}
		if errors.Is(err, ErrIdentityDenied) || errors.Is(err, ErrSelectionDenied) {
			return Decision{}, Facts{}, doc, err
		}
		return Decision{}, Facts{}, doc, ErrDenied
	}
	if s.Decisions == nil || policy.Mode == "public" {
		return local, facts, doc, nil
	}
	remote, err := s.Decisions.Evaluate(ctx, request, doc, facts)
	if errors.Is(err, ErrDenied) {
		return Decision{}, Facts{}, doc, ErrDenied
	}
	if err != nil || ctx.Err() != nil {
		return Decision{}, Facts{}, Document{}, ErrUnavailable
	}
	if !facts.ValidUntil.After(time.Now()) {
		return Decision{}, Facts{}, doc, ErrDenied
	}
	decision, err := Intersect(local, remote)
	if err != nil {
		return Decision{}, Facts{}, doc, ErrDenied
	}
	return decision, facts, doc, nil
}

func (s *Service) Get(ctx context.Context, resource Resource) (Document, error) {
	doc, _, err := s.load(ctx, resource, "viewAccess")
	return doc, err
}

func (s *Service) Replace(ctx context.Context, candidate Document) (Document, error) {
	current, facts, err := s.load(ctx, candidate.Resource, "manageAccess")
	if err != nil {
		return Document{}, err
	}
	if current.Revision != candidate.Revision {
		return Document{}, ErrConflict
	}
	if len(candidate.Policies) == 0 {
		return Document{}, ErrDenied
	}
	for action, policy := range candidate.Policies {
		if err = ValidatePolicy(action, policy); err != nil {
			return Document{}, err
		}
	}
	if err = ctx.Err(); err != nil {
		return Document{}, err
	}
	return s.Store.Replace(ctx, candidate, current.Revision, facts.Subject)
}

func ValidatePolicy(action string, p Policy) error {
	if action == "" {
		return ErrDenied
	}
	switch p.Mode {
	case "public":
		if p.Rule != nil || p.EntityType != "" || len(p.RequiredScopes) != 0 {
			return ErrDenied
		}
		switch action {
		case "discover", "describe", "execute", "retrieve":
			return nil
		}
	case "protected":
		if p.Rule != nil && valid(*p.Rule, 0) && validScopeNames(p.RequiredScopes) {
			return nil
		}
	}
	return ErrDenied
}
