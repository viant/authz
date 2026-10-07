package authz

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// ResourceFamily identifies a logical resource before selecting its version.
// Publication endpoints and concrete runtime instances remain host-owned.
type ResourceFamily struct {
	Kind   string `json:"kind"`
	ID     string `json:"id"`
	Tenant string `json:"tenant"`
}

// VersionOverride matches when all exposures are present. Larger Priority wins.
// Priorities must be unique so overlapping grants select deterministically.
type VersionOverride struct {
	Version           string   `json:"version"`
	RequiredExposures []string `json:"requiredExposures"`
	Priority          int      `json:"priority"`
}

type SelectionDocument struct {
	Resource       ResourceFamily    `json:"resource"`
	Revision       int64             `json:"revision"`
	DefaultVersion string            `json:"defaultVersion"`
	Overrides      []VersionOverride `json:"overrides,omitempty"`
}

// SelectionStore returns a current, host-owned mapping. Its revision describes
// the mapping, independently of the selected resource's policy revision.
type SelectionStore interface {
	GetSelection(context.Context, ResourceFamily) (SelectionDocument, error)
}

type StaticSelectionStore struct {
	documents map[ResourceFamily]SelectionDocument
}

func NewStaticSelectionStore(documents []SelectionDocument) (*StaticSelectionStore, error) {
	result := &StaticSelectionStore{documents: map[ResourceFamily]SelectionDocument{}}
	for _, doc := range documents {
		if err := validateSelection(doc); err != nil {
			return nil, err
		}
		if _, exists := result.documents[doc.Resource]; exists {
			return nil, fmt.Errorf("duplicate resource selection")
		}
		doc = cloneSelection(doc)
		sort.Slice(doc.Overrides, func(i, j int) bool { return doc.Overrides[i].Priority > doc.Overrides[j].Priority })
		result.documents[doc.Resource] = doc
	}
	return result, nil
}
func (s *StaticSelectionStore) GetSelection(ctx context.Context, resource ResourceFamily) (SelectionDocument, error) {
	if s == nil || ctx == nil || ctx.Err() != nil {
		return SelectionDocument{}, ErrUnavailable
	}
	doc, ok := s.documents[resource]
	if !ok {
		return SelectionDocument{}, ErrDenied
	}
	return cloneSelection(doc), nil
}
func cloneSelection(doc SelectionDocument) SelectionDocument {
	doc.Overrides = append([]VersionOverride(nil), doc.Overrides...)
	for i := range doc.Overrides {
		doc.Overrides[i].RequiredExposures = append([]string(nil), doc.Overrides[i].RequiredExposures...)
	}
	return doc
}
func validateSelection(doc SelectionDocument) error {
	clean := func(s string) bool { return s != "" && strings.TrimSpace(s) == s }
	if !clean(doc.Resource.Kind) || !clean(doc.Resource.ID) || !clean(doc.Resource.Tenant) || !clean(doc.DefaultVersion) || doc.Revision < 1 {
		return fmt.Errorf("invalid resource selection")
	}
	priorities := map[int]bool{}
	for _, override := range doc.Overrides {
		if !clean(override.Version) || override.Version == doc.DefaultVersion || len(override.RequiredExposures) == 0 || priorities[override.Priority] {
			return fmt.Errorf("invalid or ambiguous version override")
		}
		priorities[override.Priority] = true
		seen := map[string]bool{}
		for _, exposure := range override.RequiredExposures {
			if !clean(exposure) || seen[exposure] {
				return fmt.Errorf("invalid override exposures")
			}
			seen[exposure] = true
		}
	}
	return nil
}

type SelectionRequest struct {
	Resource  ResourceFamily
	Action    string
	Selection *[]Entity
}

type SelectedResource struct {
	Resource        Resource `json:"resource"`
	MappingRevision int64    `json:"mappingRevision"`
	PolicyRevision  int64    `json:"policyRevision"`
	Decision        Decision `json:"decision"`
}

// Selector chooses a version and authorizes that exact resource. A mapping
// never grants resource access. No fallback occurs after denial or an outage.
// Hosts use this same resolver for discovery and execution, and must enforce
// returned entity bounds. MCP routing and session pinning are host concerns.
type Selector struct {
	Mappings SelectionStore
	Service  *Service
}

func (s *Selector) Authorize(ctx context.Context, request SelectionRequest) (SelectedResource, error) {
	selected, _, err := s.resolve(ctx, request, false)
	return selected, err
}

// FindPolicy returns the selected version's current policy document only after
// an unbounded viewAccess decision against that same document and identity.
// Execution permission does not imply policy inspection permission.
func (s *Selector) FindPolicy(ctx context.Context, resource ResourceFamily) (SelectedResource, Document, error) {
	return s.resolve(ctx, SelectionRequest{Resource: resource, Action: "viewAccess"}, true)
}

func (s *Selector) resolve(ctx context.Context, request SelectionRequest, policyRead bool) (SelectedResource, Document, error) {
	if s == nil || s.Mappings == nil || s.Service == nil || s.Service.Store == nil || ctx == nil || ctx.Err() != nil {
		return SelectedResource{}, Document{}, ErrUnavailable
	}
	if request.Action == "" {
		return SelectedResource{}, Document{}, ErrDenied
	}
	mapping, err := s.Mappings.GetSelection(ctx, request.Resource)
	if err != nil {
		return SelectedResource{}, Document{}, selectionError(err)
	}
	if mapping.Resource != request.Resource || validateSelection(mapping) != nil {
		return SelectedResource{}, Document{}, ErrDenied
	}
	var facts Facts
	resolved := false
	resolveFacts := func() error {
		if resolved {
			return nil
		}
		if s.Service.Provider == nil {
			return ErrUnavailable
		}
		var err error
		facts, err = s.Service.Provider.Resolve(ctx)
		if err != nil {
			if errors.Is(err, ErrDenied) {
				return ErrIdentityDenied
			}
			return ErrUnavailable
		}
		resolved = true
		if ctx.Err() != nil {
			return ErrUnavailable
		}
		if facts.Subject == "" || facts.Issuer == "" || facts.Tenant == "" || !facts.ValidUntil.After(time.Now()) {
			return ErrIdentityDenied
		}
		return nil
	}
	version := mapping.DefaultVersion
	if len(mapping.Overrides) > 0 {
		if err := resolveFacts(); err != nil {
			return SelectedResource{}, Document{}, err
		}
		if facts.Subject == "" || facts.Issuer == "" || facts.Tenant == "" || !facts.ValidUntil.After(time.Now()) || (request.Resource.Tenant != "*" && facts.Tenant != request.Resource.Tenant) {
			return SelectedResource{}, Document{}, ErrIdentityDenied
		}
		exposures := map[string]bool{}
		for _, item := range facts.Exposures {
			exposures[item] = true
		}
		matched := false
		priority := 0
		for _, override := range mapping.Overrides {
			allowed := true
			for _, required := range override.RequiredExposures {
				if !exposures[required] {
					allowed = false
					break
				}
			}
			if allowed && (!matched || override.Priority > priority) {
				version = override.Version
				priority = override.Priority
				matched = true
			}
		}
	}
	resource := Resource{Kind: request.Resource.Kind, ID: request.Resource.ID, Tenant: request.Resource.Tenant, Version: version}
	doc, err := s.Service.Store.Get(ctx, resource)
	if err != nil {
		return SelectedResource{}, Document{}, selectionError(err)
	}
	if doc.Resource != resource || doc.Revision < 1 {
		return SelectedResource{}, Document{}, ErrDenied
	}
	policy, ok := doc.Policies[request.Action]
	if !ok {
		return SelectedResource{}, Document{}, ErrDenied
	}
	if policy.Mode != "public" || resource.Tenant != "*" {
		if err := resolveFacts(); err != nil {
			return SelectedResource{}, Document{}, err
		}
	}
	if resolved && !facts.ValidUntil.After(time.Now()) {
		return SelectedResource{}, Document{}, ErrIdentityDenied
	}
	decision, err := s.Service.evaluate(ctx, Request{Resource: resource, Action: request.Action, Selection: request.Selection}, doc, facts)
	if err != nil {
		return SelectedResource{}, Document{}, err
	}
	if policyRead && decision.Bounded {
		return SelectedResource{}, Document{}, ErrDenied
	}
	selected := SelectedResource{Resource: resource, MappingRevision: mapping.Revision, PolicyRevision: doc.Revision, Decision: decision}
	return selected, cloneStaticDocument(doc), nil
}
func selectionError(err error) error {
	if errors.Is(err, ErrDenied) || errors.Is(err, sql.ErrNoRows) {
		return ErrDenied
	}
	return ErrUnavailable
}
