// Package sqlstore persists generic gate requirements with transactional CAS.
// The host supplies a database and an exact configured binding allowlist.
package sqlstore

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/viant/authz"
	"github.com/viant/authz/gating"
)

type key struct {
	resource authz.Resource
	action   string
}

// Store reads current requirements and commits revisions in one SQL database.
// Unlike gating.FileStore, separate server processes may share this store.
type Store struct {
	DB      *sql.DB
	allowed map[string]key
}

var _ gating.RequirementsStore = (*Store)(nil)
var _ gating.RequirementsWriter = (*Store)(nil)
var _ gating.ActorRequirementsWriter = (*Store)(nil)

func New(ctx context.Context, db *sql.DB, bindings []gating.Binding) (*Store, error) {
	if ctx == nil || ctx.Err() != nil || db == nil {
		return nil, gating.ErrUnavailable
	}
	if _, err := gating.NewStaticStore(bindings); err != nil {
		return nil, err
	}
	store := &Store{DB: db, allowed: make(map[string]key, len(bindings))}
	for _, binding := range bindings {
		store.allowed[bindingKey(binding.Resource, binding.Action)] = key{binding.Resource, binding.Action}
	}
	for _, binding := range bindings {
		if _, err := store.GetRequirements(ctx, binding.Resource, binding.Action); err == nil {
			continue
		} else if !errors.Is(err, authz.ErrDenied) {
			return nil, err
		}
		if err := store.bootstrap(ctx, binding); err != nil {
			return nil, err
		}
	}
	return store, nil
}

func bindingKey(resource authz.Resource, action string) string {
	raw, _ := json.Marshal(struct {
		Resource authz.Resource `json:"resource"`
		Action   string         `json:"action"`
	}{resource, action})
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func (s *Store) enabled(resource authz.Resource, action string) (string, bool) {
	if s == nil {
		return "", false
	}
	id := bindingKey(resource, action)
	wanted, ok := s.allowed[id]
	return id, ok && wanted.resource == resource && wanted.action == action
}

func (s *Store) GetRequirements(ctx context.Context, resource authz.Resource, action string) (gating.RequirementsDocument, error) {
	if s == nil || s.DB == nil || ctx == nil || ctx.Err() != nil {
		return gating.RequirementsDocument{}, gating.ErrUnavailable
	}
	id, allowed := s.enabled(resource, action)
	if !allowed {
		return gating.RequirementsDocument{}, authz.ErrDenied
	}
	var resourceJSON, storedAction, revision, requirementsJSON string
	err := s.DB.QueryRowContext(ctx, "SELECT resource_json, action_name, revision, requirements_json FROM authz_gate_heads WHERE binding_key = ?", id).Scan(&resourceJSON, &storedAction, &revision, &requirementsJSON)
	if errors.Is(err, sql.ErrNoRows) {
		return gating.RequirementsDocument{}, authz.ErrDenied
	}
	if err != nil {
		return gating.RequirementsDocument{}, gating.ErrUnavailable
	}
	doc, err := decodeHead(resourceJSON, storedAction, revision, requirementsJSON, resource, action)
	if err != nil {
		return gating.RequirementsDocument{}, err
	}
	var historicalJSON, actor string
	if err := s.DB.QueryRowContext(ctx, "SELECT requirements_json, actor_id FROM authz_gate_revisions WHERE binding_key = ? AND revision = ?", id, revision).Scan(&historicalJSON, &actor); err != nil || !sameRequirementsJSON(historicalJSON, requirementsJSON) || actor == "" {
		return gating.RequirementsDocument{}, gating.ErrUnavailable
	}
	return doc, nil
}

func sameRequirementsJSON(left, right string) bool {
	if left == right {
		return true
	}
	var a, b gating.Requirements
	return json.Unmarshal([]byte(left), &a) == nil && json.Unmarshal([]byte(right), &b) == nil && reflect.DeepEqual(a, b)
}

func decodeHead(resourceJSON, storedAction, revision, requirementsJSON string, resource authz.Resource, action string) (gating.RequirementsDocument, error) {
	var storedResource authz.Resource
	var requirements gating.Requirements
	if json.Unmarshal([]byte(resourceJSON), &storedResource) != nil || storedResource != resource || storedAction != action || revision == "" || json.Unmarshal([]byte(requirementsJSON), &requirements) != nil {
		return gating.RequirementsDocument{}, gating.ErrUnavailable
	}
	doc := gating.RequirementsDocument{Revision: revision, Requirements: requirements}
	if _, err := gating.NewStaticStore([]gating.Binding{{Resource: resource, Action: action, Document: doc}}); err != nil {
		return gating.RequirementsDocument{}, gating.ErrUnavailable
	}
	return doc, nil
}

func (s *Store) bootstrap(ctx context.Context, binding gating.Binding) error {
	id := bindingKey(binding.Resource, binding.Action)
	resourceJSON, err := json.Marshal(binding.Resource)
	if err != nil {
		return gating.ErrUnavailable
	}
	requirementsJSON, err := json.Marshal(binding.Document.Requirements)
	if err != nil {
		return gating.ErrUnavailable
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return gating.ErrUnavailable
	}
	defer tx.Rollback()
	now := time.Now().UTC()
	_, err = tx.ExecContext(ctx, "INSERT INTO authz_gate_heads (binding_key, resource_json, action_name, revision, requirements_json, updated_at) VALUES (?, ?, ?, ?, ?, ?)", id, string(resourceJSON), binding.Action, binding.Document.Revision, string(requirementsJSON), now)
	if err != nil {
		// Another host may have bootstrapped the same exact binding. Re-read
		// after rollback to distinguish that race from a database failure.
		_ = tx.Rollback()
		if _, readErr := s.GetRequirements(ctx, binding.Resource, binding.Action); readErr == nil {
			return nil
		}
		return gating.ErrUnavailable
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO authz_gate_revisions (binding_key, revision, requirements_json, actor_id, occurred_at) VALUES (?, ?, ?, ?, ?)", id, binding.Document.Revision, string(requirementsJSON), "bootstrap", now); err != nil {
		return gating.ErrUnavailable
	}
	if tx.Commit() != nil {
		return gating.ErrUnavailable
	}
	return nil
}

func (s *Store) ReplaceRequirements(ctx context.Context, resource authz.Resource, action, expected string, requirements gating.Requirements) (gating.RequirementsDocument, error) {
	return s.ReplaceRequirementsAs(ctx, resource, action, expected, requirements, "system")
}

func (s *Store) ReplaceRequirementsAs(ctx context.Context, resource authz.Resource, action, expected string, requirements gating.Requirements, actor string) (gating.RequirementsDocument, error) {
	if s == nil || s.DB == nil || ctx == nil || ctx.Err() != nil {
		return gating.RequirementsDocument{}, gating.ErrUnavailable
	}
	id, allowed := s.enabled(resource, action)
	if !allowed || expected == "" || actor == "" || strings.TrimSpace(actor) != actor {
		return gating.RequirementsDocument{}, authz.ErrDenied
	}
	if _, err := gating.NewStaticStore([]gating.Binding{{Resource: resource, Action: action, Document: gating.RequirementsDocument{Revision: "validate", Requirements: requirements}}}); err != nil {
		return gating.RequirementsDocument{}, authz.ErrDenied
	}
	current, err := s.GetRequirements(ctx, resource, action)
	if err != nil {
		return gating.RequirementsDocument{}, err
	}
	if current.Revision != expected {
		return gating.RequirementsDocument{}, authz.ErrConflict
	}
	currentJSON, err := json.Marshal(current.Requirements)
	if err != nil {
		return gating.RequirementsDocument{}, gating.ErrUnavailable
	}
	requirementsJSON, err := json.Marshal(requirements)
	if err != nil {
		return gating.RequirementsDocument{}, gating.ErrUnavailable
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return gating.RequirementsDocument{}, gating.ErrUnavailable
	}
	nextRevision := hex.EncodeToString(nonce[:])
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return gating.RequirementsDocument{}, gating.ErrUnavailable
	}
	defer tx.Rollback()
	now := time.Now().UTC()
	result, err := tx.ExecContext(ctx, "UPDATE authz_gate_heads SET revision = ?, requirements_json = ?, updated_at = ? WHERE binding_key = ? AND revision = ?", nextRevision, string(requirementsJSON), now, id, expected)
	if err != nil {
		return gating.RequirementsDocument{}, gating.ErrUnavailable
	}
	changed, err := result.RowsAffected()
	if err != nil || changed != 1 {
		return gating.RequirementsDocument{}, authz.ErrConflict
	}
	var resourceJSON, storedAction string
	if err := tx.QueryRowContext(ctx, "SELECT resource_json, action_name FROM authz_gate_heads WHERE binding_key = ?", id).Scan(&resourceJSON, &storedAction); err != nil || storedAction != action {
		return gating.RequirementsDocument{}, gating.ErrUnavailable
	}
	var storedResource authz.Resource
	if json.Unmarshal([]byte(resourceJSON), &storedResource) != nil || storedResource != resource {
		return gating.RequirementsDocument{}, gating.ErrUnavailable
	}
	var historicalJSON, historicalActor string
	if err := tx.QueryRowContext(ctx, "SELECT requirements_json, actor_id FROM authz_gate_revisions WHERE binding_key = ? AND revision = ?", id, expected).Scan(&historicalJSON, &historicalActor); err != nil || !sameRequirementsJSON(historicalJSON, string(currentJSON)) || historicalActor == "" {
		return gating.RequirementsDocument{}, gating.ErrUnavailable
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO authz_gate_revisions (binding_key, revision, requirements_json, actor_id, occurred_at) VALUES (?, ?, ?, ?, ?)", id, nextRevision, string(requirementsJSON), actor, now); err != nil {
		return gating.RequirementsDocument{}, gating.ErrUnavailable
	}
	if ctx.Err() != nil || tx.Commit() != nil {
		return gating.RequirementsDocument{}, gating.ErrUnavailable
	}
	var detached gating.Requirements
	if json.Unmarshal(requirementsJSON, &detached) != nil {
		return gating.RequirementsDocument{}, fmt.Errorf("decode committed requirements: %w", gating.ErrUnavailable)
	}
	return gating.RequirementsDocument{Revision: nextRevision, Requirements: detached}, nil
}
