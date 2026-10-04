package gating

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/viant/authz"
)

const maxGateFileBytes = 8 << 20

type gateFileRevision struct {
	Document RequirementsDocument `json:"document"`
	Actor    string               `json:"actor"`
	At       time.Time            `json:"at"`
}

type gateFileRecord struct {
	Resource authz.Resource       `json:"resource"`
	Action   string               `json:"action"`
	Current  RequirementsDocument `json:"current"`
	History  []gateFileRevision   `json:"history"`
}

// FileStore is a durable single-process gate registry. The configured binding
// list is its allowlist; a retired file cannot reactivate a removed binding.
// Updates replace one complete history file atomically under an in-process
// CAS lock. Clustered hosts should supply their own transactional writer.
type FileStore struct {
	root    string
	allowed map[string]bool
	mu      sync.Mutex
}

var _ RequirementsStore = (*FileStore)(nil)
var _ RequirementsWriter = (*FileStore)(nil)
var _ ActorRequirementsWriter = (*FileStore)(nil)

func NewFileStore(root string, bindings []Binding) (*FileStore, error) {
	if root == "" || strings.TrimSpace(root) != root {
		return nil, fmt.Errorf("gate store root is required")
	}
	if _, err := NewStaticStore(bindings); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(root, 0700); err != nil {
		return nil, err
	}
	info, err := os.Stat(root)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0022 != 0 {
		return nil, fmt.Errorf("gate store directory must not be group/world writable")
	}
	store := &FileStore{root: root, allowed: make(map[string]bool, len(bindings))}
	for _, binding := range bindings {
		key := gateFileKey(binding.Resource, binding.Action)
		store.allowed[key] = true
		path := store.filePath(key)
		if _, err := os.Stat(path); err == nil {
			if _, err := store.read(path, binding.Resource, binding.Action); err != nil {
				return nil, fmt.Errorf("read persisted gate %s/%s: %w", binding.Resource.ID, binding.Action, err)
			}
			continue
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		doc := cloneDocument(binding.Document)
		record := gateFileRecord{Resource: binding.Resource, Action: binding.Action, Current: doc,
			History: []gateFileRevision{{Document: doc, Actor: "bootstrap", At: time.Now().UTC()}}}
		if err := store.write(path, record); err != nil {
			return nil, err
		}
	}
	return store, nil
}

func gateFileKey(resource authz.Resource, action string) string {
	raw, _ := json.Marshal(struct {
		Resource authz.Resource `json:"resource"`
		Action   string         `json:"action"`
	}{resource, action})
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func (s *FileStore) filePath(key string) string { return filepath.Join(s.root, key+".json") }

func (s *FileStore) GetRequirements(ctx context.Context, resource authz.Resource, action string) (RequirementsDocument, error) {
	if s == nil || ctx == nil || ctx.Err() != nil {
		return RequirementsDocument{}, ErrUnavailable
	}
	key := gateFileKey(resource, action)
	if !s.allowed[key] {
		return RequirementsDocument{}, authz.ErrDenied
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	record, err := s.read(s.filePath(key), resource, action)
	if err != nil {
		return RequirementsDocument{}, err
	}
	return cloneDocument(record.Current), nil
}

func (s *FileStore) ReplaceRequirements(ctx context.Context, resource authz.Resource, action, expected string, requirements Requirements) (RequirementsDocument, error) {
	return s.ReplaceRequirementsAs(ctx, resource, action, expected, requirements, "system")
}

func (s *FileStore) ReplaceRequirementsAs(ctx context.Context, resource authz.Resource, action, expected string, requirements Requirements, actor string) (RequirementsDocument, error) {
	if s == nil || ctx == nil || ctx.Err() != nil {
		return RequirementsDocument{}, ErrUnavailable
	}
	if expected == "" || actor == "" || strings.TrimSpace(actor) != actor || !validRequirements(requirements) {
		return RequirementsDocument{}, authz.ErrDenied
	}
	key := gateFileKey(resource, action)
	if !s.allowed[key] {
		return RequirementsDocument{}, authz.ErrDenied
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	path := s.filePath(key)
	record, err := s.read(path, resource, action)
	if err != nil {
		return RequirementsDocument{}, err
	}
	if record.Current.Revision != expected {
		return RequirementsDocument{}, authz.ErrConflict
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return RequirementsDocument{}, ErrUnavailable
	}
	updated := RequirementsDocument{Revision: hex.EncodeToString(nonce[:]), Requirements: cloneRequirements(requirements)}
	record.Current = updated
	record.History = append(record.History, gateFileRevision{Document: updated, Actor: actor, At: time.Now().UTC()})
	if err := ctx.Err(); err != nil {
		return RequirementsDocument{}, ErrUnavailable
	}
	if err := s.write(path, record); err != nil {
		return RequirementsDocument{}, ErrUnavailable
	}
	return cloneDocument(updated), nil
}

func (s *FileStore) read(path string, resource authz.Resource, action string) (gateFileRecord, error) {
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return gateFileRecord{}, authz.ErrDenied
	}
	if err != nil || info.Size() > maxGateFileBytes {
		return gateFileRecord{}, ErrUnavailable
	}
	raw, err := os.ReadFile(path)
	if err != nil || len(raw) > maxGateFileBytes {
		return gateFileRecord{}, ErrUnavailable
	}
	var record gateFileRecord
	if json.Unmarshal(raw, &record) != nil || record.Resource != resource || record.Action != action || record.Current.Revision == "" || !validRequirements(record.Current.Requirements) || len(record.History) == 0 {
		return gateFileRecord{}, ErrUnavailable
	}
	seen := map[string]bool{}
	for _, revision := range record.History {
		if revision.Document.Revision == "" || seen[revision.Document.Revision] || !validRequirements(revision.Document.Requirements) || revision.Actor == "" || revision.At.IsZero() {
			return gateFileRecord{}, ErrUnavailable
		}
		seen[revision.Document.Revision] = true
	}
	if !reflect.DeepEqual(record.History[len(record.History)-1].Document, record.Current) {
		return gateFileRecord{}, ErrUnavailable
	}
	return record, nil
}

func (s *FileStore) write(path string, record gateFileRecord) error {
	raw, err := json.Marshal(record)
	if err != nil || len(raw) > maxGateFileBytes {
		return ErrUnavailable
	}
	temp, err := os.CreateTemp(s.root, ".gate-*")
	if err != nil {
		return err
	}
	defer os.Remove(temp.Name())
	if _, err = temp.Write(raw); err != nil {
		temp.Close()
		return err
	}
	if err = temp.Sync(); err != nil {
		temp.Close()
		return err
	}
	if err = temp.Close(); err != nil {
		return err
	}
	if err = os.Rename(temp.Name(), path); err != nil {
		return err
	}
	dir, err := os.Open(s.root)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
