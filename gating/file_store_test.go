package gating

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/viant/authz"
)

func TestFileStorePersistsAuditedGateCASAndRetiresRemovedBindings(t *testing.T) {
	ctx := context.Background()
	resource := authz.Resource{Kind: "window", ID: "orders", Version: "1", Tenant: "tenant"}
	binding := Binding{Resource: resource, Action: "execute", Document: RequirementsDocument{Revision: "r1", Requirements: Requirements{SchemaVersion: 1}}}
	root := t.TempDir()
	store, err := NewFileStore(root, []Binding{binding})
	if err != nil {
		t.Fatal(err)
	}
	principal := &principalSource{value: Principal{Facts: authz.Facts{Subject: "alice", Issuer: "issuer", Tenant: "tenant", Roles: []string{"administrator"}, ValidUntil: time.Now().Add(time.Hour)}, AccountID: "account", IdentityRevision: "identity"}}
	rule := &authz.Rule{Kind: "role", Value: "administrator"}
	acl := &authz.Service{Provider: principal, Store: policyStore{authz.Document{Resource: resource, Revision: 1, Policies: map[string]authz.Policy{"viewAccess": {Mode: "protected", Rule: rule}, "manageAccess": {Mode: "protected", Rule: rule}}}}}
	admin := &Administration{ACL: acl, Store: store, Writer: store}
	updated, err := admin.Replace(ctx, resource, "execute", "r1", Requirements{SchemaVersion: 1, RequiredExposures: []string{"FEATURE"}})
	if err != nil || updated.Revision == "" || updated.Revision == "r1" {
		t.Fatalf("replace=%+v err=%v", updated, err)
	}
	if _, err := admin.Replace(ctx, resource, "execute", "r1", Requirements{SchemaVersion: 1}); !errors.Is(err, authz.ErrConflict) {
		t.Fatalf("stale replacement=%v", err)
	}
	loaded, err := store.GetRequirements(ctx, resource, "execute")
	if err != nil || loaded.Revision != updated.Revision || loaded.Requirements.RequiredExposures[0] != "FEATURE" {
		t.Fatalf("loaded=%+v err=%v", loaded, err)
	}
	loaded.Requirements.RequiredExposures[0] = "forged"
	opened, err := NewFileStore(root, []Binding{binding})
	if err != nil {
		t.Fatal(err)
	}
	again, err := opened.GetRequirements(ctx, resource, "execute")
	if err != nil || again.Requirements.RequiredExposures[0] != "FEATURE" {
		t.Fatalf("reopened=%+v err=%v", again, err)
	}
	raw, err := os.ReadFile(store.filePath(gateFileKey(resource, "execute")))
	if err != nil {
		t.Fatal(err)
	}
	var record gateFileRecord
	if err := json.Unmarshal(raw, &record); err != nil || len(record.History) != 2 || record.History[1].Actor != "alice" {
		t.Fatalf("audit history=%+v err=%v", record.History, err)
	}
	retired, err := NewFileStore(root, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := retired.GetRequirements(ctx, resource, "execute"); !errors.Is(err, authz.ErrDenied) {
		t.Fatalf("retired binding active: %v", err)
	}
}

func TestFileStoreRejectsConcurrentStaleRevisionAndCorruption(t *testing.T) {
	ctx := context.Background()
	resource := authz.Resource{Kind: "window", ID: "../same-name", Version: "1", Tenant: "tenant"}
	binding := Binding{Resource: resource, Action: "open", Document: RequirementsDocument{Revision: "r1", Requirements: Requirements{SchemaVersion: 1}}}
	store, err := NewFileStore(t.TempDir(), []Binding{binding})
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := store.ReplaceRequirementsAs(ctx, resource, "open", "r1", Requirements{SchemaVersion: 1}, "alice")
			results <- err
		}()
	}
	wg.Wait()
	close(results)
	allows, conflicts := 0, 0
	for err := range results {
		switch {
		case err == nil:
			allows++
		case errors.Is(err, authz.ErrConflict):
			conflicts++
		default:
			t.Fatalf("unexpected write error: %v", err)
		}
	}
	if allows != 1 || conflicts != 1 {
		t.Fatalf("concurrent CAS: allow=%d conflict=%d", allows, conflicts)
	}
	path := store.filePath(gateFileKey(resource, "open"))
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var record gateFileRecord
	if err := json.Unmarshal(raw, &record); err != nil {
		t.Fatal(err)
	}
	record.History[len(record.History)-1].Actor = ""
	tampered, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, tampered, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetRequirements(ctx, resource, "open"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("missing audit actor accepted: %v", err)
	}
	if err := os.WriteFile(path, []byte(`{}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetRequirements(ctx, resource, "open"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("corrupt file accepted: %v", err)
	}
}
