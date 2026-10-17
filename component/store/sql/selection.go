package access

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"reflect"

	acl "github.com/viant/authz"
	policygraph "github.com/viant/authz/component/policy/graph"
	dexec "github.com/viant/datly/exec"
	"github.com/viant/datly/spec"
)

// RevisionSelections loads resource -> revisions -> one current policy document
// through Datly. Action identifies the policy to evaluate on each revision.
type RevisionSelections struct {
	Store  *Store
	Action string
}

var _ acl.SelectionStore = (*RevisionSelections)(nil)

func (s *RevisionSelections) GetSelection(ctx context.Context, family acl.ResourceFamily) (acl.SelectionDocument, error) {
	if s == nil || s.Store == nil || s.Action == "" || ctx == nil || ctx.Err() != nil {
		return acl.SelectionDocument{}, acl.ErrUnavailable
	}
	if family.Tenant == "" || family.Kind == "" || family.ID == "" {
		return acl.SelectionDocument{}, acl.ErrDenied
	}
	s.Store.mu.Lock()
	invalid := s.Store.closed || (s.Store.transaction != nil && (s.Store.Invoker != nil || s.Store.DB != s.Store.transactionDB))
	s.Store.mu.Unlock()
	if invalid {
		return acl.SelectionDocument{}, acl.ErrDenied
	}
	input := &policygraph.Input{TenantId: family.Tenant, ResourceKind: family.Kind, ResourceId: family.ID, Has: &policygraph.InputHas{TenantId: true, ResourceKind: true, ResourceId: true}}
	target := dexec.ComponentTarget{Component: spec.Key{Kind: spec.KindComponent, Scope: reflect.TypeFor[policygraph.GraphComponent]().PkgPath(), Name: "graph"}, Route: spec.RouteRef{Method: "GET", Path: "/_authz/policy-store/graph"}}
	var value any
	var err error
	if s.Store.Invoker != nil {
		value, err = s.Store.Invoker.InvokeComponent(ctx, dexec.ComponentRequest{Target: target, Input: input})
	} else {
		runtime, buildErr := s.Store.components()
		if buildErr != nil {
			return acl.SelectionDocument{}, buildErr
		}
		value, err = runtime.InvokeComponent(ctx, dexec.ComponentRequest{Target: s.Store.graph, Input: input})
	}
	if err != nil {
		return acl.SelectionDocument{}, err
	}
	output, ok := value.(*policygraph.Output)
	if !ok || len(output.Resources) != 1 || output.Resources[0] == nil {
		return acl.SelectionDocument{}, acl.ErrDenied
	}
	row := output.Resources[0]
	if row.TenantId != family.Tenant || row.ResourceKind != family.Kind || row.ResourceId != family.ID {
		return acl.SelectionDocument{}, acl.ErrDenied
	}
	document := acl.SelectionDocument{Resource: family, Action: s.Action}
	for _, revision := range row.Revisions {
		if revision == nil || revision.Revision == nil || revision.Policy == nil || revision.Policy.Revision == nil || *revision.Policy.Revision != *revision.Revision {
			return acl.SelectionDocument{}, acl.ErrDenied
		}
		var policies map[string]acl.Policy
		if err := json.Unmarshal(revision.Policy.PoliciesJson, &policies); err != nil {
			return acl.SelectionDocument{}, errors.New("invalid revision policy document")
		}
		policy, ok := acl.PolicyForAction(policies, s.Action)
		if !ok {
			continue
		}
		document.Revisions = append(document.Revisions, acl.RevisionSelection{Version: revision.ResourceVersion, Policy: policy, PolicyRevision: int64(*revision.Policy.Revision)})
	}
	if len(document.Revisions) == 0 {
		return acl.SelectionDocument{}, acl.ErrDenied
	}
	// Include current policy head revisions in the mapping identity. Graph rows
	// and decisions are not retained across requests; revocation is read afresh.
	snapshot, err := json.Marshal(row)
	if err != nil {
		return acl.SelectionDocument{}, err
	}
	digest := sha256.Sum256(snapshot)
	document.Revision = int64(binary.BigEndian.Uint64(digest[:8]) & 0x7fffffffffffffff)
	if document.Revision == 0 {
		document.Revision = 1
	}
	compiled, err := acl.NewStaticSelectionStore([]acl.SelectionDocument{document})
	if err != nil {
		return acl.SelectionDocument{}, err
	}
	return compiled.GetSelection(ctx, family)
}
