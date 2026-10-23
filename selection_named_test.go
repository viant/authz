package authz

import (
	"context"
	"errors"
	"testing"
	"time"
)

func namedSelectorFixture(t *testing.T, mode string) (*Selector, namedFixtureStore, Resource, *selectionProvider, ResourceFamily) {
	t.Helper()
	store, named, assignment, facts := namedFixture()
	family := ResourceFamily{Kind: "report", ID: "overview", Tenant: "tenant"}
	mapping := SelectionDocument{Resource: family, Revision: 3, DefaultVersion: "main"}
	if mode == "override" {
		mapping.Overrides = []VersionOverride{{Version: "42", RequiredExposures: []string{"preview"}, Priority: 10}}
		facts.Exposures = []string{"preview"}
	}
	if mode == "revision" {
		mapping.DefaultVersion = ""
		mapping.Revisions = []RevisionSelection{{Version: "main", PolicyRevision: 9, Policy: assignment.Policies["*"]}}
	}
	for _, version := range []string{"main", "42"} {
		doc := cloneStaticDocument(assignment)
		doc.Resource = Resource{Kind: family.Kind, ID: family.ID, Tenant: family.Tenant, Version: version}
		doc.Revision = 9
		store[doc.Resource] = doc
	}
	mappings, err := NewStaticSelectionStore([]SelectionDocument{mapping})
	if err != nil {
		t.Fatal(err)
	}
	provider := &selectionProvider{facts: facts}
	return &Selector{Mappings: mappings, Service: &Service{Store: store, Provider: provider}}, store, named, provider, family
}

func TestSelectorNamedDefaultOverrideAndRevisionRecipients(t *testing.T) {
	for _, mode := range []string{"default", "override", "revision"} {
		t.Run(mode, func(t *testing.T) {
			selector, store, _, provider, family := namedSelectorFixture(t, mode)
			for _, action := range []string{"read", "execute"} {
				selected, err := selector.Authorize(context.Background(), SelectionRequest{Resource: family, Action: action})
				if err != nil {
					t.Fatalf("assigned recipient denied: %v", err)
				}
				want := "main"
				if mode == "override" {
					want = "42"
				}
				if selected.Resource.Version != want || selected.MappingRevision != 3 || selected.PolicyRevision != 9 {
					t.Fatalf("wrong exact revision: %+v", selected)
				}
				if store[selected.Resource].Policies["*"].Named == nil {
					t.Fatal("stored named assignment replaced by effective policy")
				}
			}
			if provider.calls != 2 {
				t.Fatalf("identity resolved %d times, want once per selection", provider.calls)
			}
			selected, raw, err := selector.FindPolicy(context.Background(), family)
			if err != nil || raw.Resource != selected.Resource || raw.Policies["*"].Named == nil {
				t.Fatalf("policy read lost raw assignment: %+v %v", raw, err)
			}
			provider.facts.MembershipGroups = nil
			provider.facts.Roles = []string{"Viant internal"} // Application roles cannot invent group membership.
			if _, err := selector.Authorize(context.Background(), SelectionRequest{Resource: family, Action: "read"}); !errors.Is(err, ErrDenied) {
				t.Fatalf("unassigned recipient allowed: %v", err)
			}
		})
	}
}

func TestSelectorNamedMissingAndMinimumRevisionDeny(t *testing.T) {
	for _, mode := range []string{"default", "override", "revision"} {
		for _, change := range []string{"missing", "minimum-revision", "archived", "exact-deny"} {
			t.Run(mode+"/"+change, func(t *testing.T) {
				selector, store, named, _, family := namedSelectorFixture(t, mode)
				switch change {
				case "missing":
					delete(store, named)
				case "minimum-revision":
					// Existing named head is valid, but below the reviewed minimum.
					for _, version := range []string{"main", "42"} {
						resource := Resource{Kind: family.Kind, ID: family.ID, Tenant: family.Tenant, Version: version}
						doc := store[resource]
						doc.Policies["*"].Named.Revision = 2
						store[resource] = doc
					}
					if mode == "revision" {
						mapping := selector.Mappings.(*StaticSelectionStore).documents[family]
						mapping.Revisions[0].Policy.Named.Revision = 2
					}
				case "archived":
					doc := store[named]
					doc.Policies[NamedDefinitionAction].Definition.Archived = true
					store[named] = doc
				case "exact-deny":
					doc := store[named]
					doc.Policies[NamedDefinitionAction].Definition.Policies["read"] = Policy{Mode: "deny"}
					store[named] = doc
				}
				if _, err := selector.Authorize(context.Background(), SelectionRequest{Resource: family, Action: "read"}); err == nil {
					t.Fatal("unavailable/unreviewed/denied named policy admitted")
				}
			})
		}
	}
}

type namedSelectionRemote struct {
	before func()
	seen   bool
	err    error
}

func (r *namedSelectionRemote) Evaluate(_ context.Context, request Request, doc Document, facts Facts) (Decision, error) {
	r.seen = true
	policy, _ := PolicyForAction(doc.Policies, request.Action)
	if policy.Named != nil || policy.Mode != "protected" {
		return Decision{}, errors.New("remote received unresolved named policy")
	}
	if r.before != nil {
		r.before()
	}
	if r.err != nil {
		return Decision{}, r.err
	}
	return Decision{}, nil
}

func TestSelectorNamedHeadFenceAndRemoteNarrowing(t *testing.T) {
	for _, mode := range []string{"default", "override", "revision"} {
		for _, change := range []string{"named-head", "selected-named-head", "remote-deny"} {
			t.Run(mode+"/"+change, func(t *testing.T) {
				selector, store, named, _, family := namedSelectorFixture(t, mode)
				if change == "selected-named-head" && mode != "revision" {
					return
				}
				if change == "selected-named-head" {
					// Make the selected resource inline: only the revision selector retains a
					// named dependency, so a final fence must retain selection dependencies too.
					resource := Resource{Kind: family.Kind, ID: family.ID, Tenant: family.Tenant, Version: "main"}
					doc := store[resource]
					doc.Policies = map[string]Policy{"read": {Mode: "protected", Rule: &Rule{Kind: "group", Value: "Viant internal"}}}
					store[resource] = doc
				}
				remote := &namedSelectionRemote{}
				if change == "remote-deny" {
					remote.err = ErrDenied
				} else {
					remote.before = func() { doc := store[named]; doc.Revision++; store[named] = doc }
				}
				selector.Service.Decisions = remote
				if _, err := selector.Authorize(context.Background(), SelectionRequest{Resource: family, Action: "read"}); !errors.Is(err, ErrDenied) {
					t.Fatalf("changed named authority or remote denial admitted: %v", err)
				}
				if !remote.seen {
					t.Fatal("named policy bypassed remote authority")
				}
			})
		}
	}
}

func TestSelectorNamedEntityAndScopeRequirementsRemainMandatory(t *testing.T) {
	selector, store, named, provider, family := namedSelectorFixture(t, "default")
	definition := store[named]
	definition.Policies[NamedDefinitionAction].Definition.Policies["*"] = Policy{Mode: "protected", Rule: &Rule{Kind: "group", Value: "Viant internal"}, EntityType: "advertiser", RequiredScopes: []string{"report:read"}}
	store[named] = definition
	provider.facts.EntityGroups = EntityGroups{"advertiser": {"101", "102"}}
	selected := []Entity{{Type: "advertiser", ID: "101"}}
	request := SelectionRequest{Resource: family, Action: "read", Selection: &selected}
	if _, err := selector.Authorize(context.Background(), request); !errors.Is(err, ErrDenied) {
		t.Fatalf("missing required scope admitted: %v", err)
	}
	provider.facts.GrantedScopes = []string{"report:read"}
	got, err := selector.Authorize(context.Background(), request)
	if err != nil || !got.Decision.Bounded || len(got.Decision.Entities) != 1 || got.Decision.Entities[0] != selected[0] {
		t.Fatalf("entity intersection lost: %+v %v", got, err)
	}
	selected[0].ID = "foreign"
	if _, err := selector.Authorize(context.Background(), request); !errors.Is(err, ErrDenied) {
		t.Fatalf("foreign entity allowed: %v", err)
	}
	empty := []Entity{}
	request.Selection = &empty
	if _, err := selector.Authorize(context.Background(), request); !errors.Is(err, ErrDenied) {
		t.Fatalf("explicit empty selection widened: %v", err)
	}
	if _, _, err := selector.FindPolicy(context.Background(), family); !errors.Is(err, ErrDenied) {
		t.Fatalf("bounded decision exposed policy: %v", err)
	}
}

func TestSelectorNamedMappingRevisionAndIdentityFences(t *testing.T) {
	for _, which := range []string{"revision", "identity", "expired", "cancelled"} {
		t.Run(which, func(t *testing.T) {
			selector, store, _, provider, family := namedSelectorFixture(t, "revision")
			switch which {
			case "revision":
				resource := Resource{Kind: family.Kind, ID: family.ID, Tenant: family.Tenant, Version: "main"}
				doc := store[resource]
				doc.Revision++
				store[resource] = doc
			case "identity":
				provider.facts.Tenant = "other"
			case "expired":
				provider.facts.ValidUntil = time.Now().Add(-time.Second)
			}
			ctx := context.Background()
			if which == "cancelled" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			if _, err := selector.Authorize(ctx, SelectionRequest{Resource: family, Action: "read"}); err == nil {
				t.Fatalf("%s fence lost", which)
			}
		})
	}
}
