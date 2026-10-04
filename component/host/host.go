// Package host assembles one writable Datly-backed authz authority for an
// embedding application. It neither owns the SQL connection nor chooses an IdP.
package host

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/viant/authz"
	"github.com/viant/authz/component/api"
	gatesql "github.com/viant/authz/component/gate/sqlstore"
	"github.com/viant/authz/component/schema"
	policystore "github.com/viant/authz/component/store/sql"
	"github.com/viant/authz/gating"
	"github.com/viant/authz/oauth"
)

type Identity interface {
	authz.Provider
	gating.PrincipalResolver
}

type Config struct {
	DB                *sql.DB
	Driver            string
	Identity          Identity
	Policies          []authz.Document
	Requirements      []gating.Binding
	EditorRoles       []string
	PolicyReplaceRule string // editor-roles (default) or manage-access
	Choices           gating.ChoicesProvider
	Directory         authz.Directory             // optional trusted policy-editor choice provider
	PolicyChoices     []authz.PolicyChoiceBinding // exact server-owned choices when no external directory is supplied
	Entities          gating.EntityPermissionProvider
	Entitlements      map[string]gating.EntitlementProvider
}

type Host struct {
	Services    *api.Services
	PolicyStore *policystore.Store
	GateStore   *gatesql.Store
}

func New(ctx context.Context, config Config) (*Host, error) {
	if ctx == nil || ctx.Err() != nil || config.DB == nil || config.Identity == nil {
		return nil, fmt.Errorf("writable authorization host requires a database and verified identity")
	}
	mode := config.PolicyReplaceRule
	if mode == "" {
		mode = "editor-roles"
	}
	if mode != "editor-roles" && mode != "manage-access" {
		return nil, fmt.Errorf("policy replacement rule must be editor-roles or manage-access")
	}
	if config.Directory != nil && len(config.PolicyChoices) > 0 {
		return nil, fmt.Errorf("choose one policy editor directory source")
	}
	if _, err := authz.NewStaticStore(config.Policies); err != nil {
		return nil, fmt.Errorf("policy seed: %w", err)
	}
	for _, seed := range config.Policies {
		if seed.Revision != 1 {
			return nil, fmt.Errorf("policy bootstrap revision must be 1")
		}
	}
	if _, err := gating.NewStaticStore(config.Requirements); err != nil {
		return nil, fmt.Errorf("gate seed: %w", err)
	}
	entitlements := make(map[string]gating.EntitlementProvider, len(config.Entitlements))
	for ref, provider := range config.Entitlements {
		if ref == "" || provider == nil {
			return nil, fmt.Errorf("invalid entitlement provider registration")
		}
		entitlements[ref] = provider
	}
	for _, binding := range config.Requirements {
		if requirement := binding.Document.Requirements.Entitlement; requirement != nil && entitlements[requirement.ProviderRef] == nil {
			return nil, fmt.Errorf("entitlement providerRef %q is not registered", requirement.ProviderRef)
		}
	}
	migration, err := schema.New(config.Driver)
	if err != nil {
		return nil, err
	}
	if err := migration.Up(ctx, config.DB); err != nil {
		return nil, err
	}
	policyStore := &policystore.Store{DB: config.DB}
	for _, seed := range config.Policies {
		if _, err := policyStore.Get(ctx, seed.Resource); err == nil {
			continue // Stored edits take precedence over bootstrap configuration.
		} else if !errors.Is(err, sql.ErrNoRows) {
			policyStore.Close(ctx)
			return nil, fmt.Errorf("load policy seed: %w", err)
		}
		if _, err := policyStore.Provision(ctx, seed, "bootstrap"); err != nil {
			if _, readErr := policyStore.Get(ctx, seed.Resource); readErr == nil {
				continue // Another host bootstrapped this resource concurrently.
			}
			policyStore.Close(ctx)
			return nil, fmt.Errorf("provision policy seed: %w", err)
		}
	}
	gateStore, err := gatesql.New(ctx, config.DB, config.Requirements)
	if err != nil {
		policyStore.Close(ctx)
		return nil, err
	}
	acl := &authz.Service{Store: policyStore, Provider: config.Identity, Directory: config.Directory}
	if len(config.PolicyChoices) > 0 {
		directory, err := authz.NewStaticDirectory(config.PolicyChoices, acl)
		if err != nil {
			_ = policyStore.Close(ctx)
			return nil, fmt.Errorf("policy editor choices: %w", err)
		}
		acl.Directory = directory
	}
	entities := config.Entities
	if entities == nil {
		entities = &oauth.FactEntityPermissionProvider{Principals: config.Identity}
	}
	policies := &authz.Administration{Store: policyStore, Provider: config.Identity, EditorRoles: append([]string(nil), config.EditorRoles...)}
	if mode == "manage-access" {
		policies.Management = acl
	}
	services := &api.Services{
		Authorization: acl,
		Policies:      policies,
		Gates:         &gating.Evaluator{ACL: acl, Principals: config.Identity, Requirements: gateStore, Entities: entities, Entitlements: entitlements},
		Requirements:  &gating.Administration{ACL: acl, Store: gateStore, Writer: gateStore, Choices: config.Choices},
	}
	return &Host{Services: services, PolicyStore: policyStore, GateStore: gateStore}, nil
}

// Close releases only the Datly policy component runtime. The caller owns DB.
func (h *Host) Close(ctx context.Context) error {
	if h == nil || h.PolicyStore == nil {
		return nil
	}
	return h.PolicyStore.Close(ctx)
}
