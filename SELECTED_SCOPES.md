# Explicit selected entity scopes

A host may configure `Service.SelectedScopes` as a trusted
`SelectedScopeProvider` when IAM evaluates effective scope for selected IDs.
This is an explicit authority choice: it replaces static entity-list bounds for
selected requests even when user-info contains empty or partial entity lists.
Leaving the provider unset preserves all existing static scope behavior.

Call `AuthorizeSelectionWithStatus(ctx, request, selected)` for execution.
The service reads one exact policy document and attaches the selection only if
that policy declares `EntityType`. For an unbounded ACL the selection is ignored;
mandatory entity-permission gates still receive and check the selection. Empty
selection on a bounded policy denies. Ordinary whole-resource authorization does
not invoke the provider or acquire remotely selected grants.

For a selected bounded policy, the service:

1. Checks original resource, tenant, identity lease, local ACL predicates and
   required OAuth scopes against the original verified facts.
2. Requires all selected IDs to have the policy's entity type, without duplicates.
3. Invokes the configured scope authority with the exact request/document/facts.
4. Requires a complete exact selected-set result and a live authority lease.
5. Reconfirms unchanged verified identity/facts, and shortens the returned facts'
   lease to the earliest remaining source/provider lease.

The provider never modifies `Facts.Entities` or `Facts.EntityGroups`. Local
entity-rule predicates therefore still need original authority facts; a returned
selected scope cannot satisfy an arbitrary entity predicate in the ACL. This
avoids converting a successful selected-ID check into a general authority list.

`oauth.EntityEvaluationScopeProvider` adapts an injected `gating.EntityPermissionProvider`
and `gating.PrincipalResolver`. Its
required `Permission` callback is a trusted host mapping of scope admission to a
named permission such as `read`. Action-specific mandatory gates independently
check permissions such as `write`. No permission name is inferred from a remote
window/report payload or from an ACL action name.

Core's `ActionAuthorizer` and the shared gate evaluator pass explicit selections
through this API. Core keeps a status-preserving compatibility fallback for its
older published authz dependency; that fallback uses the existing static scope
and checks every requested entity before execution. Remote selected scope needs
the updated shared module to be linked or published.

`ErrSelectionRequired` and `ErrSelectionDenied` retain denial semantics while
allowing gates to report `needsEntity` and `entityDenied`. Identity rejection and
provider outage remain distinct and fail closed.

For large entity populations, the host may configure its identity binding to
omit expanded entity grants and supply a selected-scope authority instead.
That binding must retain the identity service's original source lease; omitted
projection and permission caches cannot restart it. Response wire schemas and
projection options belong to that provider binding, outside this module.
