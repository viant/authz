# Authz

Authz is a Go authorization library for resources, principals, roles, feature
entitlements and entity permissions. Embed it in a service to evaluate policies
and return decisions with mandatory entity bounds. Your application supplies
trusted identity facts and enforces the result before returning protected data.

## Why Authz

- **One authorization model** for reports, tools, agents, UI resources and data APIs.
- **Explicit data boundaries**: entity grants constrain access even when a role or
  another branch of a policy matches.
- **Host-owned trust**: configure your identity provider, tenant mapping, policy
  store and administration roles for your application.
- **Small core**: the root package uses only the Go standard library. OAuth and
  Datly integration are available when your host needs them.

## Features

- Public and protected action policies with subject, role, exposure, entity,
  `all` and `any` rules
- Mandatory OAuth scope checks and typed entity bounds outside `any` branches
- Exact per-entity permissions without implicit inheritance
- Immutable policy revisions and atomic replacement with conflict detection
- Verified JWT and user-info providers with configurable identity leases
- Account-bound gates, entitlement checks and an optional durable file registry
- Datly HTTP/MCP components, SQLite/MySQL persistence and a runnable host

## Packages and modules

| Import path | Purpose | Go module |
| --- | --- | --- |
| `github.com/viant/authz` | Core types, evaluation, scope intersection, policy services and administration | Core |
| `github.com/viant/authz/oauth` | Optional verified JWT and user-info providers | Core |
| `github.com/viant/authz/gating` | Mandatory gates, versioned decisions, administration and an optional single-process file registry | Core |
| `github.com/viant/authz/component` | Authz Components, persistence and host | Separate nested module |

`oauth` and `gating` are packages in the core module; `component` has its own
`go.mod`. Datly and Studio are not dependencies of the core. Studio and
agently-core consume the shared core types directly.

## Installation

The core module requires **Go 1.25.5 or newer**; the optional component module
requires **Go 1.25.8 or newer**. To build and test a source checkout:

```sh
git clone https://github.com/viant/authz.git
cd authz
go test ./...
```

Import `github.com/viant/authz` in your Go application. Consumer integration
currently uses local module mappings while releases are prepared; see
[local development](#verification-and-local-development) before integrating
from an independent checkout.

## Quick start

This runnable example shows a role policy constrained to the caller's allowed
projects. Save it as `main.go` in a temporary directory and run `go run` with its
absolute file path from the checkout. The facts are a fixture for this example;
a service must obtain them from a trusted `Provider` after verifying credentials.

```go
package main

import (
    "fmt"
    "time"

    "github.com/viant/authz"
)

func main() {
    resource := authz.Resource{
        Kind: "report", ID: "usage", Version: "1", Tenant: "team-a",
    }
    policies := map[string]authz.Policy{
        "execute": {
            Mode: "protected",
            Rule: &authz.Rule{Kind: "role", Value: "analyst"},
            EntityType: "project",
        },
    }
    facts := authz.Facts{
        Subject: "alice", Tenant: "team-a", Issuer: "https://idp.example.com",
        Roles: []string{"analyst"},
        EntityGroups: authz.EntityGroups{"project": {"101", "102"}},
        ValidUntil: time.Now().Add(time.Minute),
    }
    decision, err := authz.Evaluate(authz.Request{
        Resource: resource, Action: "execute",
    }, policies, facts, time.Now())
    if err != nil {
        panic(err) // Deny the operation on any authorization error.
    }

    // Example enforcement: release only rows within the returned bounds.
    allowed := make(map[authz.Entity]bool)
    for _, entity := range decision.Entities {
        allowed[entity] = true
    }
    for _, projectID := range []string{"101", "102", "999"} {
        if decision.Bounded && !allowed[authz.Entity{Type: "project", ID: projectID}] {
            continue
        }
        fmt.Println("allowed project:", projectID)
    }
}
```

Output:

```text
allowed project: 101
allowed project: 102
```

For stored policies and request-scoped identity, use `Service.Authorize` with
`Store` and `Provider`. `NewStaticStore` serves immutable policy documents;
mutable administration needs a writable store. Push entity constraints into the
data query when possible, and reject bounded decisions if your operation cannot
enforce them.

## Security boundary

Authz evaluates authorization; the host verifies credentials, selects the
resource and tenant, resolves trusted facts, and enforces decisions. Never copy
roles, entity grants or identity from an operation request into `Facts`. Treat
any authorization error as a denied operation. Reading a policy or hiding a UI
control does not authorize execution. A successful bounded decision grants only
the returned entities.

The optional OAuth adapters use host-configured issuers, audiences, keys,
user-info endpoints and tenant mappings. The account adapter is optional; Authz
has no built-in Viant identity deployment or product-specific account model.

## Authorization

A resource is identified by kind, ID, tenant and version. `Service.Authorize`
checks one action against its stored policy using server-resolved `Facts`.
Policies support subject, role, exposure, entity, all and any conditions.
Protected policies may also declare `requiredScopes`, a list of OAuth scope
names checked together with the rule and outside its `any` branches. Every
required scope must be present in `Facts.GrantedScopes`; absent scopes deny.
These credential grants are distinct from the entity bounds in `Decision`.
`Decision.Bounded` means callers must enforce the returned entity IDs. An empty
or incompatible intersection denies access. Client-supplied filters cannot widen
server-owned entity grants. Reading a policy does not authorize its resource.
`Service.AuthorizeWithStatus` retains the immutable revision and distinguishes
explicit denial or a missing policy from provider/store outages for gate hosts;
the original `Authorize` methods retain their existing compatibility behavior.

`Facts.EntityGroups` is the canonical `allowedEntities` map. Entity IDs preserve
strings and full-width integers; they are never rounded through float64. Providers
must verify the credential and supply subject, tenant, issuer and an expiry lease.
The library does not trust roles or entity IDs from operation request bodies.
The signed OAuth fact-token provider reads granted scopes from its verified
space-delimited `scope` claim. The ID-token user-info provider does not promote
the response's displayed scopes to access-token authority.

For account-bound hosts, `oauth.NewAccountUserInfo` requires an explicit
verified-account-to-tenant resolver and a positive `FactLease`. The host chooses
issuer, audience, keys, user-info endpoint and fact freshness; no account or
product name is built in. Its observed identity revision binds decisions to
one verified credential and the current user-info authority facts, but does
not claim to be an IAM revocation revision. The
identity service's own authority cache and revocation policy remain material
when choosing the lease.
`oauth.NewConfiguredAccountUserInfo` accepts the same boundaries as typed
configuration, including a trusted JWKS URL, refresh interval, user-info URL
and exactly one explicit tenant mapping: per-account IDs or one shared policy
namespace for all verified accounts. The shared namespace does not merge
account roles, exposures or entity permissions. Unknown key IDs cannot force per-request
JWKS fetches; key rotation becomes visible at the configured refresh lease.

## Permissions per entity

`Facts.EntityPermissions` is a list of `EntityPermission` records, with type, ID
and a list of opaque permissions beside each ID. It is not a map or an entity
hierarchy. `HasPermission` checks exact identity and permission membership; a
permission named `admin` does not imply a global role, ancestor inheritance or
cross-namespace access. Business logic defines the meaning of permission names.
Signed OAuth facts can carry this list; clients cannot supply verified grants.
An optional `oauth.NewEntityRoleResolver` projects only explicitly mapped
permissions on the exact selected entity into UI resource-role labels. Global
user roles and unrelated entity permissions are not copied into that list.

```json
[{"type":"advertiser","id":"123","permissions":["read"]},
 {"type":"advertiser","id":"456","permissions":["read","edit"]}]
```

## Policy administration

`Administration.Get` currently permits every authenticated caller within its
tenant. Anonymous access is disabled. Policy reads are available to signed-in callers in the same tenant; execution
permissions are evaluated separately.

`Administration.Create` and `Replace` require membership in the configured
`EditorRoles`. No editor roles are enabled by default. The server owns this list;
a policy document or client request cannot change it. Creation cannot overwrite
an existing resource. Replacements compare an expected revision atomically in
storage. A policy's execute/discover rules remain independent of administration.

```go
administration := &authz.Administration{
    Store: store,
    Provider: verifiedProvider,
    EditorRoles: []string{"policy_admin"}, // deployment-defined example
}
```

## Authz Components

The components are the SDK endpoints. HTTP and MCP use the same input/output
contracts, handlers, trusted capabilities and policy rules. Other Datly projects
can import the components into their bootstrap/runtime; exposure and providers
remain the host's configuration. See [Authz Components](component/README.md).

## Agently

agently-core's `service/policy.AuthzResolver` consumes the shared core types and
a host-configured resource mapping. It never treats request context metadata as
identity facts. Its whole-resource consumer rejects bounded decisions because it
cannot enforce a row/entity scope. This adapter does not change existing policy
configuration or automatically enable authorization on an agent.

## Verification and local development

```sh
go test ./...
go test -race ./...
cd component
go test ./...
go build -o bin/authz ./cmd/authz
```

The extracted reader/writer components have SQLite persistence/transaction tests
and an authorized local MySQL integration test. Native HTTP/MCP tests cover reads,
configured-role creation/modification, forged role input, bounded decisions and
revision conflicts. MySQL integration uses `AUTHZ_MYSQL_TEST_DSN` and creates a
unique disposable database; do not point it at a production server.

Consumer repositories currently use explicit local module mappings for source
development. Publish/version both Go modules and replace those mappings with
release pins before deployment from an independent checkout. Root `go test ./...`
does not traverse the nested component module, so run its checks separately.

## License

Apache License 2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE).

This product includes software developed at Viant (http://viantinc.com/).
