# authz

Generic Go authorization for resources, principals, roles, feature exposures and
allowed entities. The core evaluates policies and returns decisions with mandatory
entity bounds. Applications supply trusted identity providers and enforce those
bounds before returning data.

## Modules

- `github.com/viant/authz`: resource/fact/policy types, evaluation, scope
  intersection, policy services and administration. The core package depends only
  on the Go standard library and supports Go 1.25.5, including agently-core.
- `github.com/viant/authz/oauth`: optional verified JWT and user-info providers.
- `github.com/viant/authz/datly`: optional Datly 1.0 SDK endpoints, reusable
  policy reader/writer components, SQLite/MySQL persistence and a runnable host.

Datly and Studio are not dependencies of the core. Studio and agently-core now
import these types directly; there are no compatibility type aliases.

## Authorization

A resource is identified by kind, ID, tenant and version. `Service.Authorize`
checks one action against its stored policy using server-resolved `Facts`.
Policies support subject, role, exposure, entity, all and any conditions.
`Decision.Bounded` means callers must enforce the returned entity IDs. An empty
or incompatible intersection denies access. Client-supplied filters cannot widen
server-owned entity grants. Reading a policy does not authorize its resource.

`Facts.EntityGroups` is the canonical `allowedEntities` map. Entity IDs preserve
strings and full-width integers; they are never rounded through float64. Providers
must verify the credential and supply subject, tenant, issuer and an expiry lease.
The library does not trust roles or entity IDs from operation request bodies.

## Policy administration

`Administration.Get` currently permits every authenticated caller within its
tenant. Anonymous access is disabled. This interprets “read everyone” as all
signed-in callers; anonymous-read behavior remains a product choice.

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

## Datly SDK

The components are the SDK endpoints. HTTP and MCP use the same input/output
contracts, handlers, trusted capabilities and policy rules. Other Datly projects
can import the components into their bootstrap/runtime; exposure and providers
remain the host's configuration. See [Datly integration](datly/README.md).

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
cd datly
go test ./...
go build -o bin/authz ./cmd/authz
```

The extracted reader/writer components have SQLite persistence/transaction tests
and an authorized local MySQL integration test. Native HTTP/MCP tests cover reads,
configured-role creation/modification, forged role input, bounded decisions and
revision conflicts. MySQL integration uses `AUTHZ_MYSQL_TEST_DSN` and creates a
unique disposable database; do not point it at a production server.

During extraction the consumer repositories use explicit local module mappings
for this unpublished module. These are development wiring, not compatibility
implementations. Publish/version both modules and replace local mappings with
real release pins before deployment from an independent checkout.

## License

Apache License 2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE).

This product includes software developed at Viant (http://viantinc.com/).
