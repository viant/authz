# Authz Components

HTTP and MCP authorization components, SQLite/MySQL policy persistence, and an
embeddable server built on Datly 1.0. The generic authorization model lives in
the parent [`github.com/viant/authz` module](../README.md).

The host configures identity verification, resource/action catalogs, management
roles, and storage. No application-specific identity provider or privileged role
is built in. Dependency versions are recorded in [go.mod](go.mod).

## Endpoints

| Authz component | HTTP endpoint (POST) | MCP tool |
| --- | --- | --- |
| Authorized authoring catalog | `/v1/authz/sdk/catalog.list` | `authz.sdk.catalog.list` |
| Authorization check | `/v1/authz/sdk/authorization.check` | `authz.sdk.authorization.check` |
| Read policy | `/v1/authz/sdk/policies.get` | `authz.sdk.policies.get` |
| Policy editor context | `/v1/authz/sdk/policies.context` | `authz.sdk.policies.context` |
| Create policy | `/v1/authz/sdk/policies.create` | `authz.sdk.policies.create` |
| Replace policy | `/v1/authz/sdk/policies.replace` | `authz.sdk.policies.replace` |
| Check mandatory gates | `/v1/authz/sdk/gates.check` | `authz.sdk.gates.check` |
| Read gate requirements | `/v1/authz/sdk/gates.get` | `authz.sdk.gates.get` |
| Gate editor context | `/v1/authz/sdk/gates.context` | `authz.sdk.gates.context` |
| Replace gate requirements | `/v1/authz/sdk/gates.replace` | `authz.sdk.gates.replace` |

All endpoints explicitly bind a verified JWT through Datly's `JwtClaim` codec.
The configured fact provider verifies its token independently and must return the
same subject. Provider/service capabilities are supplied by the host, never by
body fields. Check accepts resource/action/optional entity selection; create and
replace accept a policy document. The output contains the decision or document,
not the token or identity facts. Error responses omit private causes.
`authorization.check` returns 403 for a policy denial, 401 for a rejected
verified identity and 503 for an unavailable authority. The shared policy
editor uses this operation only for a current-principal, saved-policy check.
`catalog.list` accepts a host-owned `api.CatalogProvider`, filters each entry
through current unbounded `viewAccess`, and verifies one account-bound principal
and policy revision throughout the scan. An absent provider or authority outage
returns 503 without partial entries. The returned action lists are editor
choices, not grants; writes still enforce management authority and revision CAS.
Embedding hosts can call `api.ListAuthorizedCatalog` for a local editor route
using the same filtering and consistency rules as the MCP tool.
Gate checks consume exact resource/action/selected-entity bindings and return a
versioned decision envelope. The service generates each gate-check request ID;
the caller cannot supply its provider correlation ID. Gate reads and
replacements require the host to register `gating.Administration`. Replacements
compare the current requirement revision and independently check unbounded
`manageAccess`. A host that does not
register gate services receives an unavailable error for these optional tools.
The standalone command loads exact gate bindings from
`-gate-requirements /path/to/gates.json`. That trusted JSON array seeds current
requirements and limits which resource/action pairs are active. Without a
store directory, it is read only. Add `-gate-store-dir /path/to/gate-state` to
persist gate edits as atomic, versioned history files. `gates.replace` then
requires an unbounded `manageAccess` policy, compares the current revision and
records the verified actor. Retiring a binding from the requirements file
disables access to its old persisted record. This file store is for one server
process; clustered hosts supply their own transactional requirements store.
Use `-gate-sql-store` instead of `-gate-store-dir` to persist the same exact
allowlisted gate bindings in the configured SQLite or MySQL policy database.
The SQL store compares and updates the head revision and appends the verified
actor's history row in one transaction, so multiple hosts may share it. The
schema initializer creates `authz_gate_heads` and `authz_gate_revisions`.
The gate SQL package has a SQLite concurrency/rollback suite and an optional
MySQL integration test enabled with `AUTHZ_TEST_MYSQL_DSN`.
The command registers no entitlement provider, so requirements naming one fail
closed. Embedding hosts supply those providers explicitly when needed.
An optional `-gate-choices /path/to/choices.json` file supplies the editor's
trusted exposure, role, entity-permission, selection-parameter and entitlement
options. It is an array of exact `{resource, action, choices}` bindings and
must cover every configured gate binding. Choices are display options, never
authorization facts or an edit grant. The SDK still checks `viewAccess` and
`manageAccess` for each request.
The editor context returns `canManage` from the current policy and choices from
a host-owned provider; callers cannot submit their own role or feature catalog.

Policy document reads require a current unbounded `viewAccess` decision against
the exact immutable revision returned in that response;
the generic Administration API can still serve hosts with their own read rule.
Create/replace are limited to deployment-defined management authority. The standalone host defaults to
`-policy-replace-rule editor-roles`, using `-policy-editor-roles` for creation
and replacement. `-policy-replace-rule manage-access` uses the current resource's
unbounded `manageAccess` policy and binds its revision to replacement CAS;
creation still requires an editor role because the new resource has no policy
yet. The policy editor context reports the selected replacement rule, and the
write endpoint checks
it again. The caller supplies revision zero for creation and the current
revision for replacement.

## Reuse in other projects

Import `github.com/viant/authz/component/api` and provide `api.Services` and a trusted
JWT codec factory. `api.LinkedRegistrations` builds the ten declared routes
from linked typed component metadata without a source checkout. The embedding
project adds those registrations to its own runtime and uses that same runtime
for HTTP and MCP. `api.Registrations` remains available for source-validated
bootstrap when the module checkout is present. The host still supplies a codec,
identity, services and named connectors.

`github.com/viant/authz/component/host.New` assembles one writable authority from a
caller-owned SQL connection and a host-supplied verified identity. It runs the
policy/gate schema initializer, seeds missing version-one policies and exact
gate bindings without overwriting later edits, and returns the same policy and
gate services for SDK operations and runtime decisions. Its `Close` releases
only the Datly component runtime; the caller closes the database. An embedding
host still configures its IdP, application resource/action catalog and HTTP or
MCP transport.
For policy-editor options, it can inject an IdP-backed `authz.Directory` or
exact server-owned `PolicyChoices` bindings. The latter rechecks `viewAccess`
and current verified facts before returning choices. Without either, the
editor context offers only choices present in the current verified principal.

Policy persistence uses the imported `policy/reader` and `policy/writer`
components. Their `/_authz/policy-store/*` routes are internal; public SDK calls
never accept arbitrary component targets. SQL storage supplies the `authz` named
connector. The host owns its database lifecycle. Studio maps its existing policy
database to that connector, preserving persisted documents and history.

## SQLite and MySQL

`schema.New("sqlite")` and `schema.New("mysql")` initialize
`resource_policies` and append-only `resource_policy_revisions`. Both schemas
use the exact tenant/kind/id/version identity and retain created/updated audit
fields. Datly's writer applies head and history within one transaction; stale
revision or failed history writes do not advance the head. Resource SQL uses
portable identifiers and preserves Datly predicate/template string literals.

The initializer creates missing tables; it does not alter an existing incompatible
schema. To upgrade an existing database that uses `resource_policy_heads`, stop
writers and take your normal backup, then run this SQLite/MySQL statement before
starting the updated application:

```sql
ALTER TABLE resource_policy_heads RENAME TO resource_policies;
```

The schema initializer does not migrate existing tables and returns a migration
required error if the legacy table is present. `Store` implements the generic `authz.Store` and `authz.Creator` interfaces.

## Run

Requires Go 1.25.8 or later. Run these commands from the `component` directory of
this repository. This SDK is a separate Go module; building or testing the
parent module does not include it. The current checkout uses the parent module
through a relative `replace` directive; consumers need matching published
versions or an explicit development workspace.

```sh
go build -o bin/authz ./cmd/authz
AUTHZ_DB_DSN='file:.data/authz.db?cache=shared' bin/authz \
  -driver sqlite \
  -issuer YOUR_TRUSTED_ISSUER -audience YOUR_TRUSTED_AUDIENCE \
  -public-key /path/to/public.pem -policy-editor-roles policy_admin
```

For account-bound gate checks, add `-gate-requirements /path/to/gates.json` and
issue a dedicated signed fact token with an explicit `accountId` claim. The
trusted issuer binds roles and exposures to that account. `tenant` remains the
independent policy ownership key. A token without `accountId` can still use
legacy ACL checks but cannot pass a gate check. For example:

```json
[{"resource":{"kind":"window","id":"overview","version":"1","tenant":"owner"},"action":"open","document":{"revision":"v1","requirements":{"schemaVersion":1,"requiredExposures":["feature"]}}}]
```

To enable checked gate edits for this allowlist, pass both
`-gate-requirements /path/to/gates.json` and
`-gate-store-dir /path/to/gate-state`. The gate file is a bootstrap seed;
subsequent revisions live in the store directory.

Use `-driver mysql` and a server-held `AUTHZ_DB_DSN` with `parseTime=true` for
MySQL. Defaults listen on HTTP `127.0.0.1:8085`, MCP `127.0.0.1:8095`. The host
uses dedicated signed fact tokens containing tenant, roles, exposures and
allowedEntities. The token's verified `scope` claim supplies optional
`GrantedScopes` for policies with mandatory `requiredScopes`; a sign-in ID token
without those grants does not invent them.
The executable uses linked route registration by default. Pass `-base-dir` to
validate against an on-disk source module when desired.
Production authentication configuration and issuer key rotation remain deployment
responsibilities. The example role name is not a built-in privilege.

```json
{"resource":{"kind":"component","id":"forecasting","version":"1","tenant":"one"},"action":"execute"}
```

Use a current MCP client for discovery/calls; the selected protocol has required
request metadata and routing headers. No LLM chooses or enforces the authorization
operation.

## Tests

```sh
go test ./...
AUTHZ_MYSQL_TEST_DSN='LOCAL_TEST_SERVER_DSN' go test ./store/sql -run TestMySQLPolicyStorage -count=1
AUTHZ_TEST_MYSQL_DSN='LOCAL_TEST_DATABASE_DSN' go test ./host -run TestWritableHostMySQLSharesManagedPolicyAndGate -count=1
```

The policy-storage MySQL test creates/drops its own isolated database. HTTP and native MCP execution are tested against the same
ten SDK registrations. Root model compatibility with agently-core is tested in
that consumer without bringing in Datly.
The host test uses the database named by its DSN; run it only against an isolated
test database. Both MySQL tests passed with MySQL 8.4 under its default SQL mode.

## License

Apache License 2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE).

This product includes software developed at Viant (http://viantinc.com/).
