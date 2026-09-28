# Datly 1.0 authorization SDK

This module reuses Datly v1.0.1-0.20260928172836-5aad1bdd5494 and its native
component/runtime stack. The generic authorization model stays in the parent
`github.com/viant/authz` module.

| Datly SDK component | HTTP endpoint (POST) | MCP tool |
| --- | --- | --- |
| Authorization check | `/v1/authz/sdk/authorization.check` | `authz.sdk.authorization.check` |
| Read policy | `/v1/authz/sdk/policies.get` | `authz.sdk.policies.get` |
| Create policy | `/v1/authz/sdk/policies.create` | `authz.sdk.policies.create` |
| Replace policy | `/v1/authz/sdk/policies.replace` | `authz.sdk.policies.replace` |

All endpoints explicitly bind a verified JWT through Datly's `JwtClaim` codec.
The configured fact provider verifies its token independently and must return the
same subject. Provider/service capabilities are supplied by the host, never by
body fields. Check accepts resource/action/optional entity selection; create and
replace accept a policy document. The output contains the decision or document,
not the token or identity facts. Error responses omit private causes.

Reads allow authenticated callers in the same tenant. Create/replace are limited
to deployment-defined editor roles; an empty role list denies writes. The caller
supplies revision zero for creation and the current revision for replacement.

## Reuse in other projects

Import `github.com/viant/authz/datly/api` and provide `api.Services` and a trusted
JWT codec factory. `api.Registrations` uses Datly bootstrap to compile the declared
component holders; its base directory is this source module's configured path.
The embedding project adds those registrations to its own runtime and uses that
same runtime for HTTP and MCP. It can instead link/select the component packages
through Datly's ordinary Go bootstrap. Source/type/resource authority and named
connectors still must be available in the host.

Policy persistence uses the imported `policy/reader` and `policy/writer`
components. Their `/_authz/policy-store/*` routes are internal; public SDK calls
never accept arbitrary component targets. SQL storage supplies the `authz` named
connector. The host owns its database lifecycle. Studio maps its existing policy
database to that connector, preserving persisted documents and history.

## SQLite and MySQL

`schema.New("sqlite")` and `schema.New("mysql")` initialize
`resource_policy_heads` and append-only `resource_policy_revisions`. Both schemas
use the exact tenant/kind/id/version identity and retain created/updated audit
fields. Datly's writer applies head and history within one transaction; stale
revision or failed history writes do not advance the head. Resource SQL uses
portable identifiers and preserves Datly predicate/template string literals.

The initializer creates missing tables; it does not alter an existing incompatible
schema. `Store` implements the generic `authz.Store` and `authz.Creator` interfaces.

## Run

```sh
go build -o bin/authz ./cmd/authz
AUTHZ_DB_DSN='file:.data/authz.db?cache=shared' bin/authz \
  -base-dir . -driver sqlite \
  -issuer YOUR_TRUSTED_ISSUER -audience YOUR_TRUSTED_AUDIENCE \
  -public-key /path/to/public.pem -policy-editor-roles policy_admin
```

Use `-driver mysql` and a server-held `AUTHZ_DB_DSN` with `parseTime=true` for
MySQL. Defaults listen on HTTP `127.0.0.1:8085`, MCP `127.0.0.1:8095`. The host
uses dedicated signed fact tokens containing tenant, roles, exposures and
allowedEntities; a sign-in ID token without those grants does not invent them.
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
```

The MySQL test creates/drops its own isolated database and never changes the
local `ci_ads` database. HTTP and native MCP execution are tested against the same
four SDK registrations. Root model compatibility with agently-core is tested in
that consumer without bringing in Datly.

## License

Apache License 2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE).

This product includes software developed at Viant (http://viantinc.com/).
