# Configured HTTP authorization providers

`NewHTTPProviders` composes the existing OAuth/OIDC JWT verifier and deployment-owned JWKS with an HTTP userinfo authority. It returns the existing authz/gating interfaces; it imports no application, vendor, or host binary.

Configuration is server-owned. `kind` is `oidc-userinfo`. Issuer, audience, allowed asymmetric algorithms, endpoints, tenant mappings, and response paths are explicit. Endpoints require HTTPS (loopback HTTP is permitted for tests), redirects never receive bearer credentials, responses are bounded, duplicate JSON keys are rejected, and source/host/token expirations are intersected. No new audience is inferred or injected.

A neutral mapping might use:

```json
{
  "kind": "oidc-userinfo",
  "issuer": "https://identity.example",
  "audience": "configured-application",
  "algorithms": ["RS256"],
  "userInfoUrl": "https://identity.example/userinfo",
  "jwksUrl": "https://identity.example/jwks",
  "jwksRefreshInterval": "1m",
  "factLease": "1h",
  "userInfoCacheTTL": "15m",
  "userInfoCacheMaxEntries": 1024,
  "tenantByAccount": {"team-a": "workspace-a"},
  "mapping": {
    "subject": "sub",
    "accountId": "accountId",
    "jwtAccountId": "accountId",
    "roles": "roles",
    "exposures": "features"
  }
}
```

The signed JWT establishes subject and any configured user/account claim. Userinfo must match those signed identifiers before it can supply roles, features, permissions, or explicitly selected display fields. Opaque string IDs are supported. Field paths are literal object paths, not expressions. Missing configured fields deny access rather than inventing values.

`NativeWindowIdentity` validates JWT/JWKS and signed account/tenant only: no userinfo calls and no role/feature/entity authority. A signed account mapping is required for that identity-only operation. Protected authorization uses `Identity.ResolvePrincipal` and validated userinfo. Account display projection reconciles before and after reads through the same profile cache.

Userinfo profiles are cached in process for fifteen minutes by default. `userInfoCacheTTL` accepts zero through fifteen minutes; `0s` disables caching and retains strict fresh scope-finish reconciliation. `userInfoCacheMaxEntries` defaults to 1024 (maximum 65536); concurrent misses for one identity share one request. Entries and concurrent requests are bounded. Failed refreshes are never cached and never release stale profiles. Each returned profile is deeply copied.

Cache identity includes the configured provider/mapping, verified canonical issuer and subject, signed account/user, resolved tenant, and credential scope/client/token class. A signed account mapping is required when caching is enabled. Every hit locally verifies the JWT and its signed identity, so renewed valid tokens can reuse the same profile without using bearer text as the identity key. Expiry is the earliest of the configured cache TTL, identity `factLease` (default and maximum one hour), JWT expiry, and provider-asserted lease. A short original token or provider lease can therefore require an earlier refresh. Role/profile revocations become visible at that expiry; this policy intentionally permits retained profile facts until then.

Decision/metadata scopes retain their original deadline. Enabled-cache scope finish revalidates the held credential and profile deadline without forcing another userinfo request. Closed snapshots cannot be reused. Execution and writes must use the returned `WithoutDecision`/`WithoutMetadataRead` context; those paths still use the same global userinfo cache. Business permission decisions are not cached: producer authorization and HTTP evaluation run for each operation.

The optional HTTP evaluation adapter sends only server-assembled canonical selection/account requirements. Request/response paths and account entitlement requirement mappings are operator configuration. It verifies issuer, subject, user (when configured), account, exact selected IDs, exact requested permission, source revision and time bounds, then refreshes the original principal before releasing a decision. Account and entity response envelopes cannot be mixed. Account requirements do not expand an empty entity selection.

`cacheTTL` bounds the remote decision lease; this implementation intentionally does not retain decisions across requests. `maxEntries` is retained only for compatibility with existing operator configuration; no cache or capacity enforcement is implemented. Existing source leases are never renewed by local reads. A configured source-clock uncertainty subtracts from source deadlines instead of extending them. Existing `StaticAuthorizationConfig` policy and requirement checks still own admission.

Tests use synthetic keys/HTTP endpoints and domain-neutral document requirements. They cover deployed-style nested response mapping, zero-userinfo native identity, account/subject/user binding, issuer/audience rejection before credential forwarding, stale/future source leases, scoped role revocation, exact selection, mixed response rejection, and redirect protection. No real credentials or production endpoints are used.

Evaluation endpoints accept their own explicit `sourceClockSkew` (zero to five seconds). Omission keeps strict time validation. Configure each endpoint independently; identity tolerance is not inherited. Tolerance shortens the returned source/freshness deadline and never revives an expired evaluation or extends the held identity lease.

`CopyDecision(requestContext, scopedContext)` carries only the provider's opaque active decision marker while preserving the caller's request values. The bearer must match exactly; missing, foreign, canceled, expired, closed, conflicting, and metadata-only scopes fail. Copies share the original lease and closure. Use separate read phases and finish the PRE phase before dispatch; create a fresh POST scope before result release. The helper does not establish a cross-request authorization cache.
