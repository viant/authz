# Fresh Authz policy schema

`github.com/viant/authz/component/schema` owns the canonical DDL for
`resource_policies` and `resource_policy_revisions`. Consumers create these
tables on an empty database with `CreatePolicies(ctx, db, driver)` or compose
`PolicyDDL(driver)` into their own fresh schema. `New(driver).Up(ctx, db)` also
creates the complete Authz schema, including gate tables.

The initializer is not a migration. It does not rename legacy tables, infer
missing immutable history, copy consumer-specific namespace columns, alter key
types, backfill audit metadata, or create a policy version ledger. An
application that previously stored policies in a different schema must not use
this initializer as a conversion step.

The head key is the full `(tenant_id, resource_kind, resource_id,
resource_version)` tuple. Immutable history adds `revision` to that key.
MySQL stores key parts as full `VARBINARY` values (512, 256, 800, and 256 bytes)
so case and trailing spaces remain significant without prefix indexes. SQLite
uses the canonical text columns and complete composite primary keys. Namespace
ownership is consumer metadata and is stored in a separate consumer-owned
association table.

Fresh-schema tests verify empty SQLite creation, idempotent `CREATE IF NOT
EXISTS` behavior, full key constraints, exact text matching, and MySQL DDL
shape. Database-specific bootstrap execution belongs to the application that
owns the target schema. An opt-in MySQL empty-schema check accepts only a
database on `127.0.0.1:23309` whose name starts with `authz_schema_test`, via
`AUTHZ_POLICY_SCHEMA_MYSQL_DSN`.
