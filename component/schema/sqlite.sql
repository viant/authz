CREATE TABLE IF NOT EXISTS resource_policies (
    tenant_id VARCHAR(128) NOT NULL,
    resource_kind VARCHAR(64) NOT NULL,
    resource_id VARCHAR(200) NOT NULL,
    resource_version VARCHAR(64) NOT NULL,
    revision BIGINT NOT NULL,
    created_at TIMESTAMP NULL,
    created_by VARCHAR(128) NULL,
    updated_at TIMESTAMP NULL,
    updated_by VARCHAR(128) NULL,
    PRIMARY KEY (tenant_id, resource_kind, resource_id, resource_version)
);

CREATE TABLE IF NOT EXISTS resource_policy_revisions (
    tenant_id VARCHAR(128) NOT NULL,
    resource_kind VARCHAR(64) NOT NULL,
    resource_id VARCHAR(200) NOT NULL,
    resource_version VARCHAR(64) NOT NULL,
    revision BIGINT NOT NULL,
    policies_json TEXT NOT NULL,
    actor_id VARCHAR(128) NOT NULL,
    occurred_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP NULL,
    created_by VARCHAR(128) NULL,
    updated_at TIMESTAMP NULL,
    updated_by VARCHAR(128) NULL,
    PRIMARY KEY (tenant_id, resource_kind, resource_id, resource_version, revision)
);

CREATE TABLE IF NOT EXISTS authz_gate_heads (
    binding_key CHAR(64) NOT NULL PRIMARY KEY,
    resource_json TEXT NOT NULL,
    action_name VARCHAR(128) NOT NULL,
    revision VARCHAR(64) NOT NULL,
    requirements_json TEXT NOT NULL,
    updated_at TIMESTAMP NOT NULL
);

CREATE TABLE IF NOT EXISTS authz_gate_revisions (
    binding_key CHAR(64) NOT NULL,
    revision VARCHAR(64) NOT NULL,
    requirements_json TEXT NOT NULL,
    actor_id VARCHAR(255) NOT NULL,
    occurred_at TIMESTAMP NOT NULL,
    PRIMARY KEY (binding_key, revision),
    FOREIGN KEY (binding_key) REFERENCES authz_gate_heads(binding_key)
);
