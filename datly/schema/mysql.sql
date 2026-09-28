CREATE TABLE IF NOT EXISTS resource_policy_heads (
    tenant_id VARCHAR(128) NOT NULL,
    resource_kind VARCHAR(64) NOT NULL,
    resource_id VARCHAR(200) NOT NULL,
    resource_version VARCHAR(64) NOT NULL,
    revision BIGINT NOT NULL,
    created_at DATETIME(6) NULL,
    created_by VARCHAR(128) NULL,
    updated_at DATETIME(6) NULL,
    updated_by VARCHAR(128) NULL,
    PRIMARY KEY (tenant_id, resource_kind, resource_id, resource_version)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS resource_policy_revisions (
    tenant_id VARCHAR(128) NOT NULL,
    resource_kind VARCHAR(64) NOT NULL,
    resource_id VARCHAR(200) NOT NULL,
    resource_version VARCHAR(64) NOT NULL,
    revision BIGINT NOT NULL,
    policies_json JSON NOT NULL,
    actor_id VARCHAR(128) NOT NULL,
    occurred_at DATETIME(6) NOT NULL,
    created_at DATETIME(6) NULL,
    created_by VARCHAR(128) NULL,
    updated_at DATETIME(6) NULL,
    updated_by VARCHAR(128) NULL,
    PRIMARY KEY (tenant_id, resource_kind, resource_id, resource_version, revision)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

