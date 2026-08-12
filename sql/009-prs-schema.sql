CREATE SCHEMA IF NOT EXISTS prs;

CREATE SCHEMA IF NOT EXISTS admin;

CREATE TABLE admin.organizations (
    id UUID PRIMARY KEY,
    oin VARCHAR(100) NOT NULL,
    name VARCHAR(255),
    scopes VARCHAR(255),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP WITH TIME ZONE DEFAULT NULL,
    UNIQUE (id, oin) WHERE deleted_at IS NULL
);

CREATE TABLE admin.clients (
    id UUID PRIMARY KEY,
    organization_id UUID NOT NULL REFERENCES admin.organizations(id),
    oin VARCHAR(100) NOT NULL,
    common_name VARCHAR(255),
    scopes VARCHAR(255),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP WITH TIME ZONE DEFAULT NULL,
    UNIQUE (organization_id, oin, common_name) WHERE deleted_at IS NULL
);

CREATE TABLE prs.hsm_key_versions (
    id UUID PRIMARY KEY,
    organization_id UUID NOT NULL REFERENCES admin.organizations(id),
    version INT NOT NULL,
    from_dt TIMESTAMP WITH TIME ZONE,
    until_dt TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP WITH TIME ZONE DEFAULT NULL
);

CREATE TABLE prs.organization_keys (
    id UUID PRIMARY KEY,
    organization_id UUID NOT NULL REFERENCES admin.organizations(id),
    scope VARCHAR(255) NOT NULL,
    key_data TEXT,
    key_id TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (organization_id, scope)
);