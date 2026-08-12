CREATE SCHEMA IF NOT EXISTS prs;

CREATE SCHEMA IF NOT EXISTS admin;

CREATE TABLE admin.organizations (
    id UUID PRIMARY KEY,
    external_id varchar(100),
    name VARCHAR(255),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP WITH TIME ZONE DEFAULT NULL
);

CREATE UNIQUE INDEX idx_admin_organizations_unique_external_id
ON admin.organizations (external_id)
WHERE deleted_at is NULL;


CREATE TABLE admin.clients (
    id UUID PRIMARY KEY,
    external_id varchar(100),
    organization_id UUID NOT NULL REFERENCES admin.organizations(id),
    common_name VARCHAR(255),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP WITH TIME ZONE DEFAULT NULL
);
CREATE UNIQUE INDEX idx_admin_clients_unique_external_id
ON admin.clients (external_id, organization_id, common_name)
WHERE deleted_at IS NULL;

CREATE TABLE admin.personal_id_types (
    id varchar(100) PRIMARY KEY,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
INSERT INTO admin.personal_id_types (id) values ('oprf');
INSERT INTO admin.personal_id_types (id) values ('oprf2');

CREATE TABLE admin.organization_receive_personal_id_types (
    id UUID PRIMARY KEY,
    organization_id UUID NOT NULL REFERENCES admin.organizations(id),
    personal_id_type varchar(100) NOT NULL REFERENCES admin.personal_id_types(id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (organization_id, personal_id_type)
);

CREATE TABLE admin.organization_request_personal_id_types (
    id UUID PRIMARY KEY,
    organization_id UUID NOT NULL REFERENCES admin.organizations(id),
    personal_id_type varchar(100) NOT NULL REFERENCES admin.personal_id_types(id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (organization_id, personal_id_type)
);

CREATE TABLE admin.client_request_personal_id_types (
    id UUID PRIMARY KEY,
    client_id UUID NOT NULL REFERENCES admin.clients(id),
    organization_request_personal_id_type_id UUID NOT NULL REFERENCES admin.organization_request_personal_id_types(id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (client_id, organization_request_personal_id_type_id)
);

CREATE TABLE prs.hsm_key_versions (
    id UUID PRIMARY KEY,
    organization_id UUID NOT NULL REFERENCES admin.organizations(id),
    version INT NOT NULL,
    from_dt TIMESTAMP WITH TIME ZONE,
    until_dt TIMESTAMP WITH TIME ZONE DEFAULT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    removed_at TIMESTAMP WITH TIME ZONE DEFAULT NULL,
    UNIQUE (organization_id, version)
);

CREATE TABLE prs.organization_public_keys (
    id UUID PRIMARY KEY,
    organization_id UUID NOT NULL REFERENCES admin.organizations(id),
    domain VARCHAR(255) NOT NULL,
    jwk TEXT,
    kid TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (organization_id, domain)
);
