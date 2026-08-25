DROP TABLE organization_key;
DROP TABLE hsm_key_version;
DROP TABLE organization;

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
    organization_id UUID NOT NULL REFERENCES admin.organizations(id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP WITH TIME ZONE DEFAULT NULL
);

CREATE TABLE admin.certificates (
    id UUID PRIMARY KEY,
    organization_identifier varchar(100),
    domain VARCHAR(255),
    organization_id UUID NOT NULL REFERENCES admin.organizations(id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP WITH TIME ZONE DEFAULT NULL
);

CREATE UNIQUE INDEX idx_admin_certificates_unique
ON admin.certificates (organization_identifier, domain, organization_id)
WHERE deleted_at IS NULL;

CREATE TABLE admin.client_certificates (
  client_id UUID NOT NULL REFERENCES admin.clients(id),
  certificate_id UUID NOT NULL REFERENCES admin.certificates(id),
  created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (client_id, certificate_id)
);

CREATE TABLE admin.personal_id_types (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO admin.personal_id_types (name) values ('OPRF');
INSERT INTO admin.personal_id_types (name) values ('REVERSIBLE_PSEUDONYM');
INSERT INTO admin.personal_id_types (name) values ('IRREVERSIBLE_PSEUDONYM');

CREATE TABLE admin.organization_receive_personal_id_types (
    organization_id UUID NOT NULL REFERENCES admin.organizations(id),
    personal_id_type_id INTEGER NOT NULL REFERENCES admin.personal_id_types(id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (organization_id, personal_id_type_id)
);

CREATE TABLE admin.organization_request_personal_id_types (
    organization_id UUID NOT NULL REFERENCES admin.organizations(id),
    personal_id_type_id INTEGER NOT NULL REFERENCES admin.personal_id_types(id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (organization_id, personal_id_type_id)
);

CREATE TABLE admin.client_request_personal_id_types (
    client_id UUID NOT NULL REFERENCES admin.clients(id),
    organization_id UUID NOT NULL,
    personal_id_type_id INTEGER NOT NULL REFERENCES admin.personal_id_types(id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (client_id, personal_id_type_id),
    FOREIGN KEY (organization_id, personal_id_type_id)
      REFERENCES admin.organization_request_personal_id_types(organization_id, personal_id_type_id)
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
