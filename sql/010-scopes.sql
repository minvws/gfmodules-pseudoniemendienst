
CREATE TABLE admin.scopes (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO admin.scopes (name) values ('ADMINISTRATION'), ('PSEUDONYM'), ('OPRF_PSEUDONYM'), ('SAML_PSEUDONYM');

CREATE TABLE admin.organization_scopes (
    organization_id UUID NOT NULL REFERENCES admin.organizations(id),
    scope_id INTEGER NOT NULL REFERENCES admin.scopes(id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (organization_id, scope_id)
);

CREATE TABLE admin.client_scopes (
    client_id UUID NOT NULL REFERENCES admin.clients(id),
    organization_id UUID NOT NULL,
    scope_id INTEGER NOT NULL REFERENCES admin.scopes(id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (client_id, organization_id, scope_id),
    FOREIGN KEY (organization_id, scope_id)
      REFERENCES admin.organization_scopes(organization_id, scope_id)
);
