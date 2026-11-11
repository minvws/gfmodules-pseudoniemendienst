ALTER TABLE admin.clients ADD COLUMN name VARCHAR(255);

-- Existing clients get their client id as name (unique by construction)
UPDATE admin.clients SET name = id::text WHERE name IS NULL;

ALTER TABLE admin.clients ALTER COLUMN name SET NOT NULL;

-- Client names are unique within an organization, not globally
ALTER TABLE admin.clients
    ADD CONSTRAINT uq_clients_organization_id_name UNIQUE (organization_id, name);
