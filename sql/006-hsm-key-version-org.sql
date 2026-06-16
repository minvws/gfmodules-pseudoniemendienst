-- Replace the free-standing URA string on hsm_key_version with a proper
-- foreign key to the organization table, mirroring organization_key.

ALTER TABLE hsm_key_version
    ADD COLUMN organization_id UUID REFERENCES organization(id) ON DELETE CASCADE;

-- Backfill from the existing URA. Any row whose URA has no matching
-- organization stays NULL and the SET NOT NULL below aborts the migration.
UPDATE hsm_key_version hkv
    SET organization_id = o.id
    FROM organization o
    WHERE o.ura = hkv.ura;

ALTER TABLE hsm_key_version
    ALTER COLUMN organization_id SET NOT NULL;

ALTER TABLE hsm_key_version
    DROP COLUMN ura;
