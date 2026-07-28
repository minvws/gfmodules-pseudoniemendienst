CREATE INDEX hsm_key_version_organization_id_version_idx
    ON hsm_key_version (organization_id, version);

CREATE INDEX hsm_key_version_active_idx
    ON hsm_key_version (organization_id, from_dt, until_dt, version)
    WHERE removed = FALSE;
