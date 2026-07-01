-- Keep organization_id migration, but store OIN directly on HSM key versions.

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_name = 'hsm_key_version'
            AND column_name = 'oin'
    ) THEN
        ALTER TABLE hsm_key_version
            ADD COLUMN oin VARCHAR;
    END IF;

    IF EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_name = 'hsm_key_version'
            AND column_name = 'organization_id'
    ) THEN
        UPDATE hsm_key_version hkv
            SET oin = o.oin
            FROM organization o
            WHERE hkv.oin IS NULL
              AND hkv.organization_id = o.id;
    END IF;

END $$;

ALTER TABLE hsm_key_version
    ALTER COLUMN oin SET NOT NULL;

ALTER TABLE hsm_key_version
    DROP COLUMN IF EXISTS organization_id;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint c
        INNER JOIN pg_class t ON t.oid = c.conrelid
        INNER JOIN pg_namespace n ON n.oid = t.relnamespace
        WHERE c.conname = 'hsm_key_version_oin_version_key'
            AND t.relname = 'hsm_key_version'
            AND n.nspname = 'public'
    ) THEN
        ALTER TABLE hsm_key_version
            ADD CONSTRAINT hsm_key_version_oin_version_key UNIQUE (oin, version);
    END IF;
END $$;
