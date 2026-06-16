CREATE TABLE hsm_key_version (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ura VARCHAR NOT NULL,
    version INTEGER NOT NULL,
    from_dt TIMESTAMPTZ NOT NULL,
    until_dt TIMESTAMPTZ,
    removed BOOLEAN NOT NULL DEFAULT FALSE
);
