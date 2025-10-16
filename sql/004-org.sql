CREATE TABLE organization (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ura VARCHAR NOT NULL UNIQUE,
    name VARCHAR NOT NULL,
    max_rid_usage VARCHAR NOT NULL DEFAULT 'irp',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX organization_ura_idx ON organization (ura);

CREATE TABLE organization_key (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organization(id) ON DELETE CASCADE,
    scope JSONB NOT NULL DEFAULT '[]',
    key_data TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (organization_id, scope)
);


ALTER TABLE organization OWNER TO prs;
ALTER TABLE organization_key OWNER TO prs;
