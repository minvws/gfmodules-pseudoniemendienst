CREATE TABLE key_entry (
    entry_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization VARCHAR NOT NULL,
    scope JSONB NOT NULL DEFAULT '[]',
    key TEXT NOT NULL
);

CREATE INDEX key_entry_scope_gin ON key_entry USING GIN (scope);

ALTER TABLE key_entry OWNER TO prs;
