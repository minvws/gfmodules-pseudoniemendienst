-- Add key ID to be returned in the JWE kid header

ALTER TABLE organization_key ADD COLUMN key_id TEXT;
