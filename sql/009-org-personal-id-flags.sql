ALTER TABLE organization
  ADD COLUMN may_provide_personal_id BOOLEAN NOT NULL DEFAULT FALSE,
  ADD COLUMN may_receive_personal_id BOOLEAN NOT NULL DEFAULT FALSE;
