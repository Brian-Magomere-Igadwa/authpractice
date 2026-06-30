-- Add migration script here
ALTER TABLE users
    ALTER COLUMN signed_up_at TYPE timestamptz,
    ALTER COLUMN signed_up_at SET NOT NULL;