-- Add soft deletion column to users table
ALTER TABLE users
ADD COLUMN deleted_at TIMESTAMPTZ DEFAULT NULL;