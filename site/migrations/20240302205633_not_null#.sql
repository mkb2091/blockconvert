-- Add migration script here
ALTER TABLE domains ALTER COLUMN processed_subdomains SET NOT NULL;