-- Add migration script here
ALTER TABLE domain_rules ADD COLUMN block BOOLEAN NOT NULL;