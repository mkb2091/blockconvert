-- Add migration script here
ALTER TABLE filterlists ALTER COLUMN lastUpdated DROP NOT NULL;