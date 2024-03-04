-- Add migration script here
ALTER TABLE filterLists ADD COLUMN lastModified INTEGER NOT NULL DEFAULT 0;