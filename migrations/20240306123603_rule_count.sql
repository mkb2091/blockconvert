-- Add migration script here
ALTER TABLE filterLists ADD COLUMN rule_count INT NOT NULL DEFAULT 0;
