-- Add migration script here
ALTER TABLE filterlists ADD COLUMN name TEXT;
ALTER TABLE filterlists ADD COLUMN author TEXT;
ALTER TABLE filterlists ADD COLUMN expires INTEGER;
ALTER TABLE filterlists ADD COLUMN license TEXT;