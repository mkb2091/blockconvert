-- Add migration script here
CREATE TABLE rule_source (
    id SERIAL PRIMARY KEY,
    source TEXT NOT NULL UNIQUE
);

CREATE INDEX idx_rule_source_source ON rule_source (source);

ALTER TABLE list_rules DROP COLUMN source;

ALTER TABLE list_rules ADD COLUMN source_id INTEGER REFERENCES rule_source(id);
