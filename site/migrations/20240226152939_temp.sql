-- Add migration script here
CREATE TABLE temp_rule_source (
    idx SERIAL PRIMARY KEY,
    rule TEXT NOT NULL,
    source TEXT NOT NULL
);