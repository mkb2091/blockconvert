-- Add migration script here
ALTER TABLE
    Rules
ADD
    COLUMN domain_rule_id INTEGER;

CREATE TABLE unknown_rules (
    id SERIAL PRIMARY KEY,
    rule TEXT NOT NULL UNIQUE
);

DELETE FROM
    Rules;

ALTER TABLE
    Rules
ADD
    COLUMN unknown_rule_id INTEGER;

ALTER TABLE
    Rules
ADD
    CONSTRAINT unique_rules UNIQUE NULLS NOT DISTINCT (domain_rule_id, unknown_rule_id);