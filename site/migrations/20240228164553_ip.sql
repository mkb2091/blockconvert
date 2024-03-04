-- Add migration script here
CREATE TABLE ip_rules (
    id SERIAL PRIMARY KEY,
    ip_address inet NOT NULL,
    allow boolean NOT NULL,
    CONSTRAINT ip_rules_unique UNIQUE (ip_address, allow)
);

ALTER TABLE Rules ADD COLUMN ip_rule_id INTEGER;
ALTER TABLE Rules DROP CONSTRAINT unique_rules;
ALTER TABLE Rules ADD CONSTRAINT unique_rules UNIQUE NULLS NOT DISTINCT (domain_rule_id, ip_rule_id, unknown_rule_id);