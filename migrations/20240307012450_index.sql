-- Add migration script here
CREATE INDEX domain_rules_allow_idx ON domain_rules (allow);
CREATE INDEX ip_rules_allow_idx ON ip_rules (allow);