-- Add migration script here
DELETE FROM Rules;
ALTER TABLE Rules ADD CONSTRAINT rules_unique UNIQUE NULLS NOT DISTINCT (domain_rule_id, ip_rule_id);
