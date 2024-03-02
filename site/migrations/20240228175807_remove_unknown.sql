-- Add migration script here
DROP TABLE unknown_rules;
ALTER TABLE Rules DROP COLUMN unknown_rule_id;