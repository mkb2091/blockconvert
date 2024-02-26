-- Add migration script here
ALTER TABLE list_rules DROP CONSTRAINT list_rules_list_id_fkey;
ALTER TABLE list_rules DROP CONSTRAINT list_rules_rule_id_fkey;
ALTER TABLE list_rules DROP CONSTRAINT list_rules_source_id_fkey;