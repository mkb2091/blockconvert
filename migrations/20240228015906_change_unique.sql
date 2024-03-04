-- Add migration script here
ALTER TABLE rule_source DROP CONSTRAINT rule_source_source_key;

ALTER TABLE rule_source ADD CONSTRAINT rule_source_unique UNIQUE (source, rule_id);
