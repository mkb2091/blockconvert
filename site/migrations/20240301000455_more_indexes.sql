-- Add migration script here
CREATE INDEX rule_source_rule_idx ON rule_source (rule_id);
CREATE INDEX domain_rules_domain_idx ON domain_rules (domain_id);
