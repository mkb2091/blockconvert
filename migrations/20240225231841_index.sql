-- Add migration script here
create index list_rules_index on list_rules(list_id, rule_id);