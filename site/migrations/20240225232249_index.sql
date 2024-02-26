-- Add migration script here
drop index list_rules_index;

create index list_rules_index_list_id on list_rules(list_id);
create index list_rules_index_rule_id on list_rules(rule_id);