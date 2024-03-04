-- Add migration script here
DELETE FROM list_rules;

ALTER TABLE
    list_rules
ADD
    PRIMARY KEY (list_id, source_id);