-- Add migration script here
CREATE TEMPORARY TABLE temp_rule_source(source TEXT UNIQUE, rule_id INTEGER) ON COMMIT DROP;

INSERT INTO
    temp_rule_source (source, rule_id)
SELECT
    rule_source.source,
    list_rules.rule_id
FROM
    list_rules
    INNER JOIN rule_source ON list_rules.source_id = rule_source.id ON CONFLICT DO NOTHING;

DELETE FROM
    rule_source;

ALTER TABLE
    rule_source
ADD
    COLUMN rule_id INTEGER NOT NULL;

INSERT INTO
    rule_source (source, rule_id)
SELECT
    source,
    rule_id
FROM
    temp_rule_source;