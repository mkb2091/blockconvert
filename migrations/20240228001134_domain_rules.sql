-- Add migration script here
ALTER TABLE
    domain_rules
ADD
    COLUMN subdomain BOOLEAN NOT NULL DEFAULT FALSE;

ALTER TABLE
    domain_rules
ALTER COLUMN
    subdomain DROP DEFAULT;

CREATE TEMPORARY TABLE temp_domain_rules (
    domain TEXT NOT NULL,
    allow BOOLEAN NOT NULL,
    subdomain BOOLEAN NOT NULL
);

INSERT INTO
    temp_domain_rules (domain, allow, subdomain)
SELECT
    domain,
    block,
    subdomain
FROM
    domain_rules;

DELETE FROM
    domain_rules;

ALTER TABLE
    domain_rules
ADD
    COLUMN id SERIAL NOT NULL UNIQUE;

ALTER TABLE
    domain_rules RENAME COLUMN block TO allow;

ALTER TABLE
    domain_rules DROP column rule_id;

ALTER TABLE
    domain_rules
ADD
    CONSTRAINT domain_rule_unique UNIQUE (domain, allow, subdomain);

INSERT INTO
    domain_rules (domain, allow, subdomain)
SELECT
    domain,
    NOT allow,
    subdomain
FROM
    temp_domain_rules;