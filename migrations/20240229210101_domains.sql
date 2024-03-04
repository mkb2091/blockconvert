-- Add migration script here
CREATE TABLE domains (
    id SERIAL PRIMARY KEY,
    domain TEXT NOT NULL UNIQUE
);

INSERT INTO
    domains (domain)
SELECT
    domain
FROM
    domain_rules ON CONFLICT DO NOTHING;

ALTER TABLE
    domain_rules RENAME TO domain_rules_old;

CREATE TABLE domain_rules (
    id SERIAL PRIMARY KEY,
    domain_id INTEGER NOT NULL,
    allow BOOLEAN NOT NULL,
    subdomain BOOLEAN NOT NULL,
    CONSTRAINT domain_rules_unique UNIQUE (domain_id, allow, subdomain)
);

INSERT INTO
    domain_rules (domain_id, allow, subdomain)
SELECT
    domains.id,
    domain_rules_old.allow,
    domain_rules_old.subdomain
FROM
    domain_rules_old
    INNER JOIN domains ON domain_rules_old.domain = domains.domain;

DROP TABLE domain_rules_old;