-- Add migration script here
ALTER TABLE
    domains
ALTER COLUMN
    id TYPE bigint;

ALTER TABLE
    domain_rules
ALTER COLUMN
    domain_id TYPE bigint;

CREATE TABLE subdomains (
    domain_id bigint NOT NULL UNIQUE,
    parent_domain_id bigint
);