-- Add migration script here
DELETE FROM
    subdomains
WHERE
    parent_domain_id IS NOT NULL;

ALTER TABLE
    subdomains DROP CONSTRAINT subdomains_domain_id_key;

ALTER TABLE
    subdomains
ADD
    CONSTRAINT subdomains_domain_id_key UNIQUE NULLS NOT DISTINCT (domain_id, parent_domain_id);