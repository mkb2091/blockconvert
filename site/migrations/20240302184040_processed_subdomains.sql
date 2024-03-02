DELETE FROM
    domains;
DELETE FROM subdomains;
DELETE FROM domain_rules;
DELETE FROM Rules;
DELETE FROM rule_source;

ALTER TABLE
    domains
ADD
    COLUMN processed_subdomains boolean DEFAULT false;