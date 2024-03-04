-- Add migration script here
CREATE INDEX domain_rules_subdomain_idx ON domain_rules (subdomain);
