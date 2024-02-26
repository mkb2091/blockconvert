-- Add migration script here
CREATE TABLE domain_rules (
  id SERIAL PRIMARY KEY,
  domain TEXT NOT NULL
);
CREATE INDEX domain_rules_idx_domain ON domain_rules (domain);