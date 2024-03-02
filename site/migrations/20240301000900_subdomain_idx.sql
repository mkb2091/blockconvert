-- Add migration script here
CREATE INDEX subdomain_domain_idx ON subdomains (domain_id);

CREATE INDEX subdomain_parent_idx ON subdomains (parent_domain_id);