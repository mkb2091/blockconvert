-- Add migration script here
DELETE FROM subdomains WHERE parent_domain_id IS NULL;
ALTER TABLE subdomains ALTER COLUMN parent_domain_id SET NOT NULL;