-- Add migration script here
CREATE INDEX domains_processed_subdomains_idx ON domains(processed_subdomains);