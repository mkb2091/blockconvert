-- Add migration script here
CREATE INDEX ip_rules_network_idx ON ip_rules (ip_network);