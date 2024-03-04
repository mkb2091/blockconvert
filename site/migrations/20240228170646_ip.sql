-- Add migration script here
ALTER TABLE ip_rules RENAME COLUMN ip_address TO ip_network;