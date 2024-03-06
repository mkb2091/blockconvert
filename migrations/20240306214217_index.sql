-- Add migration script here
CREATE INDEX rules_last_checked_matches_idx ON rules (last_checked_matches);