-- Add migration script here
CREATE TABLE rule_matches (
    rule_id INTEGER NOT NULL,
    domain_id BIGINT NOT NULL
);

ALTER TABLE rule_matches ADD CONSTRAINT rule_matches_pk UNIQUE (rule_id, domain_id);
CREATE INDEX rule_matches_rule_id_idx ON rule_matches (rule_id);
CREATE INDEX rule_matches_domain_id_idx ON rule_matches (domain_id);

ALTER TABLE Rules ADD COLUMN last_checked_matches TIMESTAMP;
