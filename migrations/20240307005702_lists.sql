-- Add migration script here
CREATE TABLE allow_domains (
    domain_id BIGINT UNIQUE NOT NULL
);

CREATE TABLE block_domains (
    domain_id BIGINT UNIQUE NOT NULL
);