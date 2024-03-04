-- Add migration script here
ALTER TABLE
    domains
ADD
    COLUMN last_checked_dns TIMESTAMP WITH TIME ZONE;

CREATE INDEX domains_last_checked_dns_idx ON domains(last_checked_dns);

CREATE TABLE dns_ips (
    domain_id BIGINT NOT NULL,
    ip_address INET NOT NULL
);

CREATE INDEX dns_ips_domain_id_idx ON dns_ips(domain_id);

CREATE INDEX dns_ips_ip_address_idx ON dns_ips(ip_address);

CREATE TABLE dns_cnames (
    domain_id BIGINT NOT NULL,
    cname_domain_id BIGINT NOT NULL
);

CREATE INDEX dns_cnames_domain_id_idx ON dns_cnames(domain_id);

CREATE INDEX dns_cnames_cname_domain_id_idx ON dns_cnames(cname_domain_id);