use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;

use crate::list_parser::Domain;
use crate::DomainId;
use futures::StreamExt;
use hickory_resolver::config::NameServerConfigGroup;
use hickory_resolver::error::ResolveError;
use leptos::*;

static SQLITE_POOL: tokio::sync::OnceCell<sqlx::PgPool> = tokio::sync::OnceCell::const_new();

#[derive(thiserror::Error, Debug)]
pub enum DbInitError {
    #[cfg(feature = "ssr")]
    #[error("Sqlx error {0}")]
    SqlxError(#[from] sqlx::Error),
    #[error("Missing DATABASE_URL")]
    MissingDatabaseUrl(#[from] std::env::VarError),
}

pub async fn get_db() -> Result<sqlx::PgPool, DbInitError> {
    let _ = dotenvy::dotenv();
    let db_url = std::env::var("DATABASE_URL")?;

    Ok(SQLITE_POOL
        .get_or_try_init(|| sqlx::PgPool::connect(&db_url))
        .await
        .cloned()?)
}

pub async fn parse_missing_subdomains() -> Result<(), ServerFnError> {
    const LIMIT: i64 = 1000;
    let pool = get_db().await?;
    loop {
        let mut tx = pool.begin().await?;
        let records = sqlx::query!(
            "SELECT domain from domains
        WHERE processed_subdomains = false
        LIMIT $1",
            LIMIT
        )
        .fetch_all(&mut *tx)
        .await?;
        if records.is_empty() {
            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
            continue;
        }
        let mut checked_domains = Vec::new();

        let mut all_domains = Vec::new();
        let mut all_parents = Vec::new();

        for record in records.into_iter() {
            checked_domains.push(record.domain.clone());
            let parents = record
                .domain
                .match_indices('.')
                .map(|(i, _)| record.domain.split_at(i + 1).1)
                .filter_map(|parent| parent.try_into().ok())
                .map(|parent: Domain| parent.as_ref().to_string());
            for parent in parents.into_iter() {
                all_domains.push(record.domain.clone());
                all_parents.push(parent);
            }
        }
        let mut parent_set = all_parents
            .iter()
            .cloned()
            .collect::<std::collections::HashSet<_>>();
        for domain in all_domains.iter() {
            parent_set.remove(domain);
        }
        let parent_set = parent_set.into_iter().collect::<Vec<_>>();
        sqlx::query!(
            "INSERT INTO domains (domain)
            SELECT domain FROM UNNEST($1::text[]) as t(domain)
            ON CONFLICT DO NOTHING",
            &parent_set[..]
        )
        .execute(&pool)
        .await?;
        sqlx::query!(
            "INSERT INTO subdomains (domain_id, parent_domain_id)
            SELECT domains_with_parents.id, parents.id
            FROM UNNEST($1::text[], $2::text[]) AS t(domain, parent)
            INNER JOIN domains AS domains_with_parents ON domains_with_parents.domain = t.domain
            INNER JOIN domains AS parents ON parents.domain = t.parent
            ON CONFLICT DO NOTHING",
            &all_domains[..],
            &all_parents[..],
        )
        .execute(&mut *tx)
        .await?;
        sqlx::query!(
            "INSERT INTO domains (domain)
    SELECT domain FROM UNNEST($1::text[]) as t(domain)
    ON CONFLICT(domain)
    DO UPDATE SET processed_subdomains = true",
            &checked_domains[..]
        )
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
    }
}

fn parse_lookup_result(
    result: Result<hickory_resolver::lookup_ip::LookupIp, ResolveError>,
) -> Result<(Vec<ipnetwork::IpNetwork>, Vec<String>), ResolveError> {
    match result {
        Ok(result) => {
            let mut ips: Vec<ipnetwork::IpNetwork> = Vec::new();
            let mut cnames = Vec::new();
            let lookup = result.as_lookup();
            for record in lookup.iter() {
                if let Some(a) = record.as_a() {
                    let ip: IpAddr = a.0.into();
                    ips.push(ip.into());
                } else if let Some(aaaa) = record.as_aaaa() {
                    let ip: IpAddr = aaaa.0.into();
                    ips.push(ip.into());
                } else if let Some(cname) = record.as_cname() {
                    cnames.push(cname.0.to_ascii());
                } else {
                    log::info!("Unknown record type {:?}", record.record_type());
                }
            }
            Ok((ips, cnames))
        }
        Err(err) => {
            if let hickory_resolver::error::ResolveErrorKind::NoRecordsFound {
                query: _,
                soa: _,
                negative_ttl: _,
                response_code: _,
                trusted: _,
            } = err.kind()
            {
                Ok((vec![], vec![]))
            } else {
                Err(err)
            }
        }
    }
}

pub async fn check_missing_dns() -> Result<(), ServerFnError> {
    const LIMIT: i64 = 200;
    const CONCURRENT_LOOKUPS: usize = 30;
    let pool = get_db().await?;
    let mut group = NameServerConfigGroup::google();
    group.merge(NameServerConfigGroup::cloudflare());
    group.merge(
        hickory_resolver::config::NameServerConfigGroup::from_ips_clear(
            &["9.9.9.10".parse().unwrap(), "149.112.112.10".parse().unwrap()],
            53,
            true,
        ),
    );
    let config = hickory_resolver::config::ResolverConfig::from_parts(None, vec![], group);
    let mut opts = hickory_resolver::config::ResolverOpts::default();
    opts.ip_strategy = hickory_resolver::config::LookupIpStrategy::Ipv4AndIpv6;
    opts.server_ordering_strategy =
        hickory_resolver::config::ServerOrderingStrategy::QueryStatistics;
    let resolver = Arc::new(hickory_resolver::AsyncResolver::tokio(config, opts));
    let mut failed_count = 100000;

    let mut tasks = futures::stream::futures_unordered::FuturesUnordered::new();
    loop {
        let mut records = sqlx::query!(
            "SELECT id, domain from domains
        WHERE last_checked_dns IS NULL
        ORDER BY (id) ASC
        LIMIT $1 OFFSET $2",
            LIMIT,
            failed_count + tasks.len() as i64
        )
        .fetch_all(&pool)
        .await?;
        if records.is_empty() && tasks.is_empty() {
            if failed_count == 0 {
                log::info!("No more records to process, sleeping");
                tokio::time::sleep(std::time::Duration::from_secs(30)).await;
            } else {
                // Retry failed domains
                failed_count = 0;
            }
            continue;
        }
        let lookup_domain = |(domain_id, mut domain): (DomainId, String)| {
            if !domain.ends_with('.') {
                domain.push('.'); // Make sure it's a FQDN
            }
            let resolver = resolver.clone();
            tokio::spawn(async move {
                let result = resolver.lookup_ip(domain.as_str()).await;
                (domain_id, domain, result)
            })
        };
        while tasks.len() < CONCURRENT_LOOKUPS {
            if let Some(record) = records.pop() {
                tasks.push(lookup_domain((DomainId(record.id), record.domain)));
            } else {
                break;
            }
        }
        let mut looked_up_domains = Vec::new();
        let mut dns_ips_domain_ids = Vec::new();
        let mut dns_ips_ips = Vec::new();
        let mut dns_cnames_domain_ids = Vec::new();
        let mut dns_cnames_cname = Vec::new();
        while let Some(result) = tasks.next().await {
            let (domain_id, domain, result) = result?;

            let (ips, cnames) = match parse_lookup_result(result) {
                Ok((ips, cnames)) => (ips, cnames),
                Err(err) => {
                    log::warn!("Error looking up domain {}: {}", domain, err);
                    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                    failed_count += 1;
                    continue;
                }
            };
            looked_up_domains.push(domain_id.0);
            for ip in ips {
                dns_ips_domain_ids.push(domain_id.0);
                dns_ips_ips.push(ip);
            }
            for cname in cnames {
                dns_cnames_domain_ids.push(domain_id.0);
                dns_cnames_cname.push(cname);
            }
            if let Some(record) = records.pop() {
                tasks.push(lookup_domain((DomainId(record.id), record.domain)));
            }
            if records.is_empty() {
                break;
            }
        }
        log::info!(
            "Looked up {} domains, got {} ips, {} cnames",
            looked_up_domains.len(),
            dns_ips_domain_ids.len(),
            dns_cnames_domain_ids.len()
        );

        let mut tx = pool.begin().await?;
        let total_cnames = dns_cnames_cname
            .iter()
            .collect::<HashSet<_>>()
            .into_iter()
            .cloned()
            .collect::<Vec<String>>();
        sqlx::query!(
            "INSERT INTO domains(domain)
        SELECT domain FROM UNNEST($1::text[]) as t(domain)
        ON CONFLICT DO NOTHING",
            &total_cnames[..]
        )
        .execute(&mut *tx)
        .await?;
        sqlx::query!(
            "INSERT INTO dns_ips(domain_id, ip_address)
        SELECT domain_id, ip FROM UNNEST($1::bigint[], $2::inet[]) as t(domain_id, ip)",
            &dns_ips_domain_ids[..],
            &dns_ips_ips[..]
        )
        .execute(&mut *tx)
        .await?;
        sqlx::query!(
            "INSERT INTO dns_cnames(domain_id, cname_domain_id)
        SELECT domain_id, cname_domains.id FROM UNNEST($1::bigint[], $2::text[]) as t(domain_id, cname)
        INNER JOIN domains AS cname_domains ON cname_domains.domain = t.cname
        ",
            &dns_cnames_domain_ids[..],
            &dns_cnames_cname[..]
        )
        .execute(&mut *tx)
        .await?;

        sqlx::query!(
            "UPDATE domains
        SET last_checked_dns = now()
        WHERE id = ANY($1::bigint[])",
            &looked_up_domains[..]
        )
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
    }
}
