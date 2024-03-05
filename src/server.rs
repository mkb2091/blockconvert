use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;

use crate::list_parser::Domain;
use crate::DomainId;
use futures::StreamExt;
use hickory_resolver::error::ResolveError;
use leptos::*;
use notify::Watcher;
use rand::Rng;
use tokio::io::AsyncBufReadExt;

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
    SQLITE_POOL
        .get_or_try_init(|| {
            let _ = dotenvy::dotenv();
            let db_url = std::env::var("DATABASE_URL");
            async { Ok::<_, DbInitError>(sqlx::PgPool::connect(&db_url?).await?) }
        })
        .await
        .cloned()
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

        for record in records {
            checked_domains.push(record.domain.clone());
            let parents = record
                .domain
                .match_indices('.')
                .map(|(i, _)| record.domain.split_at(i + 1).1)
                .filter_map(|parent| parent.parse().ok())
                .map(|parent: Domain| parent.as_ref().to_string());
            for parent in parents {
                all_domains.push(record.domain.clone());
                all_parents.push(parent);
            }
        }
        let mut parent_set = all_parents
            .iter()
            .cloned()
            .collect::<std::collections::HashSet<_>>();
        for domain in &all_domains {
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
) -> Result<(Vec<ipnetwork::IpNetwork>, Vec<Domain>), ResolveError> {
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
                    let mut cname = cname.0.to_ascii();
                    if cname.ends_with('.') {
                        cname.pop();
                    }
                    if let Ok(cname) = cname.as_str().parse() {
                        cnames.push(cname);
                    } else {
                        log::warn!("Invalid CNAME {}", cname);
                    }
                } else {
                    log::info!("Unknown record type {:?}", record.record_type());
                }
            }
            Ok((ips, cnames))
        }
        Err(err) => match err.kind() {
            hickory_resolver::error::ResolveErrorKind::NoRecordsFound {
                query: _,
                soa: _,
                negative_ttl: _,
                response_code: _,
                trusted: _,
            } => Ok((vec![], vec![])),
            hickory_resolver::error::ResolveErrorKind::Proto(_) => Ok((vec![], vec![])),
            hickory_resolver::error::ResolveErrorKind::Timeout => Err(err),
            _ => Err(err),
        },
    }
}

type Resolver = Arc<
    hickory_resolver::AsyncResolver<
        hickory_resolver::name_server::GenericConnector<
            hickory_resolver::name_server::TokioRuntimeProvider,
        >,
    >,
>;

fn get_resolvers() -> Result<Vec<(Arc<str>, Resolver)>, ServerFnError> {
    let _ = dotenvy::dotenv()?;
    let servers_str = std::env::var("DNS_SERVERS")?;
    let mut resolvers = Vec::new();
    for server in servers_str.split(',') {
        let server: Arc<str> = server.into();
        let (addr, port) = server
            .split_once(':')
            .ok_or_else(|| ServerFnError::new("Bad DNS_SERVER env"))?;
        let server_conf = hickory_resolver::config::NameServerConfigGroup::from_ips_clear(
            &[addr.parse()?],
            port.parse()?,
            true,
        );
        let config =
            hickory_resolver::config::ResolverConfig::from_parts(None, vec![], server_conf);
        let mut opts = hickory_resolver::config::ResolverOpts::default();
        opts.ip_strategy = hickory_resolver::config::LookupIpStrategy::Ipv4AndIpv6;
        opts.cache_size = 32;
        opts.attempts = 3;
        opts.timeout = std::time::Duration::from_secs_f32(5.0);
        let resolver = Arc::new(hickory_resolver::AsyncResolver::tokio(config, opts));
        resolvers.push((server, resolver));
    }

    if resolvers.is_empty() {
        return Err(ServerFnError::new("Empty DNS server list"));
    }
    Ok(resolvers)
}

pub async fn check_missing_dns() -> Result<(), ServerFnError> {
    let _ = dotenvy::dotenv()?;
    let pool: sqlx::Pool<sqlx::Postgres> = get_db().await?;
    let read_limit: usize = std::env::var("READ_LIMIT")?.parse()?;
    let concurrent_lookups = std::env::var("CONCURRENT_LOOKUPS")?.parse()?;
    let write_frequency: u64 = std::env::var("WRITE_FREQUENCY")?.parse()?;
    let resolvers = get_resolvers()?;
    let size: Option<i64> =
        sqlx::query!("SELECT COUNT(*) FROM domains WHERE last_checked_dns IS NULL")
            .fetch_one(&pool)
            .await?
            .count;

    let mut start = 0;
    if let Some(size) = size {
        if size as usize > read_limit {
            start = rand::thread_rng().gen_range(0..size.saturating_sub(read_limit as i64));
        }
    }
    let mut failed_count = 100_000;

    let mut records = Vec::new();

    let mut tasks = futures::stream::futures_unordered::FuturesUnordered::new();
    let mut last_wrote = std::time::Instant::now();
    let lookup_domain = |(domain_id, mut domain): (DomainId, String)| {
        if !domain.ends_with('.') {
            domain.push('.'); // Make sure it's a FQDN
        }
        let (server_str, resolver) = resolvers[domain_id.0 as usize % resolvers.len()].clone();
        tokio::spawn(async move {
            let result = resolver.lookup_ip(domain.as_str()).await;
            assert!(domain.ends_with('.'));
            let _ = domain.pop();
            (server_str, domain_id, domain, result)
        })
    };

    let mut looked_up_domains = Vec::new();
    let mut dns_ips_domain_ids = Vec::new();
    let mut dns_ips_ips = Vec::new();
    let mut dns_cnames_domain_ids = Vec::new();
    let mut dns_cnames_cname = Vec::new();
    let mut bad_domains = Vec::new();
    loop {
        if records.len() < read_limit {
            let new_records = sqlx::query!(
                "SELECT id, domain from domains
        WHERE last_checked_dns IS NULL
        ORDER BY (id) ASC
        LIMIT $1 OFFSET $2",
                read_limit as i64,
                start + failed_count + tasks.len() as i64 + records.len() as i64
            )
            .fetch_all(&pool)
            .await?;
            records.extend(new_records);
        }
        if records.is_empty() && tasks.is_empty() {
            if failed_count == 0 {
                tokio::time::sleep(std::time::Duration::from_secs(30)).await;
            } else {
                // Retry failed domains
                failed_count = 0;
            }
            start = 0;
            continue;
        }

        while tasks.len() < concurrent_lookups {
            if let Some(record) = records.pop() {
                tasks.push(lookup_domain((DomainId(record.id), record.domain)));
            } else {
                break;
            }
        }
        looked_up_domains.clear();
        dns_ips_domain_ids.clear();
        dns_ips_ips.clear();
        dns_cnames_domain_ids.clear();
        dns_cnames_cname.clear();
        bad_domains.clear();
        while let Some(result) = tasks.next().await {
            let (server_str, domain_id, domain, result) = result?;
            match parse_lookup_result(result) {
                Ok((ips, cnames)) => {
                    looked_up_domains.push(domain_id.0);
                    for ip in ips {
                        dns_ips_domain_ids.push(domain_id.0);
                        dns_ips_ips.push(ip);
                    }
                    for cname in cnames {
                        dns_cnames_domain_ids.push(domain_id.0);
                        dns_cnames_cname.push(cname.as_ref().into());
                    }
                }
                Err(err) => {
                    log::warn!(
                        "Server:  {} Error looking up domain {}: {}",
                        server_str,
                        domain,
                        err
                    );
                    let domain_parsed: Result<Domain, _> = domain.as_str().parse();
                    if domain_parsed.is_err() {
                        log::warn!("Removing bad domain: {}", domain);
                        bad_domains.push(domain_id.0);
                    }
                    looked_up_domains.push(domain_id.0); // Don't try again until rechecking
                    failed_count += 1;
                    continue;
                }
            };
            if let Some(record) = records.pop() {
                tasks.push(lookup_domain((DomainId(record.id), record.domain)));
            }
            if records.is_empty() || last_wrote.elapsed().as_secs() > write_frequency {
                break;
            }
        }
        log::info!(
            "Looked up {} domains, got {} ips, {} cnames",
            looked_up_domains.len(),
            dns_ips_domain_ids.len(),
            dns_cnames_domain_ids.len()
        );
        last_wrote = std::time::Instant::now();
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
        sqlx::query!(
            "DELETE FROM domains
    WHERE id = ANY($1::bigint[])",
            &bad_domains[..]
        )
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
    }
}

pub async fn import_pihole_logs() -> Result<(), ServerFnError> {
    let _ = dotenvy::dotenv()?;
    let Ok(log_path) = std::env::var("PIHOLE_LOG_PATH") else {
        log::info!("No PIHOLE_LOG_PATH set, skipping");
        return Ok(());
    };
    let log_path: std::path::PathBuf = log_path.parse()?;
    let write_frequency: u64 = std::env::var("WRITE_FREQUENCY")?.parse()?;
    let notify = std::sync::Arc::new(tokio::sync::Notify::new());
    let notify2 = notify.clone();
    let mut watcher = notify::recommended_watcher(move |_| {
        notify.notify_one();
    })?;
    watcher.watch(&log_path, notify::RecursiveMode::NonRecursive)?;
    let pool: sqlx::Pool<sqlx::Postgres> = get_db().await?;
    let file = tokio::fs::File::open(log_path).await?;
    let buf = tokio::io::BufReader::new(file);
    let mut lines = buf.lines();
    let mut domains = HashSet::new();
    let mut last_wrote = std::time::Instant::now();
    while let Ok(line) = lines.next_line().await {
        if let Some(line) = line {
            for segment in line.split_whitespace() {
                if let Ok(domain) = segment.parse() {
                    let domain: Domain = domain;
                    domains.insert(domain);
                }
            }
        } else {
            notify2.notified().await;
        }
        if last_wrote.elapsed().as_secs() > write_frequency {
            let domains_vec = domains
                .drain()
                .map(|domain| domain.as_ref().to_string())
                .collect::<Vec<_>>();
            let inserted = sqlx::query!(
                "INSERT INTO domains (domain)
            SELECT domain FROM UNNEST($1::text[]) as t(domain)
            ON CONFLICT DO NOTHING
            RETURNING *
            ",
                &domains_vec[..]
            )
            .fetch_all(&pool)
            .await?;
            if !inserted.is_empty() {
                log::info!("Inserted {} domains", inserted.len());
            }
            last_wrote = std::time::Instant::now();
        }
    }

    Ok(())
}
