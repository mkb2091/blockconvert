use crate::list_parser::Domain;
use crate::DomainId;
use axum::error_handling::future;
use futures::StreamExt;
use hickory_resolver::error::ResolveError;
use leptos::*;
use notify::Watcher;
use rand::seq::SliceRandom;
use rand::Rng;
use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};
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
                    if let Ok(cname) = cname.parse() {
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

type Task = (DomainId, Domain);

#[derive(Clone)]
struct DomainResolver {
    resolvers: Vec<(Arc<str>, Resolver)>,
    tx: async_channel::Sender<Task>,
    rx: async_channel::Receiver<Task>,
    read_limit: i64,
    failed_domains: Arc<AtomicUsize>,
    bad_domains: Arc<Mutex<Vec<i64>>>,
    looked_up_domains: Arc<Mutex<Vec<i64>>>,
    dns_ips: Arc<Mutex<(Vec<i64>, Vec<ipnetwork::IpNetwork>)>>,
    dns_cnames: Arc<Mutex<(Vec<i64>, Vec<String>)>>,
}

impl DomainResolver {
    fn new() -> Result<Self, ServerFnError> {
        let _ = dotenvy::dotenv()?;
        let servers_str = std::env::var("DNS_SERVERS")?;

        let read_limit = std::env::var("READ_LIMIT")?.parse::<u32>()? as i64;
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
        let (tx, rx) = async_channel::bounded(read_limit as usize);

        let bad_domains = Arc::new(Mutex::new(Vec::new()));

        Ok(Self {
            resolvers,
            bad_domains,
            tx,
            rx,
            read_limit,
            failed_domains: Arc::new(AtomicUsize::new(0)),
            looked_up_domains: Arc::new(Mutex::new(Vec::new())),
            dns_ips: Default::default(),
            dns_cnames: Default::default(),
        })
    }

    async fn run(&self) -> Result<(), ServerFnError> {
        dotenvy::dotenv()?;
        let concurrent_lookups: usize = std::env::var("CONCURRENT_LOOKUPS")?.parse()?;

        let mut tasks = futures::stream::futures_unordered::FuturesUnordered::new();

        for resolver in &self.resolvers {
            for _ in 0..concurrent_lookups {
                let resolver_str = resolver.0.clone();
                let resolver = resolver.1.clone();
                let resolver_self = self.clone();
                let task =
                    tokio::spawn(
                        async move { resolver_self.run_task(resolver_str, resolver).await },
                    );
                tasks.push(task);
            }
        }
        let selector = self.clone();
        let selector_task = tokio::spawn(async move { selector.domain_selector().await });
        tasks.push(selector_task);
        let writer = self.clone();
        let writer_task = tokio::spawn(async move { writer.write_to_db().await });
        tasks.push(writer_task);
        let failure_reset = self.clone();
        let _ = tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
            interval.tick().await;
            loop {
                interval.tick().await;
                failure_reset.failed_domains.store(0, Ordering::SeqCst);
            }
        });
        while let Some(result) = tasks.next().await {
            let _ = result?;
        }
        Ok(())
    }

    async fn domain_selector(&self) -> Result<(), ServerFnError> {
        let pool = get_db().await?;
        loop {
            let records = sqlx::query!(
                "SElECT id, domain
            FROM Domains
            ORDER BY last_checked_dns ASC NULLS FIRST
            LIMIT $1
            OFFSET $2
            ",
                self.read_limit,
                (self.rx.len()
                    + self.bad_domains.lock()?.len()
                    + self.looked_up_domains.lock()?.len()) as i64
            )
            .fetch_all(&pool)
            .await?;
            if records.is_empty() {
                log::warn!("No records to check");
                tokio::time::sleep(std::time::Duration::from_secs(30)).await;
                continue;
            }

            for record in records {
                if let Ok(domain) = record.domain.parse::<Domain>() {
                    self.tx.send((DomainId(record.id), domain)).await?;
                } else {
                    log::warn!("Invalid domain: {}", record.domain);
                    self.bad_domains.lock()?.push(record.id);
                }
            }
        }
    }

    async fn run_task(
        &self,
        resolver_str: Arc<str>,
        resolver: Resolver,
    ) -> Result<(), ServerFnError> {
        while let Ok(task) = self.rx.recv().await {
            let (domain_id, domain) = task;
            let mut domain_str = domain.as_ref().to_string();
            domain_str.push('.');
            let result = resolver.lookup_ip(&domain_str).await;
            let result = parse_lookup_result(result);
            match result {
                Ok((ips, cnames)) => {
                    self.looked_up_domains.lock()?.push(domain_id.0);
                    {
                        let mut dns_ips = self.dns_ips.lock()?;
                        for ip in ips {
                            dns_ips.0.push(domain_id.0);
                            dns_ips.1.push(ip);
                        }
                    }
                    {
                        let mut dns_cnames = self.dns_cnames.lock()?;
                        for cname in cnames {
                            dns_cnames.0.push(domain_id.0);
                            dns_cnames.1.push(cname.as_ref().into());
                        }
                    }
                }
                Err(err) => {
                    log::warn!(
                        "Server: {} Error looking up domain {}: {}",
                        resolver_str,
                        domain.as_ref(),
                        err
                    );
                    self.failed_domains.fetch_add(1, Ordering::SeqCst);
                }
            }
        }
        Ok(())
    }

    async fn write_to_db(&self) -> Result<(), ServerFnError> {
        let pool = get_db().await?;
        let write_frequency: u64 = std::env::var("WRITE_FREQUENCY")?.parse()?;
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(write_frequency));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        interval.tick().await;
        loop {
            interval.tick().await;
            let looked_up_domains = std::mem::take(&mut *self.looked_up_domains.lock()?);
            let dns_ips = std::mem::take(&mut *self.dns_ips.lock()?);
            let dns_ips_domain_ids = &dns_ips.0;
            let dns_ips_ips = &dns_ips.1;
            let dns_cnames = std::mem::take(&mut *self.dns_cnames.lock()?);
            let dns_cnames_domain_ids = &dns_cnames.0;
            let dns_cnames_cname = &dns_cnames.1;
            let bad_domains = std::mem::take(&mut *self.bad_domains.lock()?);
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
                "DELETE FROM dns_ips WHERE domain_id = ANY($1::bigint[])",
                &looked_up_domains[..]
            )
            .execute(&mut *tx)
            .await?;
            sqlx::query!(
                "DELETE FROM dns_cnames WHERE domain_id = ANY($1::bigint[])",
                &looked_up_domains[..]
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
            if !bad_domains.is_empty() {
                log::info!("Removing {} bad domains", bad_domains.len());
                sqlx::query!(
                    "DELETE FROM domains
                    WHERE id = ANY($1::bigint[])",
                    &bad_domains[..]
                )
                .execute(&mut *tx)
                .await?;
            }
            tx.commit().await?;
        }
    }
}

pub async fn check_dns() -> Result<(), ServerFnError> {
    let resolver = DomainResolver::new()?;
    resolver.run().await?;
    Ok(())
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

pub async fn find_rule_matches() -> Result<(), ServerFnError> {
    dotenvy::dotenv()?;
    let pool = get_db().await?;
    let read_limit = std::env::var("READ_LIMIT")?.parse::<u32>()? as i64;
    let interval: u64 = std::env::var("RULE_MATCH_CHECK_INTERVAL")?.parse()?;
    let interval: std::time::Duration = std::time::Duration::from_secs(interval);
    let mut interval = tokio::time::interval(interval);
    loop {
        interval.tick().await;
        let mut tx = pool.begin().await?;
        let records = sqlx::query!(
            "SELECT id from Rules
            ORDER BY last_checked_matches ASC NULLS FIRST
            LIMIT $1",
            read_limit
        )
        .fetch_all(&mut *tx)
        .await?;

        let rule_ids = records
            .into_iter()
            .map(|record| record.id)
            .collect::<Vec<_>>();

        sqlx::query!(
            "DELETE FROM rule_matches WHERE rule_id = ANY($1::int[])",
            &rule_ids[..]
        )
        .execute(&mut *tx)
        .await?;
        sqlx::query!("
            INSERT INTO rule_matches(rule_id, domain_id)
            SELECT Rules.id AS rule_id, domains.id AS domain_id
            FROM Rules
            LEFT JOIN domain_rules ON Rules.domain_rule_id = domain_rules.id
            LEFT JOIN subdomains ON domain_rules.domain_id = subdomains.parent_domain_id AND domain_rules.subdomain = true
            LEFT JOIN ip_rules ON Rules.ip_rule_id = ip_rules.id
            LEFT JOIN dns_ips ON ip_rules.ip_network = dns_ips.ip_address
            LEFT JOIN dns_cnames ON dns_cnames.cname_domain_id = domain_rules.domain_id
                OR dns_cnames.cname_domain_id = subdomains.domain_id
            INNER JOIN domains ON domain_rules.domain_id = domains.id
                OR subdomains.domain_id = domains.id
                OR dns_ips.domain_id = domains.id
                OR dns_cnames.domain_id = domains.id
            INNER JOIN dns_ips AS dns_check ON dns_check.domain_id = domains.id AND dns_check.ip_address IS NOT NULL
            WHERE Rules.id = ANY($1::int[])
            ON CONFLICT DO NOTHING
            ",
        &rule_ids[..]).execute(&mut *tx).await?;
        let count = sqlx::query!(
            "SELECT COUNT(*) FROM rule_matches WHERE rule_id = ANY($1::int[])",
            &rule_ids[..]
        )
        .fetch_one(&mut *tx)
        .await?
        .count
        .unwrap_or(0);
        log::info!(
            "Checked {} rules and found {} matches",
            rule_ids.len(),
            count
        );
        sqlx::query!(
            "UPDATE rules
        SET last_checked_matches = now()
        WHERE id = ANY($1::int[])",
            &rule_ids[..]
        )
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
    }
}
