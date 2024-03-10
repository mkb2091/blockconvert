use crate::list_parser::Domain;
use crate::{DbInitError, DomainId, FilterListUrl};
use hickory_resolver::error::ResolveError;
use leptos::*;
use notify::Watcher;
use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
use tokio_util::sync::CancellationToken;

static SQLITE_POOL: tokio::sync::OnceCell<sqlx::PgPool> = tokio::sync::OnceCell::const_new();

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
        let records = sqlx::query!(
            "SELECT domain from domains
        WHERE processed_subdomains = false
        LIMIT $1",
            LIMIT
        )
        .fetch_all(&pool)
        .await?;
        if records.is_empty() {
            tokio::time::sleep(Duration::from_secs(30)).await;
            continue;
        }
        let mut checked_domains = Vec::new();

        let mut all_domains = Vec::new();
        let mut all_parents = Vec::new();

        for record in records {
            checked_domains.push(record.domain.clone());
            let Ok(domain) = record.domain.parse::<Domain>() else {
                continue;
            };
            let parents = domain
                .as_ref()
                .match_indices('.')
                .map(|(i, _)| record.domain.split_at(i + 1).1)
                .filter_map(|parent| parent.parse::<Domain>().ok());
            for parent in parents {
                all_domains.push(domain.clone());
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
            &parent_set[..] as _
        )
        .execute(&pool)
        .await?;

        let mut tx = pool.begin().await?;
        sqlx::query!(
            "INSERT INTO subdomains (domain_id, parent_domain_id)
            SELECT domains_with_parents.id, parents.id
            FROM UNNEST($1::text[], $2::text[]) AS t(domain, parent)
            INNER JOIN domains AS domains_with_parents ON domains_with_parents.domain = t.domain
            INNER JOIN domains AS parents ON parents.domain = t.parent
            ON CONFLICT DO NOTHING",
            &all_domains[..] as _,
            &all_parents[..] as _,
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
    failed_cache_size: usize,
    failed_domains: Arc<Mutex<Vec<i64>>>,
    written_domains: Arc<Mutex<Vec<i64>>>,
    bad_domains: Arc<Mutex<Vec<i64>>>,
    looked_up_domains: Arc<Mutex<Vec<i64>>>,
    dns_ips: Arc<Mutex<(Vec<i64>, Vec<ipnetwork::IpNetwork>)>>,
    dns_cnames: Arc<Mutex<(Vec<i64>, Vec<Domain>)>>,
    token: CancellationToken,
}

impl DomainResolver {
    fn new(token: CancellationToken) -> Result<Self, ServerFnError> {
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
            opts.timeout = Duration::from_secs_f32(5.0);
            let resolver = Arc::new(hickory_resolver::AsyncResolver::tokio(config, opts));
            resolvers.push((server, resolver));
        }

        if resolvers.is_empty() {
            return Err(ServerFnError::new("Empty DNS server list"));
        }
        let (tx, rx) = async_channel::bounded(read_limit as usize);

        let bad_domains = Arc::new(Mutex::new(Vec::new()));
        let failed_cache_size = std::env::var("FAILED_CACHE_SIZE")?.parse()?;

        Ok(Self {
            resolvers,
            bad_domains,
            tx,
            rx,
            read_limit,
            failed_cache_size,
            failed_domains: Arc::new(Mutex::new(Vec::new())),
            written_domains: Arc::new(Mutex::new(Vec::new())),
            looked_up_domains: Arc::new(Mutex::new(Vec::new())),
            dns_ips: Default::default(),
            dns_cnames: Default::default(),
            token,
        })
    }

    async fn run(&self) -> Result<(), ServerFnError> {
        dotenvy::dotenv()?;
        let concurrent_lookups: usize = std::env::var("CONCURRENT_LOOKUPS")?.parse()?;

        let mut tasks = tokio::task::JoinSet::new();

        for resolver in &self.resolvers {
            for _ in 0..concurrent_lookups {
                let resolver_str = resolver.0.clone();
                let resolver = resolver.1.clone();
                let resolver_self = self.clone();
                let task = async move {
                    let token = resolver_self.token.clone();
                    tokio::select! {
                    _ = token.cancelled() => {
                        log::info!("Shutting down DNS resolver");
                        Ok(())},
                    res =
                    resolver_self.run_task(resolver_str, resolver) => res}
                };
                tasks.spawn(task);
            }
        }
        let selector = self.clone();
        tasks.spawn(async move {
            let token = selector.token.clone();
            tokio::select! {
            _ = token.cancelled() => {
                log::info!("Shutting down DNS selector");
                return Ok(());}
            res = selector.domain_selector() => res
            }
        });
        let writer = self.clone();
        tasks.spawn(async move { writer.write_to_db().await });
        while let Some(result) = tasks.join_next().await {
            let _ = result?;
        }
        Ok(())
    }

    async fn domain_selector(&self) -> Result<(), ServerFnError> {
        let pool = get_db().await?;
        let mut started_domains = HashSet::new();
        let mut failed_domains = std::collections::VecDeque::<i64>::new();
        loop {
            {
                failed_domains.extend(std::mem::take(&mut *self.failed_domains.lock()?));
            }
            while failed_domains.len() > self.failed_cache_size {
                if let Some(failed) = failed_domains.pop_front() {
                    started_domains.remove(&failed);
                }
            }
            let written_domains = std::mem::take(&mut *self.written_domains.lock()?);
            for domain_id in written_domains {
                started_domains.remove(&domain_id);
            }
            let limit = self.read_limit + started_domains.len() as i64;
            let records = sqlx::query!(
                "SELECT id, domain
                        FROM Domains
                        WHERE last_checked_dns IS NULL
                        ORDER BY id DESC NULLS FIRST
                        LIMIT $1",
                limit
            )
            .fetch_all(&pool)
            .await?;
            let recheck_domains = if records.len() < limit as usize {
                sqlx::query!(
                    "SELECT id, domain
                            FROM Domains
                            ORDER BY last_checked_dns ASC NULLS FIRST
                            LIMIT $1",
                    limit
                )
                .fetch_all(&pool)
                .await?
            } else {
                vec![]
            };

            let records = records.into_iter().map(|record| (record.id, record.domain));
            let recheck_domains = recheck_domains
                .into_iter()
                .map(|record| (record.id, record.domain));
            let mut has_domains = false;
            for (domain_id, domain_str) in records.chain(recheck_domains) {
                has_domains = true;
                if !started_domains.insert(domain_id) {
                    continue;
                }
                if let Ok(domain) = domain_str.parse::<Domain>() {
                    if domain_str == domain.as_ref() {
                        self.tx.send((DomainId(domain_id), domain)).await?;
                        continue;
                    }
                }
                log::warn!("Invalid domain: {}", domain_str);
                self.bad_domains.lock()?.push(domain_id);
            }
            if !has_domains {
                log::info!("No domains to check, sleeping");
                tokio::time::sleep(Duration::from_secs(30)).await;
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
                            dns_cnames.1.push(cname);
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
                    self.failed_domains.lock()?.push(domain_id.0);
                }
            }
        }
        Ok(())
    }

    async fn write_to_db(&self) -> Result<(), ServerFnError> {
        let pool = get_db().await?;
        let write_frequency: u64 = std::env::var("WRITE_FREQUENCY")?.parse()?;
        let mut interval = tokio::time::interval(Duration::from_secs(write_frequency));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        interval.tick().await;
        loop {
            tokio::select! {
                _ = interval.tick() => {},
                _ = self.token.cancelled() => {
                    log::info!("Shutting down DNS writer")
                }
            }
            let looked_up_domains = std::mem::take(&mut *self.looked_up_domains.lock()?);
            let looked_up_domains_deduped =
                looked_up_domains.iter().cloned().collect::<HashSet<_>>();
            assert_eq!(looked_up_domains.len(), looked_up_domains_deduped.len());
            let dns_ips = std::mem::take(&mut *self.dns_ips.lock()?);
            let dns_ips_domain_ids = &dns_ips.0;
            let dns_ips_ips = &dns_ips.1;
            let dns_cnames = std::mem::take(&mut *self.dns_cnames.lock()?);
            let dns_cnames_domain_ids = &dns_cnames.0;
            let dns_cnames_cname = &dns_cnames.1;
            let bad_domains = std::mem::take(&mut *self.bad_domains.lock()?);
            let total_cnames = dns_cnames_cname
                .iter()
                .collect::<HashSet<_>>()
                .into_iter()
                .cloned()
                .collect::<Vec<Domain>>();
            let new_domains_from_cnames = sqlx::query!(
                "INSERT INTO domains(domain)
                    SELECT domain FROM UNNEST($1::text[]) as t(domain)
                    ON CONFLICT DO NOTHING",
                &total_cnames[..] as _
            )
            .execute(&pool)
            .await?
            .rows_affected();

            let mut tx = pool.begin().await?;
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
                        &dns_cnames_cname[..] as _
                    )
                    .execute(&mut *tx)
                    .await?;

            let updated_domains = sqlx::query!(
                "UPDATE domains
                    SET last_checked_dns = now()
                    WHERE id = ANY($1::bigint[])",
                &looked_up_domains[..]
            )
            .execute(&mut *tx)
            .await?
            .rows_affected();
            assert_eq!(updated_domains, looked_up_domains.len() as u64);

            tx.commit().await?;
            self.written_domains.lock()?.extend(&looked_up_domains);

            if !bad_domains.is_empty() {
                log::info!("Removing {} bad domains", bad_domains.len());
                sqlx::query!(
                    "DELETE FROM domains
                    WHERE id = ANY($1::bigint[])",
                    &bad_domains[..]
                )
                .execute(&pool)
                .await?;
            }

            self.written_domains.lock()?.extend(&bad_domains);

            log::info!(
                "Looked up {} domains, got {} ips, {} cnames ({} new)",
                looked_up_domains.len(),
                dns_ips_domain_ids.len(),
                dns_cnames_domain_ids.len(),
                new_domains_from_cnames
            );
            if self.token.is_cancelled() {
                return Ok(());
            }
        }
    }
}

pub async fn check_dns(token: CancellationToken) -> Result<(), ServerFnError> {
    let resolver = DomainResolver::new(token)?;
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
            let domains_vec = domains.drain().collect::<Vec<_>>();
            let record = sqlx::query!(
                "INSERT INTO domains (domain)
            SELECT domain FROM UNNEST($1::text[]) as t(domain)
            ON CONFLICT DO NOTHING",
                &domains_vec[..] as _
            )
            .execute(&pool)
            .await?;
            let inserted = record.rows_affected();
            if inserted != 0 {
                log::info!("Inserted {} domains", inserted);
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
    let interval: Duration = Duration::from_secs(interval);
    let mut interval = tokio::time::interval(interval);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
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
            LEFT JOIN ip_rules ON Rules.ip_rule_id = ip_rules.id AND ip_rules.allow=false
            LEFT JOIN dns_ips ON ip_rules.ip_network = dns_ips.ip_address
            LEFT JOIN dns_cnames ON (dns_cnames.cname_domain_id = domain_rules.domain_id
                OR dns_cnames.cname_domain_id = subdomains.domain_id) AND domain_rules.allow=false
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

pub async fn update_expired_lists() -> Result<(), ServerFnError> {
    let pool = get_db().await?;
    loop {
        let record = sqlx::query!(
            r#"SELECT url, lastupdated+expires * INTERVAL '1 seconds' AS nextupdate
            FROM filterLists ORDER BY nextupdate NULLS FIRST
            LIMIT 1"#r
        )
        .fetch_one(&pool)
        .await?;
        if let Some(next_update) = record.nextupdate {
            let next_update = next_update - chrono::Utc::now();
            if let Ok(next_update) = next_update.to_std() {
                tokio::time::sleep(next_update).await;
            }
        }
        let url: FilterListUrl = record.url.parse()?;
        if let Err(err) = crate::list_manager::update_list(url.clone()).await {
            log::warn!("Error updating list {}: {:?}", url.as_str(), err);
        }
    }
}

pub async fn build_list() -> Result<(), ServerFnError> {
    // return Ok(());
    dotenvy::dotenv()?;
    let pool = get_db().await?;
    sqlx::query!("DELETE FROM allow_domains")
        .execute(&pool)
        .await?;
    sqlx::query!("DELETE FROM block_domains")
        .execute(&pool)
        .await?;
    let allow_record = sqlx::query!(
        "INSERT INTO allow_domains(domain_id)
        SELECT rule_matches.domain_id from rule_matches
        INNER JOIN rules ON rule_matches.rule_id = rules.id
        LEFT JOIN domain_rules ON rules.domain_rule_id = domain_rules.id
        LEFT JOIN ip_rules ON rules.ip_rule_id = ip_rules.id
        WHERE domain_rules.allow = true OR ip_rules.allow = true
        ON CONFLICT DO NOTHING",
    )
    .execute(&pool)
    .await?;
    log::info!("Inserted {} allow rules", allow_record.rows_affected());
    let record = sqlx::query!(
        "INSERT INTO block_domains(domain_id)
        SELECT rule_matches.domain_id from rule_matches
        INNER JOIN rules ON rule_matches.rule_id = rules.id
        LEFT JOIN domain_rules ON rules.domain_rule_id = domain_rules.id
        LEFT JOIN ip_rules ON rules.ip_rule_id = ip_rules.id
        WHERE domain_rules.allow = false OR ip_rules.allow = false
        ON CONFLICT DO NOTHING",
    )
    .execute(&pool)
    .await?;
    log::info!("Inserted {} block rules", record.rows_affected());

    {
        let records = sqlx::query!("select domain from block_domains
    INNER JOIN domains ON block_domains.domain_id = domains.id
    where not exists(select 1 from allow_domains where allow_domains.domain_id=block_domains.domain_id)
    ORDER BY domain").fetch_all(&pool).await?;
        let domain_file = tokio::fs::File::create("output/domains.txt").await?;
        let mut domain_buf = tokio::io::BufWriter::new(domain_file);
        let adblock_file = tokio::fs::File::create("output/adblock.txt").await?;
        let mut adblock_buf = tokio::io::BufWriter::new(adblock_file);
        let mut count = 0;
        for record in records {
            domain_buf.write_all(record.domain.as_bytes()).await?;
            domain_buf.write_all(b"\n").await?;

            adblock_buf.write_all(b"||").await?;
            adblock_buf.write_all(record.domain.as_bytes()).await?;
            adblock_buf.write_all(b"^\n").await?;

            count += 1;
        }
        domain_buf.flush().await?;
        log::info!("Wrote {} rules to output/domains.txt", count);
        adblock_buf.flush().await?;
        log::info!("Wrote {} rules to output/adblock.txt", count);
    }
    sqlx::query!("DELETE FROM allow_domains")
        .execute(&pool)
        .await?;
    sqlx::query!("DELETE FROM block_domains")
        .execute(&pool)
        .await?;
    Ok(())
}

async fn garbage_collect_rule_source(pool: &sqlx::PgPool) -> Result<u64, ServerFnError> {
    let record = sqlx::query!(
        "delete from rule_source where not exists
    (select 1 from list_rules where source_id=rule_source.id)"
    )
    .execute(pool)
    .await?;
    Ok(record.rows_affected())
}

async fn garbage_collect_rules(pool: &sqlx::PgPool) -> Result<u64, ServerFnError> {
    let record = sqlx::query!(
        "delete from Rules where not exists
    (select 1 from rule_source where Rules.id=rule_source.rule_id)"
    )
    .execute(pool)
    .await?;
    Ok(record.rows_affected())
}

async fn garbage_collect_rule_matches(pool: &sqlx::PgPool) -> Result<u64, ServerFnError> {
    let record = sqlx::query!(
        "delete from rule_matches where not exists
    (select 1 from rules where Rules.id=rule_matches.rule_id)"
    )
    .execute(pool)
    .await?;
    Ok(record.rows_affected())
}

pub async fn garbage_collect() -> Result<(), ServerFnError> {
    let pool = get_db().await?;
    let gc_interval = std::env::var("GC_INTERVAL")?.parse::<u64>()?;
    let mut interval = tokio::time::interval(Duration::from_secs(gc_interval));
    interval.tick().await;
    loop {
        interval.tick().await;
        let rows = garbage_collect_rule_source(&pool).await?;
        if rows > 0 {
            log::info!("Garbage collected {} rule sources", rows);
        }
        interval.tick().await;
        let rows = garbage_collect_rules(&pool).await?;
        if rows > 0 {
            log::info!("Garbage collected {} rules", rows);
        }
        interval.tick().await;
        let rows = garbage_collect_rule_matches(&pool).await?;
        if rows > 0 {
            log::info!("Garbage collected {} rule matches", rows);
        }
    }
}

pub async fn run_cmd(token: CancellationToken) -> Result<(), ServerFnError> {
    dotenvy::dotenv()?;
    let cmd = std::env::var("TASK_CMD")?;
    let mut interval = tokio::time::interval(Duration::from_secs(300));
    loop {
        tokio::select! {
        _ = token.cancelled() => {
            log::info!("Shutting down run_cmd");
            return Ok(());},
            _ = interval.tick() => {}}
        let output = tokio::process::Command::new(&cmd).output().await;
        if let Err(err) = output {
            log::warn!("Error running command: {:?}", err);
        }
    }
}

const CERTSTREAM_URL: &str = "wss://certstream.calidog.io/domains-only";

#[derive(serde::Deserialize)]
struct CertStreamMessage {
    data: Vec<String>,
}

async fn stream_certstream(
    domains: tokio::sync::mpsc::UnboundedSender<Domain>,
) -> Result<(), ServerFnError> {
    use futures::StreamExt;
    let (mut client, _) = tokio_tungstenite::connect_async(CERTSTREAM_URL).await?;
    while let Some(Ok(msg)) = client.next().await {
        if let tokio_tungstenite::tungstenite::protocol::Message::Text(msg) = msg {
            let msg: CertStreamMessage = serde_json::from_str(&msg)?;
            for domain in msg.data {
                let Ok(domain) = domain.parse::<Domain>() else {
                    continue;
                };
                domains.send(domain)?;
            }
        }
    }
    Ok(())
}

async fn write_certstream(
    mut rx: tokio::sync::mpsc::UnboundedReceiver<Domain>,
    token: CancellationToken,
) -> Result<(), ServerFnError> {
    dotenvy::dotenv()?;
    let pool = get_db().await?;
    let interval = std::env::var("WRITE_FREQUENCY")?.parse::<u64>()?;
    let mut interval = tokio::time::interval(Duration::from_secs(interval));
    interval.tick().await;
    loop {
        tokio::select! {_ = interval.tick() => {},
            _ = token.cancelled() => log::info!("Shutting down certstream writer")
        }
        let mut domains = Vec::new();
        while let Ok(domain) = rx.try_recv() {
            domains.push(domain.as_ref().to_string());
        }
        if domains.is_empty() {
            continue;
        }
        let record = sqlx::query!(
            "INSERT INTO domains(domain)
            SELECT domain FROM UNNEST($1::text[]) as t(domain)
            ON CONFLICT DO NOTHING",
            &domains[..]
        )
        .execute(&pool)
        .await?;
        log::info!(
            "Certstream inserted {} new domains (out of {} found)",
            record.rows_affected(),
            domains.len()
        );
        if token.is_cancelled() {
            return Ok(());
        }
    }
}

pub async fn certstream(token: CancellationToken) -> Result<(), ServerFnError> {
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    let _ = tokio::spawn(async move {
        loop {
            if let Err(err) = stream_certstream(tx.clone()).await {
                log::warn!("Error streaming certstream: {:?}", err);
                tokio::time::sleep(Duration::from_secs(10)).await;
            }
        }
    });
    write_certstream(rx, token).await?;
    Ok(())
}
