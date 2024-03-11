use crate::DbInitError;
use crate::{domain::Domain, filterlist::FilterListUrl};

use leptos::*;
use notify::Watcher;
use std::collections::HashSet;

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
    dotenvy::dotenv()?;
    let read_limit: usize = std::env::var("READ_LIMIT")?.parse()?;
    let pool = get_db().await?;
    loop {
        let records = sqlx::query!(
            "SELECT domain from domains
        WHERE processed_subdomains = false
        LIMIT $1",
            read_limit as i64
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
        .execute(&pool)
        .await?;
        sqlx::query!(
            "INSERT INTO domains (domain)
    SELECT domain FROM UNNEST($1::text[]) as t(domain)
    ON CONFLICT(domain)
    DO UPDATE SET processed_subdomains = true",
            &checked_domains[..]
        )
        .execute(&pool)
        .await?;
    }
}

pub async fn check_dns(token: CancellationToken) -> Result<(), ServerFnError> {
    let resolver = crate::domain::DomainResolver::new(token)?;
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
                log::info!("Inserted {} domains from Pihole logs", inserted);
            }
            last_wrote = std::time::Instant::now();
        }
    }

    Ok(())
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
        if let Err(err) = crate::filterlist::update_list(url.clone()).await {
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
    tokio::spawn(async move {
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
