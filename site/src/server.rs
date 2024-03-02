use crate::list_parser::Domain;
use futures::SinkExt;
use futures::StreamExt;
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
    let _ = dotenv::dotenv();
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
            log::info!("No more records to process, sleeping");
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

pub async fn ct_find_domains() -> Result<(), ServerFnError> {
    for log in ct_logs::LOGS.iter() {
        log::info!("Log URL: {:?}", log.url);
    }
    Ok(())
}
