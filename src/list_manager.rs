use std::str::FromStr;

use leptos::{server, ServerFnError};
use serde::*;

#[derive(Clone, Debug, Serialize, Deserialize)]
struct CsvRecord {
    pub name: String,
    pub url: url::Url,
    pub author: String,
    pub license: String,
    pub expires: u64,
    pub list_type: crate::FilterListType,
}

#[server]
pub async fn load_filter_map() -> Result<(), ServerFnError> {
    dotenvy::dotenv()?;
    let filterlists_path: std::path::PathBuf = std::env::var("FILTERLISTS_PATH")?.parse()?;
    let contents = tokio::fs::read_to_string(filterlists_path).await?;
    let records = csv::Reader::from_reader(contents.as_bytes())
        .deserialize::<CsvRecord>()
        .collect::<Result<Vec<CsvRecord>, _>>()?;
    let mut urls = Vec::new();
    let mut names = Vec::new();
    let mut formats = Vec::new();
    let mut expires_list = Vec::new();
    let mut authors = Vec::new();
    let mut licenses = Vec::new();

    for csv_record in &records {
        let url = csv_record.url.as_str().to_string();
        let name = csv_record.name.clone();
        let format = csv_record.list_type.as_str().to_string();
        let expires = csv_record.expires as i32;
        let author = csv_record.author.clone();
        let license = csv_record.license.clone();
        urls.push(url);
        names.push(name);
        formats.push(format);
        expires_list.push(expires);
        authors.push(author);
        licenses.push(license);
    }

    let pool = crate::server::get_db().await?;
    sqlx::query!(
        "INSERT INTO filterLists (url, name, format, expires, author, license)
        SELECT * FROM UNNEST($1::text[], $2::text[], $3::text[], $4::int[], $5::text[], $6::text[])
        ON CONFLICT (url) DO UPDATE
        SET name = EXCLUDED.name, format = EXCLUDED.format, expires = EXCLUDED.expires, author = EXCLUDED.author, license = EXCLUDED.license
        ",
        &urls,
        &names,
        &formats,
        &expires_list,
        &authors,
        &licenses
    ).execute(&pool).await?;
    write_filter_map().await?;
    Ok(())
}

#[server]
pub async fn watch_filter_map() -> Result<(), ServerFnError> {
    dotenvy::dotenv()?;
    let filterlists_path: std::path::PathBuf = std::env::var("FILTERLISTS_PATH")?.parse()?;
    use notify::Watcher;
    let notify = std::sync::Arc::new(tokio::sync::Notify::new());
    let notify2 = notify.clone();
    load_filter_map().await?;
    let mut watcher = notify::recommended_watcher(move |_| {
        notify.notify_one();
    })?;

    watcher.watch(&filterlists_path, notify::RecursiveMode::NonRecursive)?;
    let mut last_updated = std::time::Instant::now();
    loop {
        notify2.notified().await;
        if last_updated.elapsed() > std::time::Duration::from_millis(200) {
            load_filter_map().await?;
            last_updated = std::time::Instant::now();
        }
    }
}

#[server]
pub async fn write_filter_map() -> Result<(), ServerFnError> {
    use csv::Writer;
    dotenvy::dotenv()?;
    let filterlists_path: std::path::PathBuf = std::env::var("FILTERLISTS_PATH")?.parse()?;
    let pool = crate::server::get_db().await?;
    let rows = sqlx::query!("SELECT url, name, format, expires, author, license FROM filterLists")
        .fetch_all(&pool)
        .await?;
    let mut records = Vec::new();
    for record in rows {
        records.push(CsvRecord {
            name: record.name.unwrap_or(String::new()),
            url: url::Url::parse(&record.url.to_string())?,
            author: record.author.unwrap_or(String::new()),
            license: record.license.unwrap_or(String::new()),
            expires: record.expires as u64,
            list_type: crate::FilterListType::from_str(&record.format)?,
        });
    }
    records.sort_by_key(|record| (record.name.clone(), record.url.clone()));
    records.reverse();
    let mut wtr = Writer::from_path(filterlists_path)?;
    for record in records {
        wtr.serialize(record)?;
    }
    Ok(())
}

#[server]
pub async fn get_filter_map() -> Result<crate::FilterListMap, ServerFnError> {
    let pool = crate::server::get_db().await?;
    let rows = sqlx::query!("SELECT url, name, format, expires, author, license FROM filterLists")
        .fetch_all(&pool)
        .await?;

    let mut filter_list_map = std::collections::BTreeMap::new();
    for record in rows {
        let url = url::Url::parse(&record.url)?.into();
        let record = crate::FilterListRecord {
            name: record.name.unwrap_or(String::new()).into(),
            list_format: crate::FilterListType::from_str(&record.format)?,
            author: record.author.unwrap_or(String::new()).into(),
            license: record.license.unwrap_or(String::new()).into(),
            expires: std::time::Duration::from_secs(record.expires as u64),
        };
        filter_list_map.insert(url, record);
    }

    Ok(crate::FilterListMap(filter_list_map))
}

#[cfg(feature = "ssr")]
struct LastVersionData {
    last_updated: chrono::NaiveDateTime,
    etag: Option<String>,
}

#[cfg(feature = "ssr")]
async fn get_last_version_data(
    url: &crate::FilterListUrl,
) -> Result<Option<LastVersionData>, ServerFnError> {
    let pool = crate::server::get_db().await?;
    let url_str = url.as_str();
    #[allow(non_camel_case_types)]
    let last_version_data = sqlx::query!(
        r#"SELECT lastUpdated as "last_updated: chrono::NaiveDateTime", etag FROM filterLists WHERE url = $1"#,
        url_str
    )
    .fetch_one(&pool)
    .await
    .ok();
    let last_version_data = last_version_data.and_then(|row| {
        Some(LastVersionData {
            last_updated: row.last_updated?,
            etag: row.etag,
        })
    });
    Ok(last_version_data)
}

#[server]
pub async fn get_last_updated(
    url: crate::FilterListUrl,
) -> Result<Option<chrono::NaiveDateTime>, ServerFnError> {
    get_last_version_data(&url)
        .await
        .map(|data| data.map(|data| data.last_updated))
}

#[cfg(feature = "ssr")]
#[derive(thiserror::Error, Debug)]
enum UpdateListError {
    #[error("Failed to fetch list")]
    FailedToFetch,
}

#[server]
pub async fn update_list(url: crate::FilterListUrl) -> Result<(), ServerFnError> {
    log::info!("Updating {}", url.as_str());
    let pool = crate::server::get_db().await?;
    let url_str = url.as_str();
    let last_updated = get_last_version_data(&url).await?;
    let mut req = reqwest::Client::new().get(url_str);
    if let Some(last_updated) = last_updated {
        req = req.header(
            "if-modified-since",
            last_updated
                .last_updated
                .format("%a, %d %b %Y %H:%M:%S GMT")
                .to_string(),
        );
        if let Some(etag) = last_updated.etag {
            req = req.header("if-none-match", etag);
        }
    }
    let response = req.send().await?;
    match response.status() {
        reqwest::StatusCode::NOT_MODIFIED => {
            log::info!("Not modified {:?}", url_str);
            Ok(())
        }
        reqwest::StatusCode::OK => {
            let headers = response.headers().clone();
            let etag = headers.get("etag").and_then(|item| item.to_str().ok());
            let body = response.text().await?;
            let new_last_updated = chrono::Utc::now();
            log::info!("Updated {} size ({})", url_str, body.len());
            sqlx::query!(
                "UPDATE filterLists
                SET lastUpdated = $2, contents = $3, etag = $4
                WHERE url = $1
                ",
                url_str,
                new_last_updated,
                body,
                etag
            )
            .execute(&pool)
            .await?;
            Ok(())
        }
        status => {
            log::error!("Error fetching {}: {:?}", url_str, status);
            Err(UpdateListError::FailedToFetch.into())
        }
    }
}

#[server]
pub async fn delete_list(url: crate::FilterListUrl) -> Result<(), ServerFnError> {
    let pool = crate::server::get_db().await?;
    let url_str = url.as_str();
    sqlx::query!(
        "DELETE FROM list_rules
    WHERE list_rules.list_id IN (
        SELECT id FROM filterLists WHERE url = $1
    )",
        url_str
    )
    .execute(&pool)
    .await?;
    sqlx::query!("DELETE FROM filterLists WHERE url = $1", url_str)
        .execute(&pool)
        .await?;
    write_filter_map().await?;
    Ok(())
}
