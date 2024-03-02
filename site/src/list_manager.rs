use leptos::{server, ServerFnError};

use serde::*;

#[derive(Clone, Debug, Serialize, Deserialize)]
struct CsvRecord {
    pub name: String,
    pub url: String,
    pub author: String,
    pub license: String,
    pub expires: u64,
    pub list_type: crate::FilterListType,
}

#[server]
pub async fn get_filter_map() -> Result<crate::FilterListMap, ServerFnError> {
    log::info!("Loading list");
    let contents = tokio::fs::read_to_string("../filterlists.csv").await?;
    let records = csv::Reader::from_reader(contents.as_bytes())
        .deserialize::<CsvRecord>()
        .collect::<Result<Vec<CsvRecord>, _>>()?;
    let filter_list_map = records
        .iter()
        .map(|csv_record| {
            let url = url::Url::parse(&csv_record.url)?;
            let url = crate::FilterListUrl::new(url, csv_record.list_type);
            let record = crate::FilterListRecord {
                name: csv_record.name.clone().into(),
                author: csv_record.author.clone().into(),
                license: csv_record.license.clone().into(),
                expires: std::time::Duration::from_secs(csv_record.expires),
            };
            Ok::<_, url::ParseError>((url, record))
        })
        .collect::<Result<
            std::collections::BTreeMap<crate::FilterListUrl, crate::FilterListRecord>,
            url::ParseError,
        >>()?;

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
    let last_version_data = last_version_data.map(|row| LastVersionData {
        last_updated: row.last_updated,
        etag: row.etag,
    });
    Ok(last_version_data)
}

#[server]
pub async fn get_last_updated(url: crate::FilterListUrl) -> Result<Option<chrono::NaiveDateTime>, ServerFnError> {
    get_last_version_data(&url).await.map(|data| data.map(|data| data.last_updated))
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
            last_updated.last_updated.format("%a, %d %b %Y %H:%M:%S GMT").to_string(),
        );
        if let Some(etag) = last_updated.etag {
            req = req.header("if-none-match", etag);
        }
    }
    let response = req.send().await?;
    match response.status() {
        reqwest::StatusCode::NOT_MODIFIED => {
            log::info!("Not modified {:?}", url_str);
            return Ok(());
        }
        reqwest::StatusCode::OK => {
            let headers = response.headers().clone();
            let etag = headers.get("etag").and_then(|item| item.to_str().ok());
            let body = response.text().await?;
            log::info!("Fetched {:?}", url_str);
            let new_last_updated = chrono::Utc::now();
            let list_format = url.list_format.as_str();
            log::info!("Updated {}", url_str);
            sqlx::query!(
                "INSERT INTO filterLists (url, lastUpdated, contents, format, etag) VALUES ($1, $2, $3, $4, $5)
                ON CONFLICT (url) DO UPDATE SET lastUpdated = $2, contents = $3, format = $4, etag = $5
                ",
                url_str,
                new_last_updated,
                body,
                list_format,
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
