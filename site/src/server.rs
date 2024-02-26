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
