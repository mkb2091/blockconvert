static SQLITE_POOL: tokio::sync::OnceCell<sqlx::SqlitePool> = tokio::sync::OnceCell::const_new();

pub async fn get_db() -> Result<sqlx::SqlitePool, sqlx::Error> {
    SQLITE_POOL.get_or_try_init(|| {
        sqlx::SqlitePool::connect("sqlite:db.sqlite")
    }).await.cloned()
}