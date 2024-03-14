use leptos::*;

trait Task {
    type Error;
    fn name(&self) -> &str;
    async fn run_once(&self) -> Result<String, Self::Error>;
}
#[cfg(feature = "ssr")]
struct GarbageCollectRuleSource {}

#[cfg(feature = "ssr")]
impl Task for GarbageCollectRuleSource {
    type Error = ServerFnError;
    fn name(&self) -> &str {
        "Garbage collect rule_source"
    }
    async fn run_once(&self) -> Result<String, Self::Error> {
        let pool = crate::server::get_db().await?;
        let rows_removed = sqlx::query!(
            "delete from rule_source where not exists
            (select 1 from list_rules where source_id=rule_source.id)"
        )
        .execute(&pool)
        .await?
        .rows_affected();
        Ok(format!(
            "Garbage collected {} rows from rule_source",
            rows_removed
        ))
    }
}

#[cfg(feature = "ssr")]
async fn register_task<T: Task>(_task: T) {
    let _pool = crate::server::get_db().await.unwrap();
}

#[component]
pub fn TaskView() -> impl IntoView {
    view! {
        <div>
            <h1>"Tasks"</h1>
            <p>"This is the tasks view"</p>
        </div>
    }
}


