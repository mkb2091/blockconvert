use crate::list_parser::Domain;
use leptos::*;
use leptos_router::*;

#[server(ImportDomainList)]
async fn import_domain_list(domains: String) -> Result<(), ServerFnError> {
    let domains = domains
        .lines()
        .filter_map(|line| {
            let domain: Result<Domain, _> = (*line).parse();
            domain.ok().map(|domain| domain.as_ref().to_string())
        })
        .collect::<Vec<_>>();
    log::info!("Importing {} domains", domains.len());
    sqlx::query!(
        "INSERT INTO domains (domain, processed_subdomains)
        SELECT domain, false FROM UNNEST($1::text[]) as t(domain)
        ON CONFLICT DO NOTHING",
        &domains[..]
    )
    .execute(&crate::server::get_db().await?)
    .await?;
    log::info!("Imported");
    Ok(())
}

#[component]
pub fn DomainImportView() -> impl IntoView {
    let import_list = create_server_action::<ImportDomainList>();
    view! {
        <div>
            <h1>"Import Domains"</h1>
            <ActionForm action=import_list>
                <label>
                    "Domains: "
                    <textarea
                        class="textarea textarea-bordered"
                        placeholder="domains"
                        id="domains"
                        name="domains"
                    ></textarea>
                </label>
                <button class="btn btn-primary" type="submit">
                    "Submit"
                </button>
            </ActionForm>
        </div>
    }
}
