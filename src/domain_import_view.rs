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

#[server(ImportDomainsFromUrl)]
async fn import_domains_from_url(url: String) -> Result<(), ServerFnError> {
    dotenvy::dotenv()?;
    let batch_size: usize = std::env::var("READ_LIMIT")?.parse()?;
    let pool = crate::server::get_db().await?;
    log::info!("Importing domains from {}", url);
    let req = reqwest::get(&url).await?;
    let body = req.text().await?;
    let domains = body
        .split(|c: char| !(c.is_ascii_alphanumeric() || c == '.'))
        .filter(|domain| domain.parse::<Domain>().is_ok())
        .map(|domain| domain.to_string())
        .collect::<Vec<_>>();
    log::info!("Sample: {:?}", &domains[..100]);
    log::info!("Importing {} domains", domains.len());
    for i in (0..domains.len()).step_by(batch_size) {
        sqlx::query!(
            "INSERT INTO domains (domain, processed_subdomains)
        SELECT domain, false FROM UNNEST($1::text[]) as t(domain)
        ON CONFLICT DO NOTHING",
            &domains[i..i + batch_size]
        )
        .execute(&pool)
        .await?;
    }
    log::info!("Imported");
    Ok(())
}

#[component]
pub fn DomainImportView() -> impl IntoView {
    let import_list = create_server_action::<ImportDomainList>();
    let import_url = create_server_action::<ImportDomainsFromUrl>();
    view! {
        <div>
            <h1>"Import Domains"</h1>

            <ActionForm action=import_url>
                <label>
                    "URL: "
                    <input class="input input-bordered" placeholder="url" id="url" name="url"/>
                </label>
                <button class="btn btn-primary" type="submit">
                    "Submit"
                </button>
            </ActionForm>

            <ActionForm action=import_list>
                <label>
                    <p>"Domains: "</p>
                    <textarea
                        class="textarea textarea-bordered w-full sm:max-w-3xl"
                        placeholder="domains"
                        id="domains"
                        name="domains"
                        rows="5"
                    ></textarea>
                </label>
                <p>
                    <button class="btn btn-primary" type="submit">
                        "Submit"
                    </button>
                </p>
            </ActionForm>
        </div>
    }
}
