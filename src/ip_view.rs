use leptos::*;
use leptos_router::*;
use std::{collections::BTreeSet, net::IpAddr};

use crate::{app::Loading, domain::DomainId};

#[server]
async fn get_domans_which_resolve_to_ip(
    ip: IpAddr,
) -> Result<BTreeSet<(DomainId, String)>, ServerFnError> {
    let ip: ipnetwork::IpNetwork = ip.into();
    let records = sqlx::query!(
        r#"SELECT domains.id as "domain_id: DomainId", domain
    from dns_ips
    INNER JOIN domains ON dns_ips.domain_id = domains.id
    WHERE dns_ips.ip_address = $1"#r,
        ip
    )
    .fetch_all(&crate::server::get_db().await?)
    .await?;
    let domains = records
        .into_iter()
        .map(|record| (record.domain_id, record.domain))
        .collect::<BTreeSet<_>>();
    Ok(domains)
}

#[component]
fn DomainsWhichResolveTo(get_ip: GetIp) -> impl IntoView {
    let domain_results = create_resource(get_ip, |ip| async move {
        let ip = ip?;
        let results = get_domans_which_resolve_to_ip(ip).await?;
        Ok::<_, ServerFnError>(results)
    });
    view! {
        <Transition fallback=move || {
            view! { <p>"Loading" <Loading/></p> }
        }>
            {move || match domain_results.get() {
                Some(Ok(domains)) => {
                    view! {
                        <div>
                            <p>"Domains which resolve to this IP Address"</p>
                            <ul class="grid grid-cols-2 gap-2">
                                <For
                                    each=move || { domains.clone() }
                                    key=|(domain_id, _domain)| *domain_id
                                    children=|(_domain_id, domain)| {
                                        view! {
                                            <li>
                                                <A
                                                    href=format!("/domain/{domain}")
                                                    class="link link-neutral"
                                                >
                                                    {domain}
                                                </A>
                                            </li>
                                        }
                                    }
                                />

                            </ul>
                        </div>
                    }
                        .into_view()
                }
                _ => view! { <p>"Error"</p> }.into_view(),
            }}

        </Transition>
    }
}

type GetIp = Box<dyn Fn() -> Result<IpAddr, ParamsError>>;

#[derive(Params, PartialEq)]
struct IpParam {
    ip: Option<IpAddr>,
}

#[component]
pub fn IpView() -> impl IntoView {
    let params = use_params::<IpParam>();
    let get_ip = move || {
        params.with(|param| {
            param.as_ref().map_err(Clone::clone).and_then(|param| {
                param
                    .ip
                    .ok_or_else(|| ParamsError::MissingParam("No domain".into()))
            })
        })
    };
    view! {
        <div>
            <h1 class="text-2xl font-bold text-gray-800">{"IP Address: "} {get_ip}</h1>
            <DomainsWhichResolveTo get_ip=Box::new(get_ip)/>
        </div>
    }
}
