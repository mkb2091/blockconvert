#[cfg(feature = "ssr")]
use crate::rule::RuleData;
use crate::{
    app::Loading, filterlist::{FilterListLink, FilterListUrl}, rule::DisplayRule,
    rule::RuleId, source::SourceId,
};
use leptos::*;
use leptos_router::*;
#[cfg(feature = "ssr")]
pub use lookup_dns_task::DomainResolver;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, net::IpAddr, str::FromStr, sync::Arc};

#[cfg_attr(feature = "ssr", derive(sqlx::Encode, sqlx::Decode))]
#[derive(Serialize, Deserialize, Debug, Copy, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct DomainId(i64);

#[derive(Debug, Clone, thiserror::Error)]
pub enum DomainParseError {
    Addr,
    HickoryProto,
    Custom,
}

impl std::fmt::Display for DomainParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Invalid domain")
    }
}

impl<'a> From<addr::error::Error<'a>> for DomainParseError {
    fn from(_: addr::error::Error) -> Self {
        DomainParseError::Addr
    }
}

impl From<hickory_proto::error::ProtoError> for DomainParseError {
    fn from(_: hickory_proto::error::ProtoError) -> Self {
        DomainParseError::HickoryProto
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(transparent)]
pub struct Domain(Arc<str>);

#[cfg(feature = "ssr")]
impl sqlx::Type<sqlx::Postgres> for Domain {
    fn type_info() -> sqlx::postgres::PgTypeInfo {
        <&str as sqlx::Type<sqlx::Postgres>>::type_info()
    }

    fn compatible(ty: &sqlx::postgres::PgTypeInfo) -> bool {
        <&str as sqlx::Type<sqlx::Postgres>>::compatible(ty)
    }
}
#[cfg(feature = "ssr")]
impl sqlx::postgres::PgHasArrayType for Domain {
    fn array_type_info() -> sqlx::postgres::PgTypeInfo {
        <&str as sqlx::postgres::PgHasArrayType>::array_type_info()
    }

    fn array_compatible(ty: &sqlx::postgres::PgTypeInfo) -> bool {
        <&str as sqlx::postgres::PgHasArrayType>::array_compatible(ty)
    }
}
#[cfg(feature = "ssr")]
impl sqlx::Encode<'_, sqlx::Postgres> for Domain {
    fn encode_by_ref(&self, buf: &mut sqlx::postgres::PgArgumentBuffer) -> sqlx::encode::IsNull {
        <&str as sqlx::Encode<sqlx::Postgres>>::encode(self.as_ref(), buf)
    }
}

impl AsRef<str> for Domain {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl FromStr for Domain {
    type Err = DomainParseError;
    fn from_str(domain: &str) -> Result<Domain, Self::Err> {
        if domain.len() > 253 {
            return Err(DomainParseError::Custom);
        }
        let mut domain: Arc<str> = domain.into();
        Arc::get_mut(&mut domain).unwrap().make_ascii_lowercase();

        if domain.starts_with('*') || domain.ends_with('.') {
            return Err(DomainParseError::Custom);
        }
        if !addr::parse_dns_name(&domain)?.has_known_suffix() {
            return Err(DomainParseError::Addr);
        }
        let name = hickory_proto::rr::Name::from_str_relaxed(&domain)?;
        if name.num_labels() < 2 {
            return Err(DomainParseError::Custom);
        }

        if domain.contains('/') {
            log::warn!("Invalid domain: {:?}", domain);
            return Err(DomainParseError::Custom);
        }
        Ok(Domain(domain))
    }
}

#[cfg(test)]
mod tests {
    use crate::domain::Domain;
    #[test]
    fn valid_domain() {
        for domain in [
            "amazonaws.com",
            "s3-website.us-east-1.amazonaws.com",
            "origin-mobile_mob.conduit.com",
        ] {
            let domain: Result<Domain, _> = domain.parse();
            assert!(domain.is_ok());
        }
    }

    #[test]
    fn invalid_domain() {
        for domain_str in [
            "com",
            "@.amazonaws.com",
            "1234",
            "example.com,google.com",
            "example.com.",
        ] {
            let domain: Result<Domain, _> = domain_str.parse();
            assert!(domain.is_err(), "{}", domain_str);
        }
    }
    #[test]
    fn makes_lowercase() {
        let domain: Domain = "EXAMPLE.COM".parse().unwrap();
        assert_eq!(domain.as_ref(), "example.com");
    }
}

#[cfg(feature = "ssr")]
mod lookup_dns_task {
    use std::{collections::HashSet, sync::Mutex, time::Duration};

    use super::*;
    use hickory_resolver::error::ResolveError;
    use tokio_util::sync::CancellationToken;

    fn parse_lookup_result(
        result: Result<hickory_resolver::lookup_ip::LookupIp, ResolveError>,
    ) -> Result<(Vec<ipnetwork::IpNetwork>, Vec<Domain>), ResolveError> {
        match result {
            Ok(result) => {
                let mut ips: Vec<ipnetwork::IpNetwork> = Vec::new();
                let mut cnames = Vec::new();
                let lookup = result.as_lookup();
                for record in lookup.iter() {
                    if let Some(a) = record.as_a() {
                        let ip: IpAddr = a.0.into();
                        ips.push(ip.into());
                    } else if let Some(aaaa) = record.as_aaaa() {
                        let ip: IpAddr = aaaa.0.into();
                        ips.push(ip.into());
                    } else if let Some(cname) = record.as_cname() {
                        let mut cname = cname.0.to_ascii();
                        if cname.ends_with('.') {
                            cname.pop();
                        }
                        if let Ok(cname) = cname.parse() {
                            cnames.push(cname);
                        } else {
                            log::warn!("Invalid CNAME {}", cname);
                        }
                    } else {
                        log::info!("Unknown record type {:?}", record.record_type());
                    }
                }
                Ok((ips, cnames))
            }
            Err(err) => match err.kind() {
                hickory_resolver::error::ResolveErrorKind::NoRecordsFound {
                    query: _,
                    soa: _,
                    negative_ttl: _,
                    response_code: _,
                    trusted: _,
                } => Ok((vec![], vec![])),
                hickory_resolver::error::ResolveErrorKind::Proto(_) => Ok((vec![], vec![])),
                hickory_resolver::error::ResolveErrorKind::Timeout => Err(err),
                _ => Err(err),
            },
        }
    }

    #[cfg(feature = "ssr")]
    type Resolver = Arc<
        hickory_resolver::AsyncResolver<
            hickory_resolver::name_server::GenericConnector<
                hickory_resolver::name_server::TokioRuntimeProvider,
            >,
        >,
    >;

    #[cfg(feature = "ssr")]
    type Task = (DomainId, Domain);

    #[cfg(feature = "ssr")]
    #[derive(Clone)]
    pub struct DomainResolver {
        resolvers: Vec<(Arc<str>, Resolver)>,
        tx: async_channel::Sender<Task>,
        rx: async_channel::Receiver<Task>,
        read_limit: i64,
        failed_cache_size: usize,
        failed_domains: Arc<Mutex<Vec<i64>>>,
        written_domains: Arc<Mutex<Vec<i64>>>,
        bad_domains: Arc<Mutex<Vec<i64>>>,
        looked_up_domains: Arc<Mutex<Vec<i64>>>,
        dns_ips: Arc<Mutex<(Vec<i64>, Vec<ipnetwork::IpNetwork>)>>,
        dns_cnames: Arc<Mutex<(Vec<i64>, Vec<Domain>)>>,
        token: CancellationToken,
    }

    #[cfg(feature = "ssr")]
    impl DomainResolver {
        pub fn new(token: CancellationToken) -> Result<Self, ServerFnError> {
            let _ = dotenvy::dotenv()?;
            let servers_str = std::env::var("DNS_SERVERS")?;

            let read_limit = std::env::var("READ_LIMIT")?.parse::<u32>()? as i64;
            let mut resolvers = Vec::new();
            for server in servers_str.split(',') {
                let server: Arc<str> = server.into();
                let (addr, port) = server
                    .split_once(':')
                    .ok_or_else(|| ServerFnError::new("Bad DNS_SERVER env"))?;
                let server_conf = hickory_resolver::config::NameServerConfigGroup::from_ips_clear(
                    &[addr.parse()?],
                    port.parse()?,
                    true,
                );
                let config =
                    hickory_resolver::config::ResolverConfig::from_parts(None, vec![], server_conf);
                let mut opts = hickory_resolver::config::ResolverOpts::default();
                opts.ip_strategy = hickory_resolver::config::LookupIpStrategy::Ipv4AndIpv6;
                opts.cache_size = 32;
                opts.attempts = 3;
                opts.timeout = std::time::Duration::from_secs_f32(5.0);
                let resolver = Arc::new(hickory_resolver::AsyncResolver::tokio(config, opts));
                resolvers.push((server, resolver));
            }

            if resolvers.is_empty() {
                return Err(ServerFnError::new("Empty DNS server list"));
            }
            let (tx, rx) = async_channel::bounded(read_limit as usize);

            let bad_domains = Arc::new(Mutex::new(Vec::new()));
            let failed_cache_size = std::env::var("FAILED_CACHE_SIZE")?.parse()?;

            Ok(Self {
                resolvers,
                bad_domains,
                tx,
                rx,
                read_limit,
                failed_cache_size,
                failed_domains: Arc::new(Mutex::new(Vec::new())),
                written_domains: Arc::new(Mutex::new(Vec::new())),
                looked_up_domains: Arc::new(Mutex::new(Vec::new())),
                dns_ips: Default::default(),
                dns_cnames: Default::default(),
                token,
            })
        }

        pub async fn run(&self) -> Result<(), ServerFnError> {
            dotenvy::dotenv()?;
            let concurrent_lookups: usize = std::env::var("CONCURRENT_LOOKUPS")?.parse()?;

            let mut tasks = tokio::task::JoinSet::new();

            for resolver in &self.resolvers {
                for _ in 0..concurrent_lookups {
                    let resolver_str = resolver.0.clone();
                    let resolver = resolver.1.clone();
                    let resolver_self = self.clone();
                    let task = async move {
                        let token = resolver_self.token.clone();
                        tokio::select! {
                        _ = token.cancelled() => {
                            log::info!("Shutting down DNS resolver");
                            Ok(())},
                        res =
                        resolver_self.run_task(resolver_str, resolver) => res}
                    };
                    tasks.spawn(task);
                }
            }
            let selector = self.clone();
            tasks.spawn(async move {
                let token = selector.token.clone();
                tokio::select! {
                _ = token.cancelled() => {
                    log::info!("Shutting down DNS selector");
                    Ok(())}
                res = selector.domain_selector() => res
                }
            });
            let writer = self.clone();
            tasks.spawn(async move { writer.write_to_db().await });
            while let Some(result) = tasks.join_next().await {
                let _ = result?;
            }
            Ok(())
        }

        async fn domain_selector(&self) -> Result<(), ServerFnError> {
            let pool = crate::server::get_db().await?;
            let mut started_domains = HashSet::new();
            let mut failed_domains = std::collections::VecDeque::<i64>::new();
            loop {
                {
                    failed_domains.extend(std::mem::take(&mut *self.failed_domains.lock()?));
                }
                while failed_domains.len() > self.failed_cache_size {
                    if let Some(failed) = failed_domains.pop_front() {
                        started_domains.remove(&failed);
                    }
                }
                let written_domains = std::mem::take(&mut *self.written_domains.lock()?);
                for domain_id in written_domains {
                    started_domains.remove(&domain_id);
                }
                let limit = self.read_limit + started_domains.len() as i64;
                let records = sqlx::query!(
                    "SELECT id, domain
                        FROM Domains
                        WHERE last_checked_dns IS NULL
                        ORDER BY id DESC NULLS FIRST
                        LIMIT $1",
                    limit
                )
                .fetch_all(&pool)
                .await?;
                let recheck_domains = if records.len() < limit as usize {
                    sqlx::query!(
                        "SELECT id, domain
                            FROM Domains
                            ORDER BY last_checked_dns ASC NULLS FIRST
                            LIMIT $1",
                        limit
                    )
                    .fetch_all(&pool)
                    .await?
                } else {
                    vec![]
                };

                let records = records.into_iter().map(|record| (record.id, record.domain));
                let recheck_domains = recheck_domains
                    .into_iter()
                    .map(|record| (record.id, record.domain));
                let mut has_domains = false;
                for (domain_id, domain_str) in records.chain(recheck_domains) {
                    has_domains = true;
                    if !started_domains.insert(domain_id) {
                        continue;
                    }
                    if let Ok(domain) = domain_str.parse::<Domain>() {
                        if domain_str == domain.as_ref() {
                            self.tx.send((DomainId(domain_id), domain)).await?;
                            continue;
                        }
                    }
                    log::warn!("Invalid domain: {}", domain_str);
                    self.bad_domains.lock()?.push(domain_id);
                }
                if !has_domains {
                    log::info!("No domains to check, sleeping");
                    tokio::time::sleep(Duration::from_secs(30)).await;
                }
            }
        }

        async fn run_task(
            &self,
            resolver_str: Arc<str>,
            resolver: Resolver,
        ) -> Result<(), ServerFnError> {
            while let Ok(task) = self.rx.recv().await {
                let (domain_id, domain) = task;
                let mut domain_str = domain.as_ref().to_string();
                domain_str.push('.');
                let result = resolver.lookup_ip(&domain_str).await;
                let result = parse_lookup_result(result);
                match result {
                    Ok((ips, cnames)) => {
                        self.looked_up_domains.lock()?.push(domain_id.0);
                        {
                            let mut dns_ips = self.dns_ips.lock()?;
                            for ip in ips {
                                dns_ips.0.push(domain_id.0);
                                dns_ips.1.push(ip);
                            }
                        }
                        {
                            let mut dns_cnames = self.dns_cnames.lock()?;
                            for cname in cnames {
                                dns_cnames.0.push(domain_id.0);
                                dns_cnames.1.push(cname);
                            }
                        }
                    }
                    Err(err) => {
                        log::warn!(
                            "Server: {} Error looking up domain {}: {}",
                            resolver_str,
                            domain.as_ref(),
                            err
                        );
                        self.failed_domains.lock()?.push(domain_id.0);
                    }
                }
            }
            Ok(())
        }

        async fn write_to_db(&self) -> Result<(), ServerFnError> {
            let pool = crate::server::get_db().await?;
            let write_frequency: u64 = std::env::var("WRITE_FREQUENCY")?.parse()?;
            let mut interval = tokio::time::interval(Duration::from_secs(write_frequency));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            interval.tick().await;
            loop {
                tokio::select! {
                    _ = interval.tick() => {},
                    _ = self.token.cancelled() => {
                        log::info!("Shutting down DNS writer")
                    }
                }
                let looked_up_domains = std::mem::take(&mut *self.looked_up_domains.lock()?);
                let looked_up_domains_deduped =
                    looked_up_domains.iter().cloned().collect::<HashSet<_>>();
                assert_eq!(looked_up_domains.len(), looked_up_domains_deduped.len());
                let dns_ips = std::mem::take(&mut *self.dns_ips.lock()?);
                let dns_ips_domain_ids = &dns_ips.0;
                let dns_ips_ips = &dns_ips.1;
                let dns_cnames = std::mem::take(&mut *self.dns_cnames.lock()?);
                let dns_cnames_domain_ids = &dns_cnames.0;
                let dns_cnames_cname = &dns_cnames.1;
                let bad_domains = std::mem::take(&mut *self.bad_domains.lock()?);
                let total_cnames = dns_cnames_cname
                    .iter()
                    .collect::<HashSet<_>>()
                    .into_iter()
                    .cloned()
                    .collect::<Vec<Domain>>();
                let new_domains_from_cnames = sqlx::query!(
                    "INSERT INTO domains(domain)
                    SELECT domain FROM UNNEST($1::text[]) as t(domain)
                    ON CONFLICT DO NOTHING",
                    &total_cnames[..] as _
                )
                .execute(&pool)
                .await?
                .rows_affected();

                let mut tx = pool.begin().await?;
                sqlx::query!(
                    "DELETE FROM dns_ips WHERE domain_id = ANY($1::bigint[])",
                    &looked_up_domains[..]
                )
                .execute(&mut *tx)
                .await?;
                sqlx::query!(
                    "DELETE FROM dns_cnames WHERE domain_id = ANY($1::bigint[])",
                    &looked_up_domains[..]
                )
                .execute(&mut *tx)
                .await?;
                sqlx::query!(
                    "INSERT INTO dns_ips(domain_id, ip_address)
                    SELECT domain_id, ip FROM UNNEST($1::bigint[], $2::inet[]) as t(domain_id, ip)",
                    &dns_ips_domain_ids[..],
                    &dns_ips_ips[..]
                )
                .execute(&mut *tx)
                .await?;
                sqlx::query!(
                        "INSERT INTO dns_cnames(domain_id, cname_domain_id)
                    SELECT domain_id, cname_domains.id FROM UNNEST($1::bigint[], $2::text[]) as t(domain_id, cname)
                    INNER JOIN domains AS cname_domains ON cname_domains.domain = t.cname
                    ",
                        &dns_cnames_domain_ids[..],
                        &dns_cnames_cname[..] as _
                    )
                    .execute(&mut *tx)
                    .await?;

                let updated_domains = sqlx::query!(
                    "UPDATE domains
                    SET last_checked_dns = now()
                    WHERE id = ANY($1::bigint[])",
                    &looked_up_domains[..]
                )
                .execute(&mut *tx)
                .await?
                .rows_affected();
                assert_eq!(updated_domains, looked_up_domains.len() as u64);

                tx.commit().await?;
                self.written_domains.lock()?.extend(&looked_up_domains);

                if !bad_domains.is_empty() {
                    log::info!("Removing {} bad domains", bad_domains.len());
                    sqlx::query!(
                        "DELETE FROM domains
                    WHERE id = ANY($1::bigint[])",
                        &bad_domains[..]
                    )
                    .execute(&pool)
                    .await?;
                }

                self.written_domains.lock()?.extend(&bad_domains);

                log::info!(
                    "Looked up {} domains, got {} ips, {} cnames ({} new)",
                    looked_up_domains.len(),
                    dns_ips_domain_ids.len(),
                    dns_cnames_domain_ids.len(),
                    new_domains_from_cnames
                );
                if self.token.is_cancelled() {
                    return Ok(());
                }
            }
        }
    }
}

#[server]
async fn get_dns_result(
    domain: Domain,
) -> Result<(BTreeSet<IpAddr>, BTreeSet<(DomainId, String)>), ServerFnError> {
    let records = sqlx::query!(
        r#"SELECT dns_ips.ip_address as "ip_address: Option<ipnetwork::IpNetwork>",
        cname_domains.id as "cname_domain_id: Option<i64>",
        cname_domains.domain as "cname_domain: Option<String>"
    FROM domains
    LEFT JOIN dns_ips ON dns_ips.domain_id=domains.id
    LEFT JOIN dns_cnames on dns_cnames.domain_id=domains.id
    LEFT JOIN domains AS cname_domains ON cname_domains.id=dns_cnames.cname_domain_id
    WHERE domains.domain = $1
    "#r,
        domain.as_ref().to_string()
    )
    .fetch_all(&crate::server::get_db().await?)
    .await?;
    let mut ip_addresses = BTreeSet::new();
    let mut cnames = BTreeSet::new();
    for record in records {
        if let Some(ip) = record.ip_address {
            ip_addresses.insert(ip.ip());
        }
        if let (Some(id), Some(cname)) = (record.cname_domain_id, record.cname_domain) {
            cnames.insert((DomainId(id), cname));
        }
    }
    Ok((ip_addresses, cnames))
}

#[component]
fn DnsResultView(domain: Domain) -> impl IntoView {
    view! {
        <Await
            future=move || {
                let domain = domain.clone();
                async move { get_dns_result(domain.clone()).await }
            }

            let:dns_results
        >

            {
                let dns_results = dns_results.clone();
                move || match dns_results.clone() {
                    Ok((ips, cnames)) => {
                        view! {
                            <div class="grid grid-cols-2 gap-4">
                                <div>
                                    <h2 class="mb-2 text-lg font-bold">IP Addresses</h2>
                                    <ul class="grid grid-cols-2">
                                        <For
                                            each=move || { ips.clone() }
                                            key=|ip| *ip
                                            children=|ip| {
                                                let href = format!("/ip/{ip}");
                                                view! {
                                                    <li>
                                                        <A href=href class="link link-neutral">
                                                            {ip.to_string()}
                                                        </A>
                                                    </li>
                                                }
                                            }
                                        />

                                    </ul>
                                </div>
                                <div>
                                    <h2 class="mb-2 text-lg font-bold">CNAMEs</h2>
                                    <ul>
                                        <For
                                            each=move || { cnames.clone() }
                                            key=|(id, _cname)| *id
                                            children=|(_id, cname)| {
                                                let href = format!("/domain/{cname}");
                                                view! {
                                                    <li>
                                                        <A href=href class="link link-neutral">
                                                            {cname}
                                                        </A>
                                                    </li>
                                                }
                                            }
                                        />

                                    </ul>

                                </div>

                            </div>
                        }
                            .into_view()
                    }
                    _ => view! { <p>"Error"</p> }.into_view(),
                }
            }

        </Await>
    }
}

#[server]
async fn get_blocked_by(
    domain: String,
) -> Result<
    Vec<(
        FilterListUrl,
        RuleId,
        SourceId,
        crate::filterlist::RulePair,
    )>,
    ServerFnError,
> {
    let records = sqlx::query!(
        r#"
        SELECT Rules.id as "rule_id: RuleId",
        domain_rules_domain.domain as "domain: Option<String>", domain_rules.allow as "domain_allow: Option<bool>", subdomain as "subdomain: Option<bool>",
        ip_rules.ip_network as "ip_network: Option<ipnetwork::IpNetwork>", ip_rules.allow as "ip_allow: Option<bool>",
        source_id AS "source_id: SourceId", source, url
        FROM domains
        INNER JOIN rule_matches ON domains.id = rule_matches.domain_id
        INNER JOIN Rules on Rules.id = rule_matches.rule_id
        INNER JOIN rule_source ON rules.id = rule_source.rule_id
        INNER JOIN list_rules ON rule_source.id = list_rules.source_id
        INNER JOIN filterLists ON list_rules.list_id = filterLists.id
        LEFT JOIN domain_rules ON rules.domain_rule_id = domain_rules.id
        LEFT JOIN domains AS domain_rules_domain ON domain_rules_domain.id = domain_rules.domain_id
        LEFT JOIN ip_rules ON rules.ip_rule_id = ip_rules.id
        WHERE domains.domain = $1
        ORDER BY url
        LIMIT 100
        "#r,
        domain
    )
    .fetch_all(&crate::server::get_db().await?)
    .await?;
    let rules = records
        .into_iter()
        .map(|record| {
            let rule_data = RuleData {
                rule_id: record.rule_id,
                domain: record.domain.clone(),
                domain_allow: record.domain_allow,
                domain_subdomain: record.subdomain,
                ip_network: record.ip_network,
                ip_allow: record.ip_allow,
            };
            let rule = rule_data.try_into()?;
            let source = record.source.clone();
            let pair = crate::filterlist::RulePair::new(source.into(), rule);
            let url = record.url.clone();
            Ok((
                url.parse()?,
                record.rule_id,
                record.source_id,
                pair,
            ))
        })
        .collect::<Result<Vec<_>, ServerFnError>>()?;

    Ok(rules)
}

#[component]
fn BlockedBy(get_domain: Box<dyn Fn() -> Result<String, ParamsError>>) -> impl IntoView {
    let blocked_by = create_resource(get_domain, |domain| async move {
        let rules = get_blocked_by(domain?).await?;
        Ok::<_, ServerFnError>(rules)
    });
    view! {
        <Transition fallback=move || {
            view! { <p>"Loading" <Loading/></p> }
        }>
            {move || match blocked_by.get() {
                Some(Ok(rules)) => {
                    view! {
                        <table class="table table-zebra">
                            <For
                                each=move || { rules.clone() }
                                key=|(_url, rule_id, source_id, _pair)| (*rule_id, *source_id)
                                children=|(url, rule_id, _source_id, pair)| {
                                    let source = pair.get_source().to_string();
                                    let rule = pair.get_rule().clone();
                                    view! {
                                        <tr>
                                            <td>
                                                <FilterListLink url=url/>
                                            </td>
                                            <td>{source}</td>
                                            <td>
                                                <A href=rule_id.get_href() class="link link-neutral">
                                                    <DisplayRule rule=rule/>
                                                </A>
                                            </td>
                                        </tr>
                                    }
                                }
                            />

                        </table>
                    }
                        .into_view()
                }
                _ => view! { <p>"Error"</p> }.into_view(),
            }}

        </Transition>
    }
}

#[server]
async fn get_subdomains(domain: String) -> Result<Vec<String>, ServerFnError> {
    let records = sqlx::query!(
        "SELECT subdomain_text.domain
        FROM domains
        INNER JOIN subdomains ON domains.id = subdomains.parent_domain_id
        INNER JOIN domains AS subdomain_text ON subdomains.domain_id = subdomain_text.id
        WHERE domains.domain = $1
        ",
        domain
    )
    .fetch_all(&crate::server::get_db().await?)
    .await?;
    let subdomains = records.into_iter().map(|record| record.domain).collect();
    Ok(subdomains)
}

#[component]
fn DisplaySubdomains(get_domain: Box<dyn Fn() -> Result<String, ParamsError>>) -> impl IntoView {
    let subdomains = create_resource(get_domain, |domain| async move {
        let subdomains = get_subdomains(domain?).await?;
        Ok::<_, ServerFnError>(subdomains)
    });
    view! {
        <Transition fallback=move || {
            view! { <p>"Loading" <Loading/></p> }
        }>
            {move || match subdomains.get() {
                Some(Ok(subdomains)) => {
                    view! {
                        <table class="table table-zebra">
                            <For
                                each=move || { subdomains.clone() }
                                key=std::clone::Clone::clone
                                children=|subdomain| {
                                    let domain_href = format!("/domain/{subdomain}");
                                    view! {
                                        <tr>
                                            <td>
                                                <A href=domain_href class="link link-neutral">
                                                    {subdomain}
                                                </A>
                                            </td>
                                        </tr>
                                    }
                                }
                            />

                        </table>
                    }
                        .into_view()
                }
                _ => view! { <p>"Error"</p> }.into_view(),
            }}

        </Transition>
    }
}

#[derive(Params, PartialEq)]
struct DomainParam {
    domain: Option<String>,
}

#[component]
pub fn DomainViewPage() -> impl IntoView {
    let params = use_params::<DomainParam>();
    let get_domain = move || {
        params.with(|param| {
            param.as_ref().map_err(Clone::clone).and_then(|param| {
                param
                    .domain
                    .clone()
                    .ok_or_else(|| ParamsError::MissingParam("No domain".into()))
            })
        })
    };
    let get_domain_parsed = move || {
        params.with(|param| {
            Ok::<_, ServerFnError>(
                param
                    .as_ref()?
                    .domain
                    .as_ref()
                    .ok_or_else(|| ParamsError::MissingParam("No domain".into()))?
                    .parse::<Domain>()?,
            )
        })
    };
    view! {
        <div>
            {move || {
                let domain = get_domain_parsed();
                match domain {
                    Ok(domain) => {
                        view! {
                            <h1 class="text-3xl">"Domain: " {domain.as_ref().to_string()}</h1>
                            <DnsResultView domain=domain.clone()/>
                            <p>"Filtered by"</p>
                            <BlockedBy get_domain=Box::new(get_domain)/>
                            <p>"Subdomains"</p>
                            <DisplaySubdomains get_domain=Box::new(get_domain)/>
                        }
                            .into_view()
                    }
                    Err(err) => view! { <p>"Error: " {format!("{err:?}")}</p> }.into_view(),
                }
            }}

        </div>
    }
}
