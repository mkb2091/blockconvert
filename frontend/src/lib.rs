use seed::{prelude::*, *};

#[derive(Debug, Default)]
struct Model {
    input_value: String,
    domain_data: Option<Result<DomainData, DomainError>>,
    list_manager: ListManagerModel,
}

#[derive(Clone, Debug)]
enum Msg {
    UpdateInput(String),
    SendRequest,
    RequestCompleted(String),
    SubmitForm,
    ListManagerMsg(ListManagerMsg),
}

#[derive(Debug)]
struct DomainData {
    domain: String,
    root: String,
    extension: String,
    filters: Vec<String>,
}

#[derive(thiserror::Error, Debug)]
enum DomainError {
    #[error("Failed to parse domain: `{0}`")]
    ParserError(String),
    #[error("Domain is missing root")]
    MissingRoot,
    #[error("Domain is missing suffix")]
    MissingSuffix,
    #[error("Unknown extension: `{0}`")]
    UnknownSuffix(String),
}

fn submit_form(input: &str) -> Result<DomainData, DomainError> {
    let domain =
        addr::parse_domain_name(&input).map_err(|err| DomainError::ParserError(err.to_string()))?;
    log::info!("Domain: {:?}", domain);
    let root = domain.root().ok_or(DomainError::MissingRoot)?;
    let suffix = domain.suffix();
    if !domain.has_known_suffix() {
        Err(DomainError::UnknownSuffix(suffix.to_string()))?;
    }
    let prefix = domain.prefix();
    let _subdomains = prefix
        .iter()
        .flat_map(|prefix| prefix.matches('.'))
        .map(|x| x.to_string())
        .collect::<Vec<_>>();

    let mut filters = vec![domain.to_string()];
    let mut base = domain.as_str();
    for prefix in domain.prefix().iter().flat_map(|prefix| prefix.split('.')) {
        if let Some(without_prefix) = base.strip_prefix(prefix) {
            let stripped = format!("*{}", without_prefix);
            filters.push(stripped);
            base = without_prefix.trim_start_matches('.');
            log::info!("without_prefix: {:?}", without_prefix);
        }
    }

    let filters_without_tld = filters
        .iter()
        .filter_map(|domain| domain.strip_suffix(suffix))
        .map(|domain| {
            let mut domain = domain.to_string();
            domain.push('*');
            domain
        })
        .chain(filters.clone())
        .collect::<Vec<String>>();
    Ok(DomainData {
        domain: domain.to_string(),
        root: root.to_string(),
        extension: suffix.to_string(),
        filters: filters_without_tld,
    })
}

fn update(msg: Msg, model: &mut Model, orders: &mut impl Orders<Msg>) {
    log::info!("msg: {:?}", &msg);
    match msg {
        Msg::UpdateInput(new_value) => {
            model.input_value = new_value;

            let form_result = submit_form(&model.input_value);
            log::info!("{:?}", &form_result);
            model.domain_data = Some(form_result);
        }
        Msg::SendRequest => {
            let url = format!("/send_request?domain={}", model.input_value);
            orders.perform_cmd(async {
                let response = reqwest::get(url).await;
                log::info!("{:?}", response);
                todo!()
                //Msg::RequestCompleted(response_text)
            });
        }
        Msg::RequestCompleted(_response_text) => {}
        Msg::SubmitForm => {
            let form_result = submit_form(&model.input_value);
            log::info!("{:?}", &form_result);
            model.domain_data = Some(form_result);
        }
        Msg::ListManagerMsg(msg) => update_list_manager(msg, &mut model.list_manager, orders),
        x => {
            log::error!("Error: {:?}", x)
        }
    }
}

fn view_domain_lookup(model: &Model) -> Node<Msg> {
    div![
        h1!["Domain Lookup"],
        form![
            // Handle form submission
            ev(Ev::Submit, |event| {
                event.prevent_default();
                Msg::SubmitForm
            }),
            div![
                C!["mdc-text-field mdc-text-field--outlined"],
                label![C!["mdc-floating-label"], "Enter a domain:"],
                input![
                    C!["mdc-text-field__input"],
                    attrs! {
                        At::Value => &model.input_value;
                    },
                    input_ev(Ev::Input, Msg::UpdateInput)
                ],
                div![C!["mdc-line-ripple"]]
            ],
            button![C!["mdc-button mdc-button--raised"], "Submit"],
        ],
        if let Some(domain_data) = &model.domain_data {
            match &domain_data {
                Err(error) => div![C!["error-message"], error.to_string()],
                Ok(domain_data) => table![
                    C!["mdc-data-table mdc-data-table--sortable"],
                    thead![
                        C!["mdc-data-table__header-row"],
                        th![C!["mdc-data-table__header-cell"], "Base domain"],
                        th![C!["mdc-data-table__header-cell"], "Filter"]
                    ],
                    tbody![
                        C!["mdc-data-table__content"],
                        domain_data.filters.iter().map(|filter| {
                            tr![
                                C!["mdc-data-table__row"],
                                td![C!["mdc-data-table__cell"], &domain_data.domain],
                                td![C!["mdc-data-table__cell"], filter]
                            ]
                        }),
                    ]
                ],
            }
        } else {
            div![]
        }
    ]
}

#[derive(Debug, Default)]
struct ListManagerModel {
    lists: Vec<String>,
}

#[derive(Debug, Clone)]
enum ListManagerMsg {
    Reload,
}

fn update_list_manager(
    msg: ListManagerMsg,
    model: &mut ListManagerModel,
    orders: &mut impl Orders<Msg>,
) {
    match msg {
        ListManagerMsg::Reload => {
            orders.perform_cmd(async {
                if let Err(err) = async {
                    let url = seed::browser::util::window()
                        .location()
                        .href()
                        .expect("get `href`");
                    let url = reqwest::Url::parse(&url)?;
                    let url = url.join("filter-lists")?;
                    let response = reqwest::get(url).await?;

                    let text = response.text().await?;

                    log::info!("text: {:?}", text);
                    Ok::<_, anyhow::Error>(())
                }
                .await
                {
                    log::error!("Error: {:?}", err);
                }
            });
        }
    }
}

fn view_list_manager(model: &ListManagerModel) -> Node<Msg> {
    div![
        h1!["List Manager"],
        button![
            C!["mdc-button mdc-button--raised"],
            "Reload",
            ev(Ev::Click, move |_| Msg::ListManagerMsg(
                ListManagerMsg::Reload
            ))
        ],
    ]
}

fn view(model: &Model) -> Node<Msg> {
    div![
        view_list_manager(&model.list_manager),
        view_domain_lookup(model)
    ]
}

fn init(_: Url, _: &mut impl Orders<Msg>) -> Model {
    Default::default()
}

#[wasm_bindgen(start)]
pub fn render() {
    let _ = console_log::init_with_level(log::Level::Debug);
    App::start("app", init, update, view);
}
