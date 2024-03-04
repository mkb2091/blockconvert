use seed::{prelude::*, *};


#[derive(Debug, Default)]
pub struct Model {
    input_value: String,
    domain_data: Option<Result<DomainData, DomainError>>,
}


#[derive(Clone, Debug)]
pub enum Msg {
    UpdateInput(String),
    SendRequest,
    RequestCompleted(String),
    SubmitForm,
}


pub fn update(msg: Msg, model: &mut Model, orders: &mut impl Orders<crate::Msg>) {
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
    }
}

pub fn view(model: &Model) -> Node<crate::Msg> {
    div![
        h1!["Domain Lookup"],
        form![
            // Handle form submission
            ev(Ev::Submit, |event| {
                event.prevent_default();
                crate::Msg::DomainLookupMsg(Msg::SubmitForm)
            }),
            div![
                C!["mdc-text-field mdc-text-field--outlined"],
                label![C!["mdc-floating-label"], "Enter a domain:"],
                input![
                    C!["mdc-text-field__input"],
                    attrs! {
                        At::Value => &model.input_value;
                    },
                    input_ev(Ev::Input, |input|crate::Msg::DomainLookupMsg(Msg::UpdateInput(input)))
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

#[derive(Debug)]
pub struct DomainData {
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