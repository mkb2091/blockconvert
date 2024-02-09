use seed::{prelude::*, *};

#[derive(Debug, Default)]
pub struct Model {
    list: Option<Result<FilterListList, Error>>,
}

#[derive(Debug, Clone, thiserror::Error)]
enum Error {
    #[error("Network Error")]
    NetworkError,
    #[error("Failed to parse URL: {0}")]
    UrlParseError(#[from] url::ParseError),
    #[error("Failed to decode data from server")]
    DataDecodeError(std::sync::Arc<bincode::Error>),
    #[error("Server does not have the list data")]
    ServerMissingData,
}

impl std::convert::From<reqwest::Error> for Error {
    fn from(_: reqwest::Error) -> Self {
        Self::NetworkError
    }
}

impl std::convert::From<bincode::Error> for Error {
    fn from(err: bincode::Error) -> Self {
        Self::DataDecodeError(std::sync::Arc::new(err))
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct FilterListList {
    list: Vec<common::FilterListRecord>,
}

#[derive(Debug, Clone)]
pub enum Msg {
    Reload,
    ReloadResult(Result<FilterListList, Error>),
}

pub fn update(
    msg: Msg,
    model: &mut Model,
    orders: &mut impl Orders<crate::Msg>,
) {
    match msg {
        Msg::Reload => {
            orders.perform_cmd(async {
                let reload_result = async {
                    let url = seed::browser::util::window()
                        .location()
                        .href()
                        .expect("get `href`");
                    let url = url::Url::parse(&url)?;
                    let url = url.join("filter-lists/view")?;
                    let response = reqwest::get(url).await?;
                    let contents = response.bytes().await?;
                    let list = bincode::deserialize::<Option<FilterListList>>(&contents)?;
                    let list = list.ok_or(Error::ServerMissingData)?;
                    Ok(list)
                }
                .await;

                crate::Msg::ListManagerMsg(Msg::ReloadResult(reload_result))
            });
        }
        Msg::ReloadResult(reload_result) => {
            model.list = Some(reload_result);
        }
    }
}

pub fn view(model: &Model) -> Node<crate::Msg> {
    div![
        h1!["List Manager"],
        button![
            C!["mdc-button mdc-button--raised"],
            "Reload",
            ev(Ev::Click, move |_| crate::Msg::ListManagerMsg(
                Msg::Reload
            ))
        ],
        form![
            "URl",
            div![
                C!["mdc-text-field mdc-text-field--outlined"],
                input![
                    C!["mdc-text-field__input"],
                    attrs! {
                        At::Value => ""
                    },
                    //input_ev(Ev::Input, Msg::UpdateInput)
                ],
                div![C!["mdc-line-ripple"]]
            ],
        ],
        if let Some(list) = &model.list {
            match list {
                Ok(list) => {
                    div![ul![
                        C!["mdc-list"],
                        list.list.iter().map(|record| {
                            li![
                                C!["mdc-list-item"],
                                &record.name,
                                &record.author,
                                a!["Source", attrs! {At::Href => &record.url}]
                            ]
                        })
                    ]]
                }
                Err(err) => {
                    div![format!("Error Loading: {:?}", err)]
                }
            }
        } else {
            div!["Not yet loaded"]
        }
    ]
}