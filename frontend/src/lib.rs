use seed::{prelude::*, *};
mod domain_lookup;
mod list_manager;

#[derive(Debug, Default)]
struct Model {
    domain_lookup: domain_lookup::Model,
    list_manager: list_manager::Model,
}

#[derive(Clone, Debug)]
enum Msg {
    DomainLookupMsg(domain_lookup::Msg),
    ListManagerMsg(list_manager::Msg),
}





fn update(msg: Msg, model: &mut Model, orders: &mut impl Orders<Msg>) {
    match msg {
        Msg::DomainLookupMsg(msg) => domain_lookup::update(msg, &mut model.domain_lookup, orders),
        Msg::ListManagerMsg(msg) => list_manager::update(msg, &mut model.list_manager, orders),
    }
}



fn view(model: &Model) -> Node<Msg> {
    div![
        list_manager::view(&model.list_manager),
        domain_lookup::view(&model.domain_lookup)
    ]
}

fn init(_: Url, orders: &mut impl Orders<Msg>) -> Model {
    orders.send_msg(Msg::ListManagerMsg(list_manager::Msg::Reload));
    Default::default()
}

#[wasm_bindgen(start)]
pub fn render() {
    let _ = console_log::init_with_level(log::Level::Debug);
    App::start("app", init, update, view);
}
