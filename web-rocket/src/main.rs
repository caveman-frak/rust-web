mod auth;
mod debug;

use {
    crate::{
        auth::{Authorization, Host, OAuth},
        debug::Inputs,
    },
    rocket::{fairing::AdHoc, response::Redirect, serde::Deserialize, Config, State},
};

#[macro_use]
extern crate rocket;

#[get("/")]
fn index() -> &'static str {
    rocket::info_!("index");
    "Hello, world!"
}

#[get("/login")]
fn login(auth: Authorization, _debug: Inputs) -> String {
    rocket::info_!("login");
    format!("Welcome to the future! \n{:?}", auth)
}

#[get("/login", rank = 1)]
fn login_redirect<'a>(oauth: &State<OAuth>, host: Host) -> Redirect {
    // let uri = oauth.uri("code", "query", "http%3A%2F%2Flocalhost%3A8000%2Fconfig");
    let uri = oauth.uri("code", "query", &host.uri("/config").unwrap());
    rocket::warn_!("index redirect to {:?}", uri);
    Redirect::to(uri)
}

#[get("/secure/<amount>")]
fn secure(amount: u32) -> String {
    rocket::info_!("secure");
    format!("Here is £{}!", amount)
}

#[get("/secure")]
fn secure_all() -> &'static str {
    rocket::info_!("secure all");
    "Have all the money!"
}

#[derive(Debug, Deserialize)]
#[serde(crate = "rocket::serde")]
struct AppConfig {
    key: Option<String>,
    port: u16,
}

#[get("/config")]
fn read_config(rocket_config: &Config, oauth: &State<OAuth>, _debug: Inputs) -> String {
    format!("{:#?}\n{:#?}", rocket_config, oauth)
}

#[launch]
fn rocket() -> _ {
    // env_logger::init();
    rocket::build()
        .mount(
            "/",
            routes![
                index,
                login,
                login_redirect,
                secure,
                secure_all,
                read_config
            ],
        )
        .attach(AdHoc::config::<OAuth>())
}
