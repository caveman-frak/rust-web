mod auth;
mod debug;

use {crate::debug::Inputs, rocket::Config};

#[macro_use]
extern crate rocket;

#[get("/")]
fn index() -> &'static str {
    rocket::info_!("index");
    "Hello, world!"
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

#[get("/config")]
fn read_config(rocket_config: &Config, _debug: Inputs) -> String {
    format!("{:#?}", rocket_config)
}

#[launch]
fn rocket() -> _ {
    // env_logger::init();
    rocket::build()
        .attach(auth::stage())
        .mount("/", routes![index, secure, secure_all, read_config])
}
