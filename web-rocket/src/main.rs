mod auth;
mod debug;
mod error;

#[macro_use]
extern crate rocket;

use {crate::auth::guard::Authorised, rocket::Config};

#[get("/")]
fn index() -> &'static str {
    rocket::info_!("index");
    "Hello, world!"
}

#[get("/secure/<amount>")]
fn secure(_authorised: Authorised, amount: u32) -> String {
    rocket::info_!("secure");
    format!("Here is £{}!", amount)
}

#[get("/secure")]
fn secure_all(_authorised: Authorised) -> &'static str {
    rocket::info_!("secure all");
    "Have all the money!"
}

#[get("/config")]
fn read_config(rocket_config: &Config) -> String {
    format!("{:#?}", rocket_config)
}

#[launch]
fn rocket() -> _ {
    rocket::build()
        .attach(auth::stage())
        .mount("/", routes![index, secure, secure_all, read_config])
}
