mod connection;
mod cookies;
pub mod guard;
mod routes;

use rocket::fairing::AdHoc;

pub fn stage() -> AdHoc {
    AdHoc::try_on_ignite("Authorisation Stage", |rocket| async {
        match connection::init_connection().await {
            Ok(connection) => Ok(rocket.manage(connection).attach(AdHoc::on_ignite(
                "Route Initialisation",
                routes::init_routes,
            ))),
            Err(e) => {
                rocket::error!("{}", e);
                Err(rocket)
            }
        }
    })
}
