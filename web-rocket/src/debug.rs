use rocket::{
    http::uri::Origin,
    request::{FromRequest, Outcome, Request},
};

pub struct Inputs {}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for Inputs {
    type Error = &'r str;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let method = request.method();
        let host = request.headers().get_one("Host");
        let client_ip = request.client_ip();
        let remote = request.remote();
        let real_ip = request.real_ip();
        let origin: &Origin = request.uri();
        let query = origin.query();
        rocket::info_!(
            "host: {:?} / {:?}\nremote: {:?} / {:?}\norigin: {} {}\nquery: {:?}",
            host,
            client_ip,
            remote,
            real_ip,
            method,
            origin,
            query
        );

        Outcome::Success(Inputs {})
    }
}
