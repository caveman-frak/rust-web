use {
    crate::auth::cookies::{self, TokenValue},
    anyhow::{anyhow, Error, Result},
    rocket::{
        http::{uri::Origin, CookieJar, HeaderMap, Status},
        request::{FromRequest, Outcome},
        Request,
    },
};

#[derive(Debug)]
pub struct Authorised {
    token: TokenValue,
}

impl Authorised {
    pub(crate) fn token(&self) -> &TokenValue {
        &self.token
    }
}

fn from_cookie<'r>(jar: &'r CookieJar<'_>) -> Result<Option<TokenValue>> {
    match jar.get(cookies::TOKEN_COOKIE) {
        Some(cookie) => Ok(Some(cookie.try_into()?)),
        _ => Ok(None),
    }
}

fn from_header<'r>(headers: &'r HeaderMap<'_>) -> Result<Option<TokenValue>> {
    match headers.get_one(cookies::AUTHORISATION_HEADER) {
        Some(header) if header.starts_with(cookies::BEARER_TOKEN) => Ok(Some(header.try_into()?)),
        _ => Ok(None),
    }
}

fn unauthorised<'r>(url: &'r Origin<'_>) -> Outcome<Authorised, Error> {
    if url.eq(&uri!("/login")) {
        Outcome::Forward(())
    } else {
        Outcome::Failure((Status::Unauthorized, anyhow!("Missing authorisation token")))
    }
}

type Source<'r> = fn(&Request<'_>) -> Result<Option<TokenValue>>;

fn outcome<'r>(mut funcs: Vec<Source>, request: &'r Request<'_>) -> Outcome<Authorised, Error> {
    if let Some(f) = funcs.pop() {
        match (f)(request) {
            Ok(Some(token)) => Outcome::Success(Authorised { token }),
            Ok(None) => outcome(funcs, request),
            Err(e) => Outcome::Failure((Status::BadRequest, e)),
        }
    } else {
        unauthorised(request.uri())
    }
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for Authorised {
    type Error = Error;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let header = |r: &Request<'_>| from_header(r.headers());
        let cookie = |r: &Request<'_>| from_cookie(r.cookies());
        outcome(vec![header, cookie], request)
    }
}
