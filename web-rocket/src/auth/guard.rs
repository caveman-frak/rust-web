use {
    crate::auth::{
        connection::AuthConnection,
        cookies::{self, TokenValue},
    },
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

async fn from_cookie<'r>(jar: &'r CookieJar<'r>) -> Result<Option<TokenValue>> {
    match jar.get(cookies::TOKEN_COOKIE) {
        Some(cookie) => Ok(Some(cookie.try_into()?)),
        _ => Ok(None),
    }
}

async fn from_header<'r>(
    headers: &'r HeaderMap<'r>,
    connection: &AuthConnection,
) -> Result<Option<TokenValue>> {
    match headers.get_one(cookies::AUTHORISATION_HEADER) {
        Some(header) if header.starts_with(cookies::BEARER_TOKEN) => {
            let token: TokenValue = header.try_into()?;
            let (introspect, user_info) = connection.get_user_info(token.access()).await?;

            rocket::info_!(
                "Access Token: {:?}",
                introspect.map_or(String::from("-"), |t| format!("{:?}", t))
            );
            rocket::info_!(
                "User Info: {}",
                user_info.map_or(String::from("-"), |u| format!("{:?}", u))
            );

            Ok(Some(token))
        }
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

async fn outcome<'r>(
    jar: &'r CookieJar<'r>,
    headers: &'r HeaderMap<'r>,
    connection: &AuthConnection,
) -> Result<Option<TokenValue>> {
    match from_cookie(jar).await {
        Ok(Some(token)) => Ok(Some(token)),
        Ok(None) => from_header(headers, connection).await,
        Err(e) => Err(e),
    }
}

async fn cached_outcome<'r>(request: &'r Request<'_>) -> Result<Option<TokenValue>> {
    let jar = request.cookies();
    let headers = request.headers();
    let connection = request.rocket().state::<AuthConnection>().unwrap();
    match request
        .local_cache_async(async { outcome(jar, headers, connection).await })
        .await
    {
        Ok(Some(token)) => Ok(Some(token.clone())),
        Err(e) => {
            rocket::error_!("{}", e);
            Ok(None)
        }
        _ => Ok(None),
    }
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for Authorised {
    type Error = Error;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        match cached_outcome(request).await {
            Ok(Some(token)) => Outcome::Success(Authorised { token }),
            Ok(None) => unauthorised(request.uri()),
            Err(e) => Outcome::Failure((Status::BadRequest, e)),
        }
    }
}
