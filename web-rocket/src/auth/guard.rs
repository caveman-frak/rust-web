use {
    crate::auth::cookies::{self, TokenValue},
    rocket::{
        http::Status,
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

#[derive(Debug)]
pub enum AuthError {
    Invalid,
    Unauthorized,
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for Authorised {
    type Error = AuthError;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        match request.cookies().get(cookies::TOKEN_COOKIE) {
            Some(cookie) => match cookie.try_into() {
                Ok(token) => Outcome::Success(Authorised { token }),
                _ => Outcome::Failure((Status::BadRequest, AuthError::Invalid)),
            },
            None => {
                if request.uri().eq(&uri!("/login")) {
                    Outcome::Forward(())
                } else {
                    Outcome::Failure((Status::Unauthorized, AuthError::Unauthorized))
                }
            }
        }
    }
}
