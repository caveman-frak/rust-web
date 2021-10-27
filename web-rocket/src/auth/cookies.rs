use {
    anyhow::{anyhow, Error, Result},
    openidconnect::{
        core::{CoreIdToken, CoreTokenResponse},
        AccessToken, AuthorizationCode, CsrfToken, Nonce, OAuth2TokenResponse, PkceCodeVerifier,
        RefreshToken,
    },
    rocket::{
        http::{Cookie, SameSite},
        serde::{Deserialize, Serialize},
    },
    time::Duration,
};

pub(crate) const CODE_STATE_COOKIE: &str = "authorisation-code-state";
pub(crate) const TOKEN_COOKIE: &str = "authorisation-token";

#[allow(dead_code)]
#[derive(Debug, FromForm)]
pub(crate) struct AuthorisationCodeParams {
    state: String,
    session_state: String,
    code: String,
}

impl AuthorisationCodeParams {
    pub(crate) fn state(&self) -> &str {
        &self.state
    }

    pub(crate) fn code(&self) -> AuthorizationCode {
        AuthorizationCode::new(self.code.to_owned())
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct StateValue {
    state: String,
    nonce: String,
    pkce_verifier: String,
}

#[allow(dead_code)]
impl StateValue {
    pub(crate) fn new(state: &CsrfToken, nonce: &Nonce, pkce_verifier: &PkceCodeVerifier) -> Self {
        Self {
            state: state.secret().clone(),
            nonce: nonce.secret().clone(),
            pkce_verifier: pkce_verifier.secret().clone(),
        }
    }

    pub(crate) fn state(&self) -> &str {
        &self.state
    }

    pub(crate) fn nonce(&self) -> Nonce {
        Nonce::new(self.nonce.to_owned())
    }

    pub(crate) fn pkce_verifier(&self) -> PkceCodeVerifier {
        PkceCodeVerifier::new(self.pkce_verifier.to_owned())
    }
}

impl<'r> From<StateValue> for Cookie<'r> {
    fn from(state_cookie: StateValue) -> Cookie<'r> {
        Cookie::build(
            CODE_STATE_COOKIE,
            serde_json::to_string(&state_cookie).expect("unable to serialise state cookie"),
        )
        .secure(false)
        .same_site(SameSite::Lax)
        .http_only(true)
        .max_age(Duration::minutes(5))
        .finish()
    }
}

impl TryFrom<&Cookie<'static>> for StateValue {
    type Error = Error;

    fn try_from(cookie: &Cookie<'static>) -> Result<StateValue> {
        if cookie.name().eq(CODE_STATE_COOKIE) {
            let state_value: StateValue = serde_json::from_str(cookie.value())?;
            Ok(state_value)
        } else {
            Err(anyhow!("Incorrect cookie name"))
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct TokenValue {
    access: AccessToken,
    id: Option<CoreIdToken>,
    refresh: Option<RefreshToken>,
}

#[allow(dead_code)]
impl TokenValue {
    pub(crate) fn new(token_response: &CoreTokenResponse) -> Self {
        Self {
            access: token_response.access_token().clone(),
            id: token_response
                .extra_fields()
                .id_token()
                .map_or(None, |v| Some(v.clone())),
            refresh: token_response
                .refresh_token()
                .map_or(None, |v| Some(v.clone())),
        }
    }

    pub(crate) fn access(&self) -> &AccessToken {
        &self.access
    }

    pub(crate) fn id(&self) -> Option<&CoreIdToken> {
        self.id.as_ref()
    }

    pub(crate) fn refresh(&self) -> Option<&RefreshToken> {
        self.refresh.as_ref()
    }
}

impl<'r> From<TokenValue> for Cookie<'r> {
    fn from(token_cookie: TokenValue) -> Cookie<'r> {
        Cookie::build(
            TOKEN_COOKIE,
            serde_json::to_string(&token_cookie).expect("unable to serialise state cookie"),
        )
        .secure(false)
        .same_site(SameSite::Strict)
        .http_only(true)
        .max_age(Duration::minutes(5))
        .finish()
    }
}

impl TryFrom<&Cookie<'static>> for TokenValue {
    type Error = Error;

    fn try_from(cookie: &Cookie<'static>) -> Result<TokenValue> {
        if cookie.name().eq(TOKEN_COOKIE) {
            let token_value: TokenValue = serde_json::from_str(cookie.value())?;
            Ok(token_value)
        } else {
            Err(anyhow!("Incorrect cookie name"))
        }
    }
}
