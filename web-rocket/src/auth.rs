use {
    anyhow::Result,
    openidconnect::{
        core::{CoreAuthenticationFlow, CoreClient, CoreProviderMetadata},
        reqwest::async_http_client,
        AuthorizationCode, ClientId, ClientSecret, CsrfToken, IssuerUrl, Nonce, RedirectUrl, Scope,
    },
    rocket::{
        fairing::AdHoc,
        http::Status,
        request::{FromRequest, Outcome},
        response::Redirect,
        serde::Deserialize,
        Build, Config, Request, Rocket, State,
    },
    std::{
        fmt::{self, Display, Formatter},
        path::PathBuf,
    },
    url::Url,
};

const BEARER: &str = "Bearer ";

#[derive(Debug, Deserialize)]
#[serde(crate = "rocket::serde")]
pub struct AuthServer {
    issuer: Url,
    realm: Option<String>,
    client: String,
    secret: Option<String>,
}

impl Display for AuthServer {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let none = &String::from("-");
        let redacted = &String::from("[redacted]");
        write!(
            f,
            "Issuer Url: {}\nRealm: {}\nClient ID: {}\nSecret: {}",
            &self.issuer.as_str(),
            &self.realm.as_ref().unwrap_or(none),
            &self.client,
            &self.secret.as_ref().map_or(none, |_| redacted)
        )
    }
}

#[derive(Debug, Deserialize)]
#[serde(crate = "rocket::serde")]
pub struct AuthConfig {
    base_url: Url,
    auth_server: AuthServer,
}

impl Display for AuthConfig {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Base Url: {}\n{}",
            &self.base_url.as_str(),
            &self.auth_server
        )
    }
}

impl AuthConfig {
    pub fn issuer(&self) -> Result<IssuerUrl> {
        let url = if let Some(realm) = &self.auth_server.realm {
            self.auth_server
                .issuer
                .join(&*format!("realms/{}", realm))?
        } else {
            self.auth_server.issuer.clone()
        };
        rocket::info_!(
            "Issuer Url: {} -> {}",
            self.auth_server.issuer.as_str(),
            url.as_str()
        );
        Ok(IssuerUrl::from_url(url))
    }

    pub fn redirect(&self, path: &str) -> Result<RedirectUrl> {
        Ok(RedirectUrl::from_url(self.base_url.join(path)?))
    }

    pub fn client(&self) -> (ClientId, Option<ClientSecret>) {
        (
            ClientId::new(self.auth_server.client.to_owned()),
            self.auth_server
                .secret
                .as_ref()
                .map_or(None, |s| Some(ClientSecret::new(s.to_owned()))),
        )
    }
}

#[derive(Debug)]
pub struct Authorization {
    token: String,
}

#[derive(Debug)]
pub enum AuthError {
    Invalid,
}

impl Authorization {
    fn extract_token(s: &str) -> Option<String> {
        if s.starts_with(BEARER) {
            Some(s.trim_start_matches(BEARER).to_owned())
        } else {
            None
        }
    }
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for Authorization {
    type Error = AuthError;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        match request.headers().get_one("Authorization") {
            Some(key) => match Authorization::extract_token(key) {
                Some(token) => Outcome::Success(Authorization { token }),
                _ => Outcome::Failure((Status::Forbidden, AuthError::Invalid)),
            },
            None => Outcome::Forward(()),
        }
    }
}

#[allow(dead_code)]
#[derive(Debug)]
pub struct AuthConnection {
    pub(crate) client: CoreClient,
    pub(crate) authorize_url: Url,
    pub(crate) csrf_state: CsrfToken,
    pub(crate) nonce: Nonce,
}

impl AuthConnection {
    async fn new(config: AuthConfig) -> Result<Self> {
        let (client, secret) = config.client();
        let issuer_url = config.issuer()?;
        rocket::info_!("Looking up meta data from {}", issuer_url.as_str());
        let provider_metadata = CoreProviderMetadata::discover_async(issuer_url, async_http_client)
            .await
            .unwrap_or_else(|_| {
                rocket::error_!("Failed to discover metadata");
                unreachable!();
            });
        let client = CoreClient::from_provider_metadata(provider_metadata, client, secret)
            .set_redirect_uri(config.redirect("code")?);

        let (authorize_url, csrf_state, nonce) = client
            .authorize_url(
                CoreAuthenticationFlow::AuthorizationCode,
                CsrfToken::new_random,
                Nonce::new_random,
            )
            .add_scope(Scope::new("email".to_string()))
            .add_scope(Scope::new("profile".to_string()))
            .url();

        Ok(Self {
            client,
            authorize_url,
            csrf_state,
            nonce,
        })
    }
}

async fn init_auth() -> AuthConnection {
    let config = Config::figment().extract::<AuthConfig>().unwrap();
    rocket::info_!("Initialising Auth:\n{}", config);
    match AuthConnection::new(config).await {
        Ok(auth) => auth,
        _ => panic!("Failed to initialise Authorisation Connection"),
    }
}

async fn init_routes(rocket: Rocket<Build>) -> Rocket<Build> {
    rocket::info_!("Mounting Routes");
    rocket.mount("/", routes![login, login_redirect, login_code])
}

#[get("/login")]
fn login(auth: Authorization) -> String {
    rocket::info_!("login");
    format!("Welcome to the future! \n{:?}", auth)
}

#[get("/login", rank = 1)]
fn login_redirect(auth: &State<AuthConnection>) -> Redirect {
    Redirect::to(auth.authorize_url.to_string())
}

#[get("/<path..>?<code>&<session_state>")]
async fn login_code<'a>(
    auth: &State<AuthConnection>,
    path: PathBuf,
    code: String,
    session_state: &'a str,
) -> String {
    rocket::info_!(
        "Path = {:?}\nSession = {}\nCode = {}",
        path,
        session_state,
        code
    );
    let code = AuthorizationCode::new(code);
    let token_response = auth
        .client
        .exchange_code(code)
        .request_async(async_http_client)
        .await
        .unwrap();

    format!("Token = {:#?}", token_response)
}

pub fn stage() -> AdHoc {
    AdHoc::on_ignite("Authorisation Stage", |rocket| async {
        rocket
            .manage(init_auth().await)
            .attach(AdHoc::on_ignite("Route Initialisation", init_routes))
    })
}
