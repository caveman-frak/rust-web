use {
    crate::auth::cookies::StateValue,
    anyhow::{anyhow, Error, Result},
    openidconnect::{
        core::{
            CoreAuthenticationFlow, CoreClient, CoreIdTokenClaims, CoreIdTokenVerifier,
            CoreProviderMetadata, CoreRevocableToken, CoreTokenIntrospectionResponse,
            CoreTokenResponse, CoreUserInfoClaims,
        },
        reqwest::async_http_client,
        AccessToken, AccessTokenHash, AuthorizationCode, ClientId, ClientSecret, CsrfToken,
        IssuerUrl, Nonce, OAuth2TokenResponse, PkceCodeChallenge, RedirectUrl, Scope,
        SubjectIdentifier, TokenIntrospectionResponse, TokenResponse,
    },
    rocket::{serde::Deserialize, Config},
    std::{
        fmt::{self, Display, Formatter},
        iter::Iterator,
    },
    url::Url,
};

#[derive(Debug, Deserialize)]
#[serde(crate = "rocket::serde")]
pub struct AuthServer {
    issuer: Url,
    realm: Option<String>,
    client: String,
    secret: Option<String>,
    scopes: Vec<String>,
}

impl Display for AuthServer {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let none = &String::from("-");
        let redacted = &String::from("[redacted]");
        write!(
            f,
            "Issuer Url: {}\nRealm: {}\nClient ID: {}\nSecret: {}\nScopes: {:?}",
            &self.issuer.as_str(),
            &self.realm.as_ref().unwrap_or(none),
            &self.client,
            &self.secret.as_ref().map_or(none, |_| redacted),
            &self.scopes
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

#[allow(dead_code)]
#[derive(Debug)]
pub struct AuthConnection {
    pub(crate) client: CoreClient,
    scopes: Vec<Scope>,
}

impl AuthConnection {
    async fn new(config: AuthConfig) -> Result<Self> {
        let (client, secret) = config.client();
        let issuer_url = config.issuer()?;
        rocket::info_!("Looking up meta data from {}", issuer_url.as_str());
        let provider_metadata =
            CoreProviderMetadata::discover_async(issuer_url, async_http_client).await?;
        let client = CoreClient::from_provider_metadata(provider_metadata, client, secret)
            .set_redirect_uri(config.redirect("code")?);

        Ok(Self {
            client,
            scopes: config
                .auth_server
                .scopes
                .iter()
                .map(|s| Scope::new(s.to_owned()))
                .collect(),
        })
    }

    pub(crate) fn authorise_url(
        &self,
        pkce_challenge: PkceCodeChallenge,
    ) -> (Url, CsrfToken, Nonce) {
        self.scopes
            .iter()
            .fold(
                self.client.authorize_url(
                    CoreAuthenticationFlow::AuthorizationCode,
                    CsrfToken::new_random,
                    Nonce::new_random,
                ),
                |a, s| a.add_scope(s.clone()),
            )
            .set_pkce_challenge(pkce_challenge)
            .url()
    }

    pub(crate) async fn exchange_code(
        &self,
        code: AuthorizationCode,
        state: &StateValue,
    ) -> Result<(CoreTokenResponse, CoreIdTokenClaims)> {
        let token_response = &self
            .client
            .exchange_code(code)
            .set_pkce_verifier(state.pkce_verifier())
            .request_async(async_http_client)
            .await?;

        let id_token = token_response
            .id_token()
            .ok_or_else(|| anyhow!("Server did not return an ID token"))?;
        let claims = id_token.claims(&self.id_token_verifier(), &state.nonce())?;

        if let Some(expected_access_token_hash) = claims.access_token_hash() {
            let actual_access_token_hash = AccessTokenHash::from_token(
                token_response.access_token(),
                &id_token.signing_alg()?,
            )?;
            if !actual_access_token_hash.eq(&expected_access_token_hash) {
                return Err(anyhow!("Invalid access token"));
            }
        }
        Ok((token_response.clone(), claims.clone()))
    }

    fn id_token_verifier(&self) -> CoreIdTokenVerifier {
        self.client
            .id_token_verifier()
            .require_audience_match(true)
            .require_issuer_match(true)
    }

    pub(crate) async fn get_user_info(
        &self,
        access_token: &AccessToken,
    ) -> Result<(
        Option<CoreTokenIntrospectionResponse>,
        Option<CoreUserInfoClaims>,
    )> {
        let token_introspect = match self.client.introspect(access_token) {
            Ok(request) => Some(request.request_async(async_http_client).await?),
            Err(e) => {
                rocket::warn_!("{}", e);
                None
            }
        };

        let subject = token_introspect.clone().map_or(None, |t| {
            t.sub()
                .map_or(None, |s| Some(SubjectIdentifier::new(s.to_owned())))
        });

        let user_info_claim = match self.client.user_info(access_token.clone(), subject) {
            Ok(request) => Some(
                request
                    .require_audience_match(true)
                    .require_issuer_match(true)
                    .require_signed_response(true)
                    .request_async(async_http_client)
                    .await?,
            ),
            Err(e) => {
                rocket::warn_!("{}", e);
                None
            }
        };
        Ok((token_introspect, user_info_claim))
    }

    pub(crate) async fn revoke(&self, access_token: AccessToken) -> Result<Option<()>> {
        match self
            .client
            .revoke_token(CoreRevocableToken::AccessToken(access_token))
        {
            Ok(request) => match request.request_async(async_http_client).await {
                Ok(()) => Ok(Some(())),
                Err(e) => Err(Error::new(e)),
            },
            Err(e) => {
                rocket::warn_!("{}", e);
                Ok(None)
            }
        }
    }
}

pub(crate) async fn init_connection() -> Result<AuthConnection> {
    let config = Config::figment().extract::<AuthConfig>()?;
    rocket::info_!("Initialising Auth Connection:\n{}", config);
    let connection = AuthConnection::new(config).await?;
    Ok(connection)
}
