use {
    percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC},
    rocket::{
        http::{hyper::Uri, Status},
        request::{FromRequest, Outcome, Request},
        serde::Deserialize,
    },
    std::net::{IpAddr, SocketAddr},
};

const BEARER: &str = "Bearer ";

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
#[serde(crate = "rocket::serde")]
pub struct Server {
    uri: String,
    realm: String,
    client: String,
    secret: Option<String>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
#[serde(crate = "rocket::serde")]
pub struct OAuth {
    server: Server,
}

#[allow(dead_code)]
impl<'a> OAuth {
    pub fn uri(
        &self,
        response_type: &'a str,
        response_mode: &'a str,
        redirect_uri: &'a str,
    ) -> String {
        let Server {
            uri, realm, client, ..
        } = &self.server;
        let nonce = 1234567890;
        let encoded = utf8_percent_encode(redirect_uri, NON_ALPHANUMERIC);

        format!(
            "{}/auth/realms/{}/protocol/openid-connect/auth\
        ?response_type={}\
        &response_mode={}\
        &client_id={}\
        &scope=openid%20profile\
        &nonce={}\
        &redirect_uri={}",
            uri, realm, client, response_type, response_mode, nonce, encoded
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

#[derive(Debug)]
pub struct Host<'r> {
    host: Option<&'r str>,
    remote: Option<SocketAddr>,
    client_ip: Option<IpAddr>,
    real_ip: Option<IpAddr>,
}

#[allow(dead_code)]
impl<'r> Host<'r> {
    pub fn host(&self) -> Option<&'r str> {
        self.host
    }
    pub fn remote(&self) -> Option<SocketAddr> {
        self.remote
    }
    pub fn client_ip(&self) -> Option<IpAddr> {
        self.client_ip
    }
    pub fn real_ip(&self) -> Option<IpAddr> {
        self.real_ip
    }

    pub fn uri(&self, path: &'r str) -> Option<String> {
        if let Some(host) = self.host {
            let uri = Uri::builder()
                .scheme("http")
                .authority(host)
                .path_and_query(path)
                .build()
                .unwrap();

            Some(uri.to_string())
        } else {
            None
        }
    }

    fn from(request: &'r Request<'_>) -> Self {
        let host = request.headers().get_one("Host");
        let client_ip = request.client_ip();
        let remote = request.remote();
        let real_ip = request.real_ip();

        Host {
            host,
            remote,
            client_ip,
            real_ip,
        }
    }
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for Host<'r> {
    type Error = ();

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        Outcome::Success(Host::from(request))
    }
}
