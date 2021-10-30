use {
    crate::{
        auth::{
            cookies::{self, AuthorisationCodeParams, StateValue, TokenValue},
            {connection::AuthConnection, guard::Authorised},
        },
        error::{err, Error, Result},
    },
    openidconnect::PkceCodeChallenge,
    rocket::{
        http::{Cookie, CookieJar},
        request::Request,
        response::{status::Accepted, Redirect},
        Build, Rocket, State,
    },
};

#[get("/login")]
fn login(authorised: Authorised) -> Result<String> {
    rocket::info_!("login");
    Ok(format!(
        "Token = {}",
        serde_json::to_string_pretty(authorised.token())?
    ))
}

#[get("/login", rank = 1)]
fn login_redirect(connection: &State<AuthConnection>, jar: &CookieJar<'_>) -> Redirect {
    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
    let (authorise_url, csrf_state, nonce) = connection.authorise_url(pkce_challenge);
    jar.add(StateValue::new(&csrf_state, &nonce, &pkce_verifier).into());
    Redirect::found(authorise_url.to_string())
}

#[get("/code?<params..>")]
async fn login_code(
    connection: &State<AuthConnection>,
    jar: &CookieJar<'_>,
    params: AuthorisationCodeParams,
) -> Result<String> {
    match jar.get(cookies::CODE_STATE_COOKIE) {
        Some(state_cookie) => {
            let state = StateValue::try_from(state_cookie)?;
            jar.remove(Cookie::named(cookies::CODE_STATE_COOKIE));

            if state.state().eq(params.state()) {
                let (token_response, id_claims) =
                    connection.exchange_code(params.code(), &state).await?;

                jar.add(TokenValue::new(&token_response).into());

                Ok(format!(
                    "ID Claims = {:#?}\nToken = {}",
                    id_claims,
                    serde_json::to_string_pretty(&token_response)?
                ))
            } else {
                err("Invalid CSRF state")
            }
        }
        _ => Err(Error::msg("Missing state cookie")),
    }
}

#[get("/logout")]
async fn logout(
    authorised: Authorised,
    connection: &State<AuthConnection>,
    jar: &CookieJar<'_>,
) -> Result<Accepted<()>> {
    if let Some(_) = connection
        .revoke(authorised.token().access().clone())
        .await?
    {
        rocket::info_!("Access token revocated");
    }
    jar.remove(Cookie::named(cookies::TOKEN_COOKIE));
    Ok(Accepted(None))
}

#[catch(401)]
fn unauthorised(request: &Request) -> String {
    format!("You have to be logged in to access '{}'", request.uri())
}

#[catch(404)]
fn not_found(request: &Request) -> String {
    format!(
        "'{}' are not the droids you were looking for!",
        request.uri()
    )
}

pub(crate) async fn init_routes(rocket: Rocket<Build>) -> Rocket<Build> {
    rocket::info_!("Mounting Routes");
    rocket
        .mount("/", routes![login, login_redirect, login_code, logout])
        .register("/", catchers![unauthorised, not_found])
}
