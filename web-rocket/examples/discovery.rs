use {
    anyhow::Result,
    openidconnect::{core::CoreProviderMetadata, reqwest::http_client, IssuerUrl},
    std::convert::TryInto,
    url::Url,
};

pub fn main() -> Result<()> {
    let url: Url = "http://grey-dragon.local:8080/auth/".try_into()?;
    let realm = url.join("realms/test")?;
    println!("Url: {} -> {}", url.as_str(), realm.as_str());

    let provider_metadata =
        CoreProviderMetadata::discover(&IssuerUrl::from_url(realm), http_client)?;

    println!("{:#?}", provider_metadata);

    Ok(())
}
