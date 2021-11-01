use {
    crate::oidc::{
        CustomClient, CustomClientAuthMethod, CustomJsonWebKeyType, CustomJwsSigningAlgorithm,
    },
    openidconnect::{
        AdditionalClaims, AdditionalProviderMetadata, ClientAuthMethod, ExtraTokenFields,
        IntrospectionUrl, JsonWebKeyType, JwsSigningAlgorithm, RevocationUrl,
    },
    serde::{Deserialize, Serialize},
    std::marker::PhantomData,
};

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
struct ExtraAdditionalProviderMetadata<CA, JS, JT>
where
    CA: ClientAuthMethod,
    JS: JwsSigningAlgorithm<JT>,
    JT: JsonWebKeyType,
{
    #[serde(skip_serializing_if = "Option::is_none")]
    revocation_endpoint: Option<RevocationUrl>,
    #[serde(
        bound(deserialize = "CA: ClientAuthMethod"),
        skip_serializing_if = "Option::is_none"
    )]
    revocation_endpoint_auth_methods_supported: Option<Vec<CA>>,
    #[serde(
        bound(deserialize = "JS: JwsSigningAlgorithm<JT>"),
        skip_serializing_if = "Option::is_none"
    )]
    revocation_endpoint_auth_signing_alg_values_supported: Option<Vec<JS>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    introspection_endpoint: Option<IntrospectionUrl>,
    #[serde(
        bound(deserialize = "CA: ClientAuthMethod"),
        skip_serializing_if = "Option::is_none"
    )]
    introspection_endpoint_auth_methods_supported: Option<Vec<CA>>,
    #[serde(
        bound(deserialize = "JS: JwsSigningAlgorithm<JT>"),
        skip_serializing_if = "Option::is_none"
    )]
    introspection_endpoint_auth_signing_alg_values_supported: Option<Vec<JS>>,
    #[serde(skip)]
    _phantom_jt: PhantomData<JT>,
}

impl<CA, JS, JT> ExtraAdditionalProviderMetadata<CA, JS, JT>
where
    CA: ClientAuthMethod,
    JS: JwsSigningAlgorithm<JT>,
    JT: JsonWebKeyType,
{
    pub fn apply_to<A, ET>(&self, mut client: CustomClient<A, ET>) -> CustomClient<A, ET>
    where
        A: AdditionalClaims,
        ET: ExtraTokenFields,
    {
        if let Some(introspection_endpoint) = self.introspection_endpoint() {
            client = client.set_introspection_uri(introspection_endpoint.clone());
        }
        if let Some(revocation_endpoint) = self.revocation_endpoint() {
            client = client.set_revocation_uri(revocation_endpoint.clone());
        }
        client
    }

    pub fn revocation_endpoint(&self) -> Option<&RevocationUrl> {
        self.revocation_endpoint.as_ref()
    }
    pub fn revocation_endpoint_auth_methods_supported(&self) -> Option<&Vec<CA>> {
        self.revocation_endpoint_auth_methods_supported.as_ref()
    }
    pub fn revocation_endpoint_auth_signing_alg_values_supported(&self) -> Option<&Vec<JS>> {
        self.revocation_endpoint_auth_signing_alg_values_supported
            .as_ref()
    }
    pub fn introspection_endpoint(&self) -> Option<&IntrospectionUrl> {
        self.introspection_endpoint.as_ref()
    }
    pub fn introspection_endpoint_auth_methods_supported(&self) -> Option<&Vec<CA>> {
        self.introspection_endpoint_auth_methods_supported.as_ref()
    }
    pub fn introspection_endpoint_auth_signing_alg_values_supported(&self) -> Option<&Vec<JS>> {
        self.introspection_endpoint_auth_signing_alg_values_supported
            .as_ref()
    }
}

impl<CA, JS, JT> AdditionalProviderMetadata for ExtraAdditionalProviderMetadata<CA, JS, JT>
where
    CA: ClientAuthMethod + Clone,
    JS: JwsSigningAlgorithm<JT>,
    JT: JsonWebKeyType,
{
}

type CustomAdditionalProviderMetadata = ExtraAdditionalProviderMetadata<
    CustomClientAuthMethod,
    CustomJwsSigningAlgorithm,
    CustomJsonWebKeyType,
>;

#[cfg(test)]
mod tests {
    use {super::*, crate::oidc::*, openidconnect::IssuerUrl};

    type ExtraProviderMetadata = CustomProviderMetadata<CustomAdditionalProviderMetadata>;

    #[test]
    fn test_basic_metadata() {
        let provider_metadata: ExtraProviderMetadata = serde_json::from_str(
            r#"{
                    "issuer": "http://grey-dragon.local:8080/auth/realms/test",
                    "authorization_endpoint": "http://grey-dragon.local:8080/auth/realms/test/protocol/openid-connect/auth",
                    "jwks_uri": "http://grey-dragon.local:8080/auth/realms/test/protocol/openid-connect/certs",
                    "response_types_supported" : ["code"],
                    "subject_types_supported" : ["public"],
                    "id_token_signing_alg_values_supported" : ["HS256"]
                }"#
            )
        .expect("failed to deserialize");
        assert_eq!(
            IssuerUrl::new("http://grey-dragon.local:8080/auth/realms/test".to_string()).unwrap(),
            *provider_metadata.issuer()
        );
        assert_eq!(
            provider_metadata
                .additional_metadata()
                .introspection_endpoint(),
            None
        );
        assert_eq!(
            provider_metadata
                .additional_metadata()
                .revocation_endpoint(),
            None
        );
    }

    #[test]
    fn test_provider_metadata() {
        let provider_metadata: ExtraProviderMetadata = serde_json::from_str(
            r#"{
                    "issuer": "http://grey-dragon.local:8080/auth/realms/test",
                    "authorization_endpoint": "http://grey-dragon.local:8080/auth/realms/test/protocol/openid-connect/auth",
                    "jwks_uri": "http://grey-dragon.local:8080/auth/realms/test/protocol/openid-connect/certs",
                    "introspection_endpoint": "http://grey-dragon.local:8080/auth/realms/test/protocol/openid-connect/token/introspect",
                    "revocation_endpoint": "http://grey-dragon.local:8080/auth/realms/test/protocol/openid-connect/revoke",
                    "response_types_supported" : ["code"],
                    "subject_types_supported" : ["public"],
                    "id_token_signing_alg_values_supported" : ["HS256"]
                }"#
            )
        .expect("failed to deserialize");
        assert_eq!(
            IssuerUrl::new("http://grey-dragon.local:8080/auth/realms/test".to_string()).unwrap(),
            *provider_metadata.issuer()
        );
        assert_eq!(
            &IntrospectionUrl::new("http://grey-dragon.local:8080/auth/realms/test/protocol/openid-connect/token/introspect".to_string()).unwrap(),
            provider_metadata.additional_metadata().introspection_endpoint().expect("introspect endpoint") 
        );
        assert_eq!(
            &RevocationUrl::new(
                "http://grey-dragon.local:8080/auth/realms/test/protocol/openid-connect/revoke"
                    .to_string()
            )
            .unwrap(),
            provider_metadata
                .additional_metadata()
                .revocation_endpoint()
                .expect("revocation endpoint")
        );
    }

    #[test]
    fn test_revocation_metadata() {
        let provider_metadata: ExtraProviderMetadata = serde_json::from_str(
            r#"{
                    "issuer": "http://grey-dragon.local:8080/auth/realms/test",
                    "authorization_endpoint": "http://grey-dragon.local:8080/auth/realms/test/protocol/openid-connect/auth",
                    "jwks_uri": "http://grey-dragon.local:8080/auth/realms/test/protocol/openid-connect/certs",
                    "revocation_endpoint": "http://grey-dragon.local:8080/auth/realms/test/protocol/openid-connect/revoke",
                    "response_types_supported" : ["code"],
                    "subject_types_supported" : ["public"],
                    "id_token_signing_alg_values_supported" : ["HS256"]
                }"#
            )
        .expect("failed to deserialize");
        assert_eq!(
            provider_metadata
                .additional_metadata()
                .introspection_endpoint(),
            None
        );
        assert_eq!(
            provider_metadata
                .additional_metadata()
                .revocation_endpoint()
                .expect("revocation endpoint"),
            &RevocationUrl::new(
                "http://grey-dragon.local:8080/auth/realms/test/protocol/openid-connect/revoke"
                    .to_string()
            )
            .unwrap(),
        );
    }

    #[test]
    fn test_introspect_metadata() {
        let provider_metadata: ExtraProviderMetadata = serde_json::from_str(
            r#"{
                    "issuer": "http://grey-dragon.local:8080/auth/realms/test",
                    "authorization_endpoint": "http://grey-dragon.local:8080/auth/realms/test/protocol/openid-connect/auth",
                    "jwks_uri": "http://grey-dragon.local:8080/auth/realms/test/protocol/openid-connect/certs",
                    "introspection_endpoint": "http://grey-dragon.local:8080/auth/realms/test/protocol/openid-connect/token/introspect",
                    "response_types_supported" : ["code"],
                    "subject_types_supported" : ["public"],
                    "id_token_signing_alg_values_supported" : ["HS256"]
                }"#
            )
        .expect("failed to deserialize");
        assert_eq!(
            provider_metadata.additional_metadata().introspection_endpoint().expect("introspect endpoint"),
            &IntrospectionUrl::new(
                "http://grey-dragon.local:8080/auth/realms/test/protocol/openid-connect/token/introspect"
                    .to_string()
            )
            .unwrap()
        );
        assert_eq!(
            provider_metadata
                .additional_metadata()
                .revocation_endpoint(),
            None
        );
    }

    #[test]
    fn test_both_metadata() {
        let provider_metadata: ExtraProviderMetadata = serde_json::from_str(
            r#"{
                    "issuer": "http://grey-dragon.local:8080/auth/realms/test",
                    "authorization_endpoint": "http://grey-dragon.local:8080/auth/realms/test/protocol/openid-connect/auth",
                    "jwks_uri": "http://grey-dragon.local:8080/auth/realms/test/protocol/openid-connect/certs",
                    "introspection_endpoint": "http://grey-dragon.local:8080/auth/realms/test/protocol/openid-connect/token/introspect",
                    "introspection_endpoint_auth_methods_supported": ["private_key_jwt"],
                    "introspection_endpoint_auth_signing_alg_values_supported": ["ES256"],
                    "revocation_endpoint": "http://grey-dragon.local:8080/auth/realms/test/protocol/openid-connect/revoke",
                    "revocation_endpoint_auth_methods_supported": ["client_secret_jwt"],
                    "revocation_endpoint_auth_signing_alg_values_supported": ["PS384"],
                    "response_types_supported" : ["code"],
                    "subject_types_supported" : ["public"],
                    "id_token_signing_alg_values_supported" : ["HS256"]
                }"#
            )
        .expect("failed to deserialize");
        assert_eq!(
            provider_metadata.additional_metadata().introspection_endpoint().expect("introspect endpoint") ,
            &IntrospectionUrl::new("http://grey-dragon.local:8080/auth/realms/test/protocol/openid-connect/token/introspect".to_string()).unwrap()
        );
        assert_eq!(
            provider_metadata
                .additional_metadata()
                .introspection_endpoint_auth_methods_supported()
                .expect("introspection auth method"),
            &vec!(CustomClientAuthMethod::PrivateKeyJwt)
        );
        assert_eq!(
            provider_metadata
                .additional_metadata()
                .introspection_endpoint_auth_signing_alg_values_supported()
                .expect("introspection signing alg"),
            &vec!(CustomJwsSigningAlgorithm::EcdsaP256Sha256)
        );
        assert_eq!(
            provider_metadata
                .additional_metadata()
                .revocation_endpoint()
                .expect("revocation endpoint"),
            &RevocationUrl::new(
                "http://grey-dragon.local:8080/auth/realms/test/protocol/openid-connect/revoke"
                    .to_string()
            )
            .unwrap()
        );
        assert_eq!(
            provider_metadata
                .additional_metadata()
                .revocation_endpoint_auth_methods_supported()
                .expect("revocation auth method"),
            &vec!(CustomClientAuthMethod::ClientSecretJwt)
        );
        assert_eq!(
            provider_metadata
                .additional_metadata()
                .revocation_endpoint_auth_signing_alg_values_supported()
                .expect("revocation signing alg"),
            &vec!(CustomJwsSigningAlgorithm::RsaSsaPssSha384)
        );
    }
}
