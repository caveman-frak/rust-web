#![allow(dead_code)]
pub mod claims;
pub mod discovery;

use openidconnect::{
    core::{
        CoreApplicationType as CustomApplicationType, CoreAuthDisplay as CustomAuthDisplay,
        CoreAuthPrompt as CustomAuthPrompt, CoreClaimName as CustomClaimName,
        CoreClaimType as CustomClaimType, CoreClientAuthMethod as CustomClientAuthMethod,
        CoreErrorResponseType as CustomErrorResponseType, CoreGenderClaim as CustomGenderClaim,
        CoreGrantType as CustomGrantType, CoreJsonWebKey as CustomJsonWebKey,
        CoreJsonWebKeyType as CustomJsonWebKeyType, CoreJsonWebKeyUse as CustomJsonWebKeyUse,
        CoreJweContentEncryptionAlgorithm as CustomJweContentEncryptionAlgorithm,
        CoreJweKeyManagementAlgorithm as CustomJweKeyManagementAlgorithm,
        CoreJwsSigningAlgorithm as CustomJwsSigningAlgorithm,
        CoreRegisterErrorResponseType as CustomRegisterErrorResponseType,
        CoreResponseMode as CustomResponseMode, CoreResponseType as CustomResponseType,
        CoreRevocableToken as CustomRevocableToken,
        CoreRevocationErrorResponse as CustomRevocationErrorResponse,
        CoreSubjectIdentifierType as CustomSubjectIdentifierType, CoreTokenType as CustomTokenType,
    },
    registration::{
        AdditionalClientMetadata, AdditionalClientRegistrationResponse, ClientMetadata,
        ClientRegistrationRequest, ClientRegistrationResponse,
    },
    AdditionalClaims, AdditionalProviderMetadata, AuthenticationFlow, Client, ExtraTokenFields,
    IdToken, IdTokenClaims, IdTokenFields, IdTokenVerifier, JsonWebKeySet, ProviderMetadata,
    StandardErrorResponse, StandardTokenIntrospectionResponse, StandardTokenResponse,
    UserInfoClaims, UserInfoJsonWebToken, UserInfoVerifier,
};

///
/// OpenID Connect Custom token introspection response.
///
#[allow(type_alias_bounds)]
pub type CustomTokenIntrospectionResponse<ET: ExtraTokenFields> =
    StandardTokenIntrospectionResponse<ET, CustomTokenType>;

///
/// OpenID Connect Custom authentication flows.
///
pub type CustomAuthenticationFlow = AuthenticationFlow<CustomResponseType>;

///
/// OpenID Connect Custom client.
///
#[allow(type_alias_bounds)]
pub type CustomClient<AC: AdditionalClaims, ET: ExtraTokenFields> = Client<
    AC,
    CustomAuthDisplay,
    CustomGenderClaim,
    CustomJweContentEncryptionAlgorithm,
    CustomJwsSigningAlgorithm,
    CustomJsonWebKeyType,
    CustomJsonWebKeyUse,
    CustomJsonWebKey,
    CustomAuthPrompt,
    StandardErrorResponse<CustomErrorResponseType>,
    CustomTokenResponse<AC, ET>,
    CustomTokenType,
    CustomTokenIntrospectionResponse<ET>,
    CustomRevocableToken,
    CustomRevocationErrorResponse,
>;

///
/// OpenID Connect Custom client metadata.
///
#[allow(type_alias_bounds)]
pub type CustomClientMetadata<AM: AdditionalClientMetadata> = ClientMetadata<
    AM,
    CustomApplicationType,
    CustomClientAuthMethod,
    CustomGrantType,
    CustomJweContentEncryptionAlgorithm,
    CustomJweKeyManagementAlgorithm,
    CustomJwsSigningAlgorithm,
    CustomJsonWebKeyType,
    CustomJsonWebKeyUse,
    CustomJsonWebKey,
    CustomResponseType,
    CustomSubjectIdentifierType,
>;

///
/// OpenID Connect Custom client registration request.
///
#[allow(type_alias_bounds)]
pub type CustomClientRegistrationRequest<
    AM: AdditionalClientMetadata,
    AR: AdditionalClientRegistrationResponse,
> = ClientRegistrationRequest<
    AM,
    AR,
    CustomApplicationType,
    CustomClientAuthMethod,
    CustomRegisterErrorResponseType,
    CustomGrantType,
    CustomJweContentEncryptionAlgorithm,
    CustomJweKeyManagementAlgorithm,
    CustomJwsSigningAlgorithm,
    CustomJsonWebKeyType,
    CustomJsonWebKeyUse,
    CustomJsonWebKey,
    CustomResponseType,
    CustomSubjectIdentifierType,
>;

///
/// OpenID Connect Custom client registration response.
///
#[allow(type_alias_bounds)]
pub type CustomClientRegistrationResponse<
    AM: AdditionalClientMetadata,
    AR: AdditionalClientRegistrationResponse,
> = ClientRegistrationResponse<
    AM,
    AR,
    CustomApplicationType,
    CustomClientAuthMethod,
    CustomGrantType,
    CustomJweContentEncryptionAlgorithm,
    CustomJweKeyManagementAlgorithm,
    CustomJwsSigningAlgorithm,
    CustomJsonWebKeyType,
    CustomJsonWebKeyUse,
    CustomJsonWebKey,
    CustomResponseType,
    CustomSubjectIdentifierType,
>;

///
/// OpenID Connect Custom ID token.
///
#[allow(type_alias_bounds)]
pub type CustomIdToken<AC: AdditionalClaims> = IdToken<
    AC,
    CustomGenderClaim,
    CustomJweContentEncryptionAlgorithm,
    CustomJwsSigningAlgorithm,
    CustomJsonWebKeyType,
>;

///
/// OpenID Connect Custom ID token claims.
///
#[allow(type_alias_bounds)]
pub type CustomIdTokenClaims<AC: AdditionalClaims> = IdTokenClaims<AC, CustomGenderClaim>;

///
/// OpenID Connect Custom ID token fields.
///
#[allow(type_alias_bounds)]
pub type CustomIdTokenFields<AC: AdditionalClaims, ET: ExtraTokenFields> = IdTokenFields<
    AC,
    ET,
    CustomGenderClaim,
    CustomJweContentEncryptionAlgorithm,
    CustomJwsSigningAlgorithm,
    CustomJsonWebKeyType,
>;

///
/// OpenID Connect Custom ID token verifier.
///
pub type CustomIdTokenVerifier<'a> = IdTokenVerifier<
    'a,
    CustomJwsSigningAlgorithm,
    CustomJsonWebKeyType,
    CustomJsonWebKeyUse,
    CustomJsonWebKey,
>;

///
/// OpenID Connect Custom token response.
///
#[allow(type_alias_bounds)]
pub type CustomTokenResponse<AC: AdditionalClaims, ET: ExtraTokenFields> =
    StandardTokenResponse<CustomIdTokenFields<AC, ET>, CustomTokenType>;

///
/// OpenID Connect Custom JSON Web Key Set.
///
pub type CustomJsonWebKeySet = JsonWebKeySet<
    CustomJwsSigningAlgorithm,
    CustomJsonWebKeyType,
    CustomJsonWebKeyUse,
    CustomJsonWebKey,
>;

///
/// OpenID Connect Custom provider metadata.
///
#[allow(type_alias_bounds)]
pub type CustomProviderMetadata<AM: AdditionalProviderMetadata> = ProviderMetadata<
    AM,
    CustomAuthDisplay,
    CustomClientAuthMethod,
    CustomClaimName,
    CustomClaimType,
    CustomGrantType,
    CustomJweContentEncryptionAlgorithm,
    CustomJweKeyManagementAlgorithm,
    CustomJwsSigningAlgorithm,
    CustomJsonWebKeyType,
    CustomJsonWebKeyUse,
    CustomJsonWebKey,
    CustomResponseMode,
    CustomResponseType,
    CustomSubjectIdentifierType,
>;

///
/// OpenID Connect Custom user info claims.
///
#[allow(type_alias_bounds)]
pub type CustomUserInfoClaims<AC: AdditionalClaims> = UserInfoClaims<AC, CustomGenderClaim>;

///
/// OpenID Connect Custom user info JSON Web Token.
///
#[allow(type_alias_bounds)]
pub type CustomUserInfoJsonWebToken<AC: AdditionalClaims> = UserInfoJsonWebToken<
    AC,
    CustomGenderClaim,
    CustomJweContentEncryptionAlgorithm,
    CustomJwsSigningAlgorithm,
    CustomJsonWebKeyType,
>;

///
/// OpenID Connect Custom user info verifier.
///
#[allow(type_alias_bounds)]
pub type CustomUserInfoVerifier<'a> = UserInfoVerifier<
    'a,
    CustomJweContentEncryptionAlgorithm,
    CustomJwsSigningAlgorithm,
    CustomJsonWebKeyType,
    CustomJsonWebKeyUse,
    CustomJsonWebKey,
>;
