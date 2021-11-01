use {
    openidconnect::AdditionalClaims,
    serde::{Deserialize, Serialize},
    std::collections::HashMap,
};

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(from = "String", into = "String")]
struct Role {
    name: String,
}

#[allow(dead_code)]
impl Role {
    pub fn new(name: String) -> Self {
        Self { name }
    }

    pub fn name(&self) -> &str {
        &self.name
    }
}

impl From<String> for Role {
    fn from(name: String) -> Self {
        Role::new(name)
    }
}

impl From<Role> for String {
    fn from(role: Role) -> Self {
        role.name
    }
}

impl From<&str> for Role {
    fn from(name: &str) -> Self {
        Role::new(String::from(name))
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize, Default)]
struct AccessClaim {
    roles: Vec<Role>,
}

#[allow(dead_code)]
impl AccessClaim {
    pub fn roles(&self) -> &Vec<Role> {
        &self.roles
    }

    pub fn has_role<T: Into<Role>>(&self, role: T) -> bool {
        self.roles.contains(&role.into())
    }
}

type RealmAccess = Option<AccessClaim>;

trait RealmAccessTrait {
    fn has_role<T: Into<Role>>(&self, role: T) -> bool;
}

impl RealmAccessTrait for RealmAccess {
    fn has_role<T: Into<Role>>(&self, role: T) -> bool {
        if let Some(access_claim) = self {
            access_claim.has_role(role.into())
        } else {
            false
        }
    }
}

type ResourceAccess = Option<HashMap<String, AccessClaim>>;

trait ResourceAccessTrait {
    fn has_role<T: Into<String>, R: Into<Role>>(&self, resource: T, role: R) -> bool;
}

impl ResourceAccessTrait for ResourceAccess {
    fn has_role<T: Into<String>, R: Into<Role>>(&self, resource: T, role: R) -> bool {
        if let Some(map) = self {
            if let Some(access_claim) = map.get(&resource.into()) {
                access_claim.has_role(role.into())
            } else {
                false
            }
        } else {
            false
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize, Default)]
struct RoleClaims {
    pub resource_access: ResourceAccess,
    pub realm_access: RealmAccess,
}

#[allow(dead_code)]
impl RoleClaims {
    pub fn resource_access(&self) -> &ResourceAccess {
        &self.resource_access
    }
    pub fn realm_access(&self) -> &RealmAccess {
        &self.realm_access
    }
}

impl AdditionalClaims for RoleClaims {}

#[cfg(test)]
mod tests {
    use {super::*, crate::oidc::CustomUserInfoClaims, openidconnect::reqwest::HttpClientError};

    #[test]
    fn test_realm_claims() {
        let claims = CustomUserInfoClaims::<RoleClaims>::from_json::<HttpClientError>(
            r#"{
                "iss": "https://server.example.com",
                "sub": "subject",
                "aud": ["audience"],
                "realm_access": {
                    "roles": [
                        "role1"
                    ]
                }
            }"#
            .as_bytes(),
            None,
        )
        .expect("failed to deserialize");
        assert_eq!(
            claims
                .additional_claims()
                .realm_access
                .as_ref()
                .expect("missing realm access")
                .roles,
            vec![Role::from("role1")]
        );
        assert!(claims.additional_claims().realm_access().has_role("role1"));
        assert_eq!(claims.additional_claims().resource_access, None);
    }

    #[test]
    fn test_resource_claims() {
        let claims = CustomUserInfoClaims::<RoleClaims>::from_json::<HttpClientError>(
            r#"{
                "iss": "https://server.example.com",
                "sub": "subject",
                "aud": ["audience"],
                "resource_access": {
                    "test-client": {
                        "roles": [
                            "role2"
                        ]
                    }
                }
            }"#
            .as_bytes(),
            None,
        )
        .expect("failed to deserialize");
        assert_eq!(claims.additional_claims().realm_access, None);
        assert_eq!(
            claims
                .additional_claims()
                .resource_access
                .as_ref()
                .expect("missing resource access")
                .get("test-client")
                .expect("missing test-client entry")
                .roles,
            vec![Role::from("role2")]
        );
        assert!(claims
            .additional_claims()
            .resource_access()
            .has_role("test-client", "role2"));
    }

    #[test]
    fn test_both_claims() {
        let claims = CustomUserInfoClaims::<RoleClaims>::from_json::<HttpClientError>(
            r#"{
                "iss": "https://server.example.com",
                "sub": "subject",
                "aud": ["audience"],
                "realm_access": {
                    "roles": ["role1a", "role1b"]
                },
                "resource_access": {
                    "test-client1": {
                        "roles": ["role2a", "role2b"]
                    },
                    "test-client2": {
                        "roles": ["role2c", "role2d"]
                    }
                }
            }"#
            .as_bytes(),
            None,
        )
        .expect("failed to deserialize");
        assert!(claims.additional_claims().realm_access().has_role("role1a"));
        assert!(claims.additional_claims().realm_access().has_role("role1b"));
        assert!(!claims.additional_claims().realm_access().has_role("role1c"));
        assert!(claims
            .additional_claims()
            .resource_access()
            .has_role("test-client1", "role2a"));
        assert!(claims
            .additional_claims()
            .resource_access()
            .has_role("test-client1", "role2b"));
        assert!(claims
            .additional_claims()
            .resource_access()
            .has_role("test-client2", "role2c"));
        assert!(claims
            .additional_claims()
            .resource_access()
            .has_role("test-client2", "role2d"));
        assert!(!claims
            .additional_claims()
            .resource_access()
            .has_role("test-client2", "role1"));
        assert!(!claims
            .additional_claims()
            .resource_access()
            .has_role("test-client", "role2a"));
    }
}
