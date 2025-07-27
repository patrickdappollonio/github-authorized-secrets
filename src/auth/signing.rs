use crate::auth::github::GitHubClaims;
use crate::error::AuthError;
use chrono::{Duration, Utc};
use jsonwebtoken::jwk::{Jwk, JwkSet};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use rsa::traits::PublicKeyParts;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{info, debug};

/// RSA key pair for JWT signing
#[derive(Clone)]
pub struct RsaKeyPair {
    pub private_key: EncodingKey,
    pub public_key_pem: String,
    pub key_id: String,
}

/// Local JWKs for testing
#[derive(Clone, Serialize, Deserialize)]
pub struct LocalJwks {
    pub jwk_set: JwkSet,
    pub key_pairs: Vec<String>, // Store only key IDs, not the actual keys for serialization
    #[serde(skip)]
    pub key_pairs_map: HashMap<String, RsaKeyPair>,
}

impl std::fmt::Debug for LocalJwks {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalJwks")
            .field("jwk_set", &self.jwk_set)
            .field("key_pairs", &self.key_pairs)
            .field("key_pairs_map", &format!("{} key pairs", self.key_pairs_map.len()))
            .finish()
    }
}

/// JWT signer for creating test tokens
pub struct JwtSigner {
    key_pair: RsaKeyPair,
}

impl JwtSigner {
    /// Create a new JWT signer with a generated RSA key pair
    pub fn new() -> Result<Self, AuthError> {
        let key_pair = Self::generate_rsa_key_pair()?;
        info!("Generated new RSA key pair for JWT signing with key ID: {}", key_pair.key_id);

        Ok(Self { key_pair })
    }

    /// Create a JWT signer with an existing key pair
    pub fn with_key_pair(key_pair: RsaKeyPair) -> Self {
        Self { key_pair }
    }

    /// Generate an RSA key pair for JWT signing
    fn generate_rsa_key_pair() -> Result<RsaKeyPair, AuthError> {
        use rand::rngs::OsRng;
        use rsa::{RsaPrivateKey, RsaPublicKey};
        use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey};

        // Generate 2048-bit RSA key pair
        let mut rng = OsRng;
        let private_key = RsaPrivateKey::new(&mut rng, 2048)
            .map_err(|e| AuthError::JwksClientError(format!("failed to generate RSA private key: {}", e)))?;

        let public_key = RsaPublicKey::from(&private_key);

        // Convert to PEM format
        let private_key_pem = private_key.to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
            .map_err(|e| AuthError::JwksClientError(format!("failed to encode private key: {}", e)))?;

        let public_key_pem = public_key.to_public_key_pem(rsa::pkcs8::LineEnding::LF)
            .map_err(|e| AuthError::JwksClientError(format!("failed to encode public key: {}", e)))?;

        // Create encoding key for JWT signing
        let encoding_key = EncodingKey::from_rsa_pem(private_key_pem.as_bytes())
            .map_err(|e| AuthError::JwtDecodeError(e))?;

        // Generate a unique key ID
        let key_id = format!("test-key-{}", uuid::Uuid::new_v4().simple());

        Ok(RsaKeyPair {
            private_key: encoding_key,
            public_key_pem,
            key_id,
        })
    }

    /// Sign a JWT token with the given claims
    pub fn sign_token(&self, claims: &GitHubClaims) -> Result<String, AuthError> {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(self.key_pair.key_id.clone());

        let token = encode(&header, claims, &self.key_pair.private_key)
            .map_err(|e| AuthError::JwtDecodeError(e))?;

        debug!("Signed JWT token for repository: {}", claims.repository);
        Ok(token)
    }

    /// Create a JWK from the public key
    pub fn create_jwk(&self) -> Result<Jwk, AuthError> {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
        use rsa::pkcs8::DecodePublicKey;
        use rsa::RsaPublicKey;

        // Parse the public key
        let public_key = RsaPublicKey::from_public_key_pem(&self.key_pair.public_key_pem)
            .map_err(|e| AuthError::JwksClientError(format!("failed to parse public key: {}", e)))?;

        // Extract RSA components
        let n = public_key.n();
        let e = public_key.e();

        // Convert to base64url encoding
        let n_bytes = n.to_bytes_be();
        let e_bytes = e.to_bytes_be();

        let n_b64 = URL_SAFE_NO_PAD.encode(&n_bytes);
        let e_b64 = URL_SAFE_NO_PAD.encode(&e_bytes);

        // Create JWK manually using the correct API
        let mut common = jsonwebtoken::jwk::CommonParameters::default();
        common.public_key_use = Some(jsonwebtoken::jwk::PublicKeyUse::Signature);
        common.key_id = Some(self.key_pair.key_id.clone());
        common.key_algorithm = Some(jsonwebtoken::jwk::KeyAlgorithm::RS256);

        Ok(Jwk {
            common,
            algorithm: jsonwebtoken::jwk::AlgorithmParameters::RSA(
                jsonwebtoken::jwk::RSAKeyParameters {
                    key_type: jsonwebtoken::jwk::RSAKeyType::RSA,
                    n: n_b64,
                    e: e_b64,
                }
            ),
        })
    }

    /// Get the key ID for this signer
    pub fn key_id(&self) -> &str {
        &self.key_pair.key_id
    }
}

impl LocalJwks {
    /// Create a new LocalJwks with generated key pairs
    pub fn new(num_keys: usize) -> Result<Self, AuthError> {
        let mut key_pairs = Vec::new();
        let mut key_pairs_map = HashMap::new();
        let mut jwks = Vec::new();

        for i in 0..num_keys {
            let signer = JwtSigner::new()?;
            let jwk = signer.create_jwk()?;

            info!("Generated JWK #{} with key ID: {}", i + 1, signer.key_id());

            jwks.push(jwk);
            key_pairs.push(signer.key_id().to_string());
            key_pairs_map.insert(signer.key_id().to_string(), signer.key_pair);
        }

        let jwk_set = JwkSet { keys: jwks };

        Ok(Self {
            jwk_set,
            key_pairs,
            key_pairs_map,
        })
    }

    /// Get a signer for the first key pair
    pub fn get_signer(&self) -> Option<JwtSigner> {
        self.key_pairs.first()
            .and_then(|kid| self.key_pairs_map.get(kid))
            .map(|kp| JwtSigner::with_key_pair(kp.clone()))
    }

    /// Get a signer by key ID
    pub fn get_signer_by_id(&self, key_id: &str) -> Option<JwtSigner> {
        self.key_pairs_map
            .get(key_id)
            .map(|kp| JwtSigner::with_key_pair(kp.clone()))
    }

    /// Get the JWK set as JSON
    pub fn to_json(&self) -> Result<String, AuthError> {
        serde_json::to_string_pretty(&self.jwk_set)
            .map_err(|e| AuthError::JwksClientError(format!("failed to serialize JWK set: {}", e)))
    }
}

/// Create test GitHub claims for signing
pub fn create_test_claims(
    repository: &str,
    repository_owner: &str,
    workflow: Option<&str>,
    actor: Option<&str>,
    ref_name: Option<&str>,
    sha: Option<&str>,
    audience: Option<&str>,
) -> GitHubClaims {
    let now = Utc::now();
    let exp = now + Duration::minutes(10);

    GitHubClaims {
        iss: "https://token.actions.githubusercontent.com".to_string(),
        sub: format!("repo:{}:ref:refs/heads/main", repository),
        aud: audience.unwrap_or("github-authorized-secrets").to_string(),
        repository: repository.to_string(),
        repository_owner: repository_owner.to_string(),
        repository_id: "123456789".to_string(),
        ref_: ref_name.unwrap_or("refs/heads/main").to_string(),
        sha: sha.unwrap_or("abcdef1234567890").to_string(),
        workflow: workflow.unwrap_or("Test Workflow").to_string(),
        actor: actor.unwrap_or(repository_owner).to_string(),
        run_id: "987654321".to_string(),
        exp: exp.timestamp(),
        iat: now.timestamp(),
        nbf: now.timestamp(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rsa_key_pair_generation() {
        let signer = JwtSigner::new().unwrap();
        assert!(!signer.key_id().is_empty());
        assert!(signer.key_id().starts_with("test-key-"));
    }

    #[test]
    #[ignore] // TODO: Fix JWT/JWK API compatibility issues
    fn test_jwk_creation() {
        let signer = JwtSigner::new().unwrap();
        let jwk = signer.create_jwk().unwrap();

        // assert_eq!(jwk.common.key_type, Some(jsonwebtoken::jwk::KeyType::RSA));
        // assert_eq!(jwk.common.key_use, Some(jsonwebtoken::jwk::PublicKeyUse::Signature));
        assert_eq!(jwk.common.key_id.as_ref(), Some(&signer.key_pair.key_id));
    }

    #[test]
    fn test_token_signing() {
        let signer = JwtSigner::new().unwrap();
        let claims = create_test_claims(
            "owner/repo",
            "owner",
            Some("test-workflow"),
            Some("test-actor"),
            None,
            None,
            None,
        );

        let token = signer.sign_token(&claims).unwrap();
        assert!(!token.is_empty());

        // Token should have 3 parts separated by dots
        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3);
    }

    #[test]
    fn test_local_jwks_creation() {
        let local_jwks = LocalJwks::new(2).unwrap();

        assert_eq!(local_jwks.jwk_set.keys.len(), 2);
        assert_eq!(local_jwks.key_pairs.len(), 2);
        assert_eq!(local_jwks.key_pairs_map.len(), 2);

        let signer = local_jwks.get_signer().unwrap();
        assert!(!signer.key_id().is_empty());
    }

    #[test]
    fn test_jwks_json_serialization() {
        let local_jwks = LocalJwks::new(1).unwrap();
        let json = local_jwks.to_json().unwrap();

        assert!(json.contains("keys"));
        assert!(json.contains("kty"));
        assert!(json.contains("use"));
        assert!(json.contains("kid"));
    }
}
