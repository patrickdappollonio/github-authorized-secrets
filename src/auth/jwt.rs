use crate::auth::github::{GitHubClaims, ValidationConfig};
use crate::error::AuthError;
use crate::security::InputValidator;
use chrono::Utc;
use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tracing::{info, warn, debug};

/// Cached JWK with expiration (without Debug because DecodingKey doesn't implement it)
#[derive(Clone)]
struct CachedJwk {
    key: DecodingKey,
    expires_at: i64,
}

/// JWT validation service for GitHub Actions tokens
pub struct JwtValidator {
    client: reqwest::Client,
    validation_config: ValidationConfig,
    /// Cache for JWKs to avoid repeated fetches
    jwk_cache: Arc<RwLock<HashMap<String, CachedJwk>>>,
    /// Cache duration in seconds
    cache_duration: i64,
    /// JWKs URL
    jwks_url: String,
    /// Input validator for security checks
    input_validator: InputValidator,
    /// Background cleanup task handle
    cleanup_task: Option<tokio::task::JoinHandle<()>>,
}

impl JwtValidator {
    /// Create a new JWT validator with default configuration
    pub async fn new() -> Result<Self, AuthError> {
        Self::new_with_url("https://token.actions.githubusercontent.com/.well-known/jwks").await
    }

    /// Create a new JWT validator with custom JWKs URL (for testing)
    pub async fn new_with_url(jwks_url: &str) -> Result<Self, AuthError> {
        let client = Self::create_optimized_client();
        let jwk_cache = Arc::new(RwLock::new(HashMap::new()));

        // Start background cache cleanup task
        let cleanup_task = Self::start_background_cleanup(Arc::clone(&jwk_cache));

        Ok(Self {
            client,
            validation_config: ValidationConfig::default(),
            jwk_cache,
            cache_duration: 300, // 5 minutes default
            jwks_url: jwks_url.to_string(),
            input_validator: InputValidator::new(false), // Default to development mode
            cleanup_task: Some(cleanup_task),
        })
    }

    /// Create a new JWT validator with custom configuration
    pub async fn new_with_config(
        validation_config: ValidationConfig,
        cache_duration: i64,
        production_mode: bool,
    ) -> Result<Self, AuthError> {
        let client = Self::create_optimized_client();
        let jwk_cache = Arc::new(RwLock::new(HashMap::new()));

        // Start background cache cleanup task
        let cleanup_task = Self::start_background_cleanup(Arc::clone(&jwk_cache));

        Ok(Self {
            client,
            validation_config,
            jwk_cache,
            cache_duration,
            jwks_url: "https://token.actions.githubusercontent.com/.well-known/jwks".to_string(),
            input_validator: InputValidator::new(production_mode),
            cleanup_task: Some(cleanup_task),
        })
    }

    /// Create an optimized HTTP client with connection pooling
    fn create_optimized_client() -> reqwest::Client {
        reqwest::Client::builder()
            .pool_max_idle_per_host(10) // Keep connections alive for reuse
            .pool_idle_timeout(Duration::from_secs(30))
            .timeout(Duration::from_secs(10))
            .connect_timeout(Duration::from_secs(5))
            .tcp_keepalive(Duration::from_secs(60))
            .user_agent("github-authorized-secrets/0.1.0")
            .build()
            .expect("failed to create HTTP client")
    }

    /// Start background task for automatic cache cleanup
    fn start_background_cleanup(
        cache: Arc<RwLock<HashMap<String, CachedJwk>>>,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60)); // Cleanup every minute

            loop {
                interval.tick().await;

                let now = Utc::now().timestamp();

                let mut cache_guard = cache.write().await;
                let initial_size = cache_guard.len();
                cache_guard.retain(|_, cached_jwk| cached_jwk.expires_at > now);
                let cleaned_count = initial_size - cache_guard.len();

                if cleaned_count > 0 {
                    debug!("Cleaned {} expired JWK entries from cache", cleaned_count);
                }
            }
        })
    }

    /// Set the JWKs URL (useful for testing)
    pub fn set_jwks_url(&mut self, url: String) {
        self.jwks_url = url;
    }

    /// Validate a GitHub Actions JWT token
    pub async fn validate_token(&self, token: &str) -> Result<GitHubClaims, AuthError> {
        // Pre-validation security checks
        self.pre_validate_token(token)?;

        // Decode header to get key ID
        let header = decode_header(token).map_err(|e| {
            warn!("Failed to decode JWT header: {}", e);
            AuthError::MalformedToken
        })?;

        let kid = header.kid.ok_or_else(|| {
            warn!("JWT token missing key ID in header");
            AuthError::MissingKeyId
        })?;

        // Security check: Validate key ID format
        if kid.is_empty() || kid.len() > 64 {
            warn!("Invalid key ID format: length={}", kid.len());
            return Err(AuthError::MalformedToken);
        }

        // Get JWK for this key ID
        let decoding_key = self.get_jwk(&kid).await?;

        // Set up validation parameters with enhanced security
        let mut validation = Validation::new(Algorithm::RS256);
        validation.validate_exp = true;
        validation.validate_nbf = true;
        validation.validate_aud = false; // Don't validate audience for flexibility
        validation.set_required_spec_claims(&["iss", "sub", "exp", "iat", "nbf"]);

        // Decode and validate the token
        let token_data = decode::<GitHubClaims>(token, &decoding_key, &validation)
            .map_err(|e| {
                warn!("JWT decode failed: {}", e);
                match e.kind() {
                    jsonwebtoken::errors::ErrorKind::ExpiredSignature => AuthError::TokenExpired,
                    jsonwebtoken::errors::ErrorKind::InvalidSignature => AuthError::InvalidSignature,
                    _ => AuthError::JwtDecodeError(e),
                }
            })?;

        // Perform GitHub-specific validations
        self.validate_github_claims(&token_data.claims)?;

        // Additional security validations
        self.perform_security_validations(&token_data.claims)?;

        info!("JWT validation successful for repository: {}", token_data.claims.repository);
        Ok(token_data.claims)
    }

    /// Pre-validation security checks on raw token
    fn pre_validate_token(&self, token: &str) -> Result<(), AuthError> {
        // Use input validator for basic format checks
        self.input_validator.validate_token(token)
            .map_err(|_| AuthError::MalformedToken)?;

        // Additional checks for suspicious patterns
        if token.contains('\n') || token.contains('\r') || token.contains('\0') {
            warn!("JWT token contains suspicious control characters");
            return Err(AuthError::MalformedToken);
        }

        // Check for potential header injection
        if token.to_lowercase().contains("javascript:") ||
           token.to_lowercase().contains("<script") {
            warn!("JWT token contains potentially malicious content");
            return Err(AuthError::MalformedToken);
        }

        Ok(())
    }

    /// Get JWK from cache or fetch from GitHub
    async fn get_jwk(&self, kid: &str) -> Result<DecodingKey, AuthError> {
        let now = Utc::now().timestamp();

        // Check cache first
        {
            let cache = self.jwk_cache.read().await;
            if let Some(cached_jwk) = cache.get(kid) {
                if cached_jwk.expires_at > now {
                    return Ok(cached_jwk.key.clone());
                }
            }
        }

        // Cache miss - fetch from GitHub

        // Fetch JWK set from GitHub
        let jwk_set = self.fetch_jwks().await?;

        // Find the specific key by kid
        let jwk = jwk_set
            .keys
            .iter()
            .find(|key| key.common.key_id.as_ref() == Some(&kid.to_string()))
            .ok_or_else(|| {
                warn!("Key ID {} not found in JWK set", kid);
                AuthError::KeyNotFound
            })?;

        // Convert to DecodingKey
        let decoding_key = DecodingKey::from_jwk(jwk)
            .map_err(|e| {
                warn!("Failed to create decoding key: {}", e);
                AuthError::JwtDecodeError(e)
            })?;

        // Cache the key
        {
            let mut cache = self.jwk_cache.write().await;
            cache.insert(
                kid.to_string(),
                CachedJwk {
                    key: decoding_key.clone(),
                    expires_at: now + self.cache_duration,
                },
            );
        }

        Ok(decoding_key)
    }

    /// Fetch JWK set from GitHub
    async fn fetch_jwks(&self) -> Result<JwkSet, AuthError> {
        let response = self
            .client
            .get(&self.jwks_url)
            .send()
            .await
            .map_err(|e| {
                warn!("Failed to fetch JWKs: {}", e);
                AuthError::JwksFetchFailed(e)
            })?;

        if !response.status().is_success() {
            warn!("JWKs fetch returned error status: {}", response.status());
            return Err(AuthError::JwksFetchFailed(reqwest::Error::from(
                response.error_for_status().unwrap_err(),
            )));
        }

        let jwk_set: JwkSet = response.json().await.map_err(|e| {
            warn!("Failed to parse JWKs JSON: {}", e);
            AuthError::JwksFetchFailed(e)
        })?;

        // Validate JWK set has keys
        if jwk_set.keys.is_empty() {
            warn!("JWK set is empty");
            return Err(AuthError::KeyNotFound);
        }

        Ok(jwk_set)
    }

    /// Validate GitHub-specific claims
    fn validate_github_claims(&self, claims: &GitHubClaims) -> Result<(), AuthError> {
        // Validate issuer
        if !self.validation_config.allowed_issuers.contains(&claims.iss) {
            warn!("Invalid issuer: {}", claims.iss);
            return Err(AuthError::InvalidIssuer);
        }

        // Validate token age
        let now = Utc::now().timestamp();
        if now - claims.iat > self.validation_config.max_token_age {
            warn!("Token too old: age={}s, max={}s", now - claims.iat, self.validation_config.max_token_age);
            return Err(AuthError::TokenTooOld);
        }

        // Validate required claims
        for claim in &self.validation_config.required_claims {
            match claim.as_str() {
                "repository" => {
                    if claims.repository.is_empty() {
                        return Err(AuthError::MissingClaim {
                            claim: "repository".to_string(),
                        });
                    }
                }
                "repository_owner" => {
                    if claims.repository_owner.is_empty() {
                        return Err(AuthError::MissingClaim {
                            claim: "repository_owner".to_string(),
                        });
                    }
                }
                "workflow" => {
                    if claims.workflow.is_empty() {
                        return Err(AuthError::MissingClaim {
                            claim: "workflow".to_string(),
                        });
                    }
                }
                _ => {
                    // For other claims, we don't have a specific validation
                    // This is a placeholder for extensibility
                }
            }
        }

        Ok(())
    }

    /// Perform additional security validations on claims
    fn perform_security_validations(&self, claims: &GitHubClaims) -> Result<(), AuthError> {
        // Validate repository format
        self.input_validator.validate_repository(&claims.repository)
            .map_err(|_| AuthError::MalformedToken)?;

        // Check for suspicious patterns in repository name
        if claims.repository.contains("../") || claims.repository.contains("..\\") {
            warn!("Repository name contains path traversal: {}", claims.repository);
            return Err(AuthError::MalformedToken);
        }

        // Validate repository owner format
        if claims.repository_owner.contains('/') ||
           claims.repository_owner.contains('\\') ||
           claims.repository_owner.len() > 39 { // GitHub username limit
            warn!("Invalid repository owner format: {}", claims.repository_owner);
            return Err(AuthError::MalformedToken);
        }

        // Check time bounds more strictly
        let now = Utc::now().timestamp();

        // Token shouldn't be issued in the future (allow 60s clock skew)
        if claims.iat > now + 60 {
            warn!("Token issued in the future: iat={}, now={}", claims.iat, now);
            return Err(AuthError::MalformedToken);
        }

        // Check for potential replay attacks (tokens shouldn't last too long)
        if claims.exp - claims.iat > 3600 { // Max 1 hour token lifetime
            warn!("Token lifetime too long: {}s", claims.exp - claims.iat);
            return Err(AuthError::TokenTooOld);
        }

        Ok(())
    }

    /// Clear expired entries from the JWK cache
    pub async fn cleanup_cache(&self) {
        let now = Utc::now().timestamp();
        let mut cache = self.jwk_cache.write().await;
        let initial_size = cache.len();
        cache.retain(|_, cached_jwk| cached_jwk.expires_at > now);
        let cleaned_count = initial_size - cache.len();
        if cleaned_count > 0 {
            info!("Cleaned {} expired JWK entries from cache", cleaned_count);
        }
    }

    /// Get the current validation configuration
    pub fn get_validation_config(&self) -> &ValidationConfig {
        &self.validation_config
    }

    /// Update validation configuration
    pub fn update_validation_config(&mut self, config: ValidationConfig) {
        self.validation_config = config;
        info!("JWT validation configuration updated");
    }
}

impl Drop for JwtValidator {
    fn drop(&mut self) {
        if let Some(task) = self.cleanup_task.take() {
            task.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mockito::Server;

    // Test helper functions - inline for now to avoid path issues
    mod test_helpers {
        use super::*;
        use chrono::{Duration, Utc};
        use jsonwebtoken::{encode, EncodingKey, Header};

        /// Create test GitHub claims with sensible defaults
        pub fn test_github_claims() -> GitHubClaims {
            let now = Utc::now();
            GitHubClaims {
                iss: "https://token.actions.githubusercontent.com".to_string(),
                sub: "repo:github/octocat:ref:refs/heads/main".to_string(),
                aud: "https://github.com/github".to_string(),
                repository: "github/octocat".to_string(),
                repository_owner: "github".to_string(),
                repository_id: "123456789".to_string(),
                ref_: "refs/heads/main".to_string(),
                sha: "example_sha".to_string(),
                workflow: "CI".to_string(),
                actor: "octocat".to_string(),
                run_id: "987654321".to_string(),
                exp: (now + Duration::seconds(3600)).timestamp(),
                iat: now.timestamp(),
                nbf: now.timestamp(),
            }
        }

        /// Create expired test GitHub claims
        pub fn expired_github_claims() -> GitHubClaims {
            let past = Utc::now() - Duration::seconds(3600);
            GitHubClaims {
                iss: "https://token.actions.githubusercontent.com".to_string(),
                sub: "repo:github/octocat:ref:refs/heads/main".to_string(),
                aud: "https://github.com/github".to_string(),
                repository: "github/octocat".to_string(),
                repository_owner: "github".to_string(),
                repository_id: "123456789".to_string(),
                ref_: "refs/heads/main".to_string(),
                sha: "example_sha".to_string(),
                workflow: "CI".to_string(),
                actor: "octocat".to_string(),
                run_id: "987654321".to_string(),
                exp: past.timestamp(),
                iat: past.timestamp(),
                nbf: past.timestamp(),
            }
        }

        /// Create test GitHub claims with invalid issuer
        pub fn invalid_issuer_claims() -> GitHubClaims {
            let mut claims = test_github_claims();
            claims.iss = "https://evil.com".to_string();
            claims
        }

        /// Create test GitHub claims with suspicious repository name
        pub fn suspicious_repository_claims() -> GitHubClaims {
            let mut claims = test_github_claims();
            claims.repository = "owner/../../../etc/passwd".to_string();
            claims
        }

        /// Create test GitHub claims with future issued at time
        pub fn future_iat_claims() -> GitHubClaims {
            let future = Utc::now() + Duration::seconds(300);
            let mut claims = test_github_claims();
            claims.iat = future.timestamp();
            claims.exp = (future + Duration::seconds(3600)).timestamp();
            claims
        }

        /// Create test GitHub claims with extremely long token lifetime
        pub fn long_lifetime_claims() -> GitHubClaims {
            let now = Utc::now();
            let mut claims = test_github_claims();
            claims.iat = now.timestamp();
            claims.exp = (now + Duration::seconds(7200)).timestamp(); // 2 hours
            claims
        }

        /// Create a test JWT token with default GitHub claims
        pub fn create_test_jwt_token() -> String {
            create_test_jwt_token_with_claims(test_github_claims())
        }

        /// Create a test JWT token with custom claims
        pub fn create_test_jwt_token_with_claims(claims: GitHubClaims) -> String {
            let mut header = Header::new(jsonwebtoken::Algorithm::RS256);
            header.kid = Some("test-key-1".to_string());

            // Use test private key
            let private_key = std::fs::read_to_string("test_data/test_private_key.pem")
                .expect("Failed to read test private key");
            let encoding_key = EncodingKey::from_rsa_pem(private_key.as_bytes()).unwrap();

            encode(&header, &claims, &encoding_key).unwrap()
        }

        /// Create a malformed JWT token (only 2 parts)
        pub fn create_malformed_jwt_token() -> String {
            "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwczovL3Rva2VuLmFjdGlvbnMuZ2l0aHViLmNvbSJ9".to_string()
        }

        /// Create a JWT token with invalid characters
        pub fn create_invalid_char_token() -> String {
            "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwczovL3Rva2VuLmFjdGlvbnMuZ2l0aHViLmNvbSJ9\n.signature".to_string()
        }

        /// Create a JWT token without kid in header
        pub fn create_token_without_kid() -> String {
            let claims = test_github_claims();
            let header = Header::new(jsonwebtoken::Algorithm::RS256);
            // Deliberately not setting kid

            let private_key = std::fs::read_to_string("test_data/test_private_key.pem")
                .expect("Failed to read test private key");
            let encoding_key = EncodingKey::from_rsa_pem(private_key.as_bytes()).unwrap();

            encode(&header, &claims, &encoding_key).unwrap()
        }
    }

    #[tokio::test]
    async fn test_jwt_validation_with_valid_token() {
        let mut server = Server::new_async().await;

        // Mock JWKs endpoint
        let jwks_content = std::fs::read_to_string("test_data/mock_jwks.json").unwrap();
        let jwks_mock = server
            .mock("GET", "/.well-known/jwks")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(&jwks_content)
            .create_async()
            .await;

        let validator = JwtValidator::new_with_url(&format!("{}/.well-known/jwks", server.url()))
            .await
            .unwrap();
        let test_token = test_helpers::create_test_jwt_token();

        let result = validator.validate_token(&test_token).await;
        match &result {
            Ok(claims) => {
                assert_eq!(claims.repository, "github/octocat");
                assert_eq!(claims.repository_owner, "github");
                assert_eq!(claims.iss, "https://token.actions.githubusercontent.com");
            }
            Err(e) => {
                eprintln!("JWT validation failed with error: {:?}", e);
                panic!("Expected successful validation but got error: {:?}", e);
            }
        }

        jwks_mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_jwt_validation_with_expired_token() {
        let mut server = Server::new_async().await;

        let jwks_content = std::fs::read_to_string("test_data/mock_jwks.json").unwrap();
        let _jwks_mock = server
            .mock("GET", "/.well-known/jwks")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(&jwks_content)
            .create_async()
            .await;

        let validator = JwtValidator::new_with_url(&format!("{}/.well-known/jwks", server.url()))
            .await
            .unwrap();
        let expired_token =
            test_helpers::create_test_jwt_token_with_claims(test_helpers::expired_github_claims());

        let result = validator.validate_token(&expired_token).await;
        assert!(result.is_err());

        match result.unwrap_err() {
            AuthError::TokenExpired => {} // Expected
            AuthError::JwtDecodeError(_) => {} // Also acceptable - expired tokens can be JWT decode errors
            other => panic!(
                "Expected TokenExpired or JwtDecodeError for expired token, got: {:?}",
                other
            ),
        }
    }

    #[tokio::test]
    async fn test_jwt_validation_with_invalid_issuer() {
        let mut server = Server::new_async().await;

        let jwks_content = std::fs::read_to_string("test_data/mock_jwks.json").unwrap();
        let _jwks_mock = server
            .mock("GET", "/.well-known/jwks")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(&jwks_content)
            .create_async()
            .await;

        let validator = JwtValidator::new_with_url(&format!("{}/.well-known/jwks", server.url()))
            .await
            .unwrap();
        let invalid_token =
            test_helpers::create_test_jwt_token_with_claims(test_helpers::invalid_issuer_claims());

        let result = validator.validate_token(&invalid_token).await;
        assert!(result.is_err());

        match result.unwrap_err() {
            AuthError::InvalidIssuer => {} // Expected
            _ => panic!("Expected InvalidIssuer error"),
        }
    }

    #[tokio::test]
    async fn test_jwt_validation_with_missing_key_id() {
        let validator = JwtValidator::new_with_url("http://localhost:3000")
            .await
            .unwrap();

        let token_without_kid = test_helpers::create_token_without_kid();

        let result = validator.validate_token(&token_without_kid).await;
        assert!(result.is_err());

        match result.unwrap_err() {
            AuthError::MissingKeyId => {} // Expected
            _ => panic!("Expected MissingKeyId error"),
        }
    }

    #[tokio::test]
    async fn test_jwt_validation_with_malformed_token() {
        let validator = JwtValidator::new_with_url("http://localhost:3000")
            .await
            .unwrap();

        let malformed_token = test_helpers::create_malformed_jwt_token();

        let result = validator.validate_token(&malformed_token).await;
        assert!(result.is_err());

        match result.unwrap_err() {
            AuthError::MalformedToken => {} // Expected
            _ => panic!("Expected MalformedToken error"),
        }
    }

    #[tokio::test]
    async fn test_jwt_validation_with_invalid_characters() {
        let validator = JwtValidator::new_with_url("http://localhost:3000")
            .await
            .unwrap();

        let invalid_char_token = test_helpers::create_invalid_char_token();

        let result = validator.validate_token(&invalid_char_token).await;
        assert!(result.is_err());

        match result.unwrap_err() {
            AuthError::MalformedToken => {} // Expected
            _ => panic!("Expected MalformedToken error for invalid characters"),
        }
    }

    #[tokio::test]
    async fn test_jwt_validation_with_suspicious_repository() {
        let mut server = Server::new_async().await;

        let jwks_content = std::fs::read_to_string("test_data/mock_jwks.json").unwrap();
        let _jwks_mock = server
            .mock("GET", "/.well-known/jwks")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(&jwks_content)
            .create_async()
            .await;

        let validator = JwtValidator::new_with_url(&format!("{}/.well-known/jwks", server.url()))
            .await
            .unwrap();
        let suspicious_token =
            test_helpers::create_test_jwt_token_with_claims(test_helpers::suspicious_repository_claims());

        let result = validator.validate_token(&suspicious_token).await;
        assert!(result.is_err());

        match result.unwrap_err() {
            AuthError::MalformedToken => {} // Expected for suspicious content
            _ => panic!("Expected MalformedToken error for suspicious repository"),
        }
    }

    #[tokio::test]
    async fn test_jwt_validation_with_future_iat() {
        let mut server = Server::new_async().await;

        let jwks_content = std::fs::read_to_string("test_data/mock_jwks.json").unwrap();
        let _jwks_mock = server
            .mock("GET", "/.well-known/jwks")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(&jwks_content)
            .create_async()
            .await;

        let validator = JwtValidator::new_with_url(&format!("{}/.well-known/jwks", server.url()))
            .await
            .unwrap();
        let future_token =
            test_helpers::create_test_jwt_token_with_claims(test_helpers::future_iat_claims());

        let result = validator.validate_token(&future_token).await;
        assert!(result.is_err());

        match result.unwrap_err() {
            AuthError::MalformedToken => {} // Expected for future-issued token
            _ => panic!("Expected MalformedToken error for future iat"),
        }
    }

    #[tokio::test]
    async fn test_jwt_validation_with_long_lifetime() {
        let mut server = Server::new_async().await;

        let jwks_content = std::fs::read_to_string("test_data/mock_jwks.json").unwrap();
        let _jwks_mock = server
            .mock("GET", "/.well-known/jwks")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(&jwks_content)
            .create_async()
            .await;

        let validator = JwtValidator::new_with_url(&format!("{}/.well-known/jwks", server.url()))
            .await
            .unwrap();
        let long_lifetime_token =
            test_helpers::create_test_jwt_token_with_claims(test_helpers::long_lifetime_claims());

        let result = validator.validate_token(&long_lifetime_token).await;
        assert!(result.is_err());

        match result.unwrap_err() {
            AuthError::TokenTooOld => {} // Expected for excessively long token lifetime
            _ => panic!("Expected TokenTooOld error for long lifetime token"),
        }
    }

    #[tokio::test]
    async fn test_jwk_caching() {
        let mut server = Server::new_async().await;

        let jwks_content = std::fs::read_to_string("test_data/mock_jwks.json").unwrap();
        let jwks_mock = server
            .mock("GET", "/.well-known/jwks")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(&jwks_content)
            .expect(1) // Should only be called once due to caching
            .create_async()
            .await;

        let validator = JwtValidator::new_with_url(&format!("{}/.well-known/jwks", server.url()))
            .await
            .unwrap();
        let test_token = test_helpers::create_test_jwt_token();

        // First validation should fetch JWK
        let result1 = validator.validate_token(&test_token).await;
        assert!(result1.is_ok());

        // Second validation should use cached JWK
        let result2 = validator.validate_token(&test_token).await;
        assert!(result2.is_ok());

        jwks_mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_jwk_cache_cleanup() {
        let validator = JwtValidator::new_with_url("http://localhost:3000")
            .await
            .unwrap();

        // Add a mock expired entry to cache
        {
            let mut cache = validator.jwk_cache.write().await;
            let expired_key = DecodingKey::from_secret(b"test");
            cache.insert("expired_key".to_string(), CachedJwk {
                key: expired_key,
                expires_at: Utc::now().timestamp() - 3600, // Expired 1 hour ago
            });
        }

        // Cleanup should remove expired entries
        validator.cleanup_cache().await;

        // Check that cache is empty
        {
            let cache = validator.jwk_cache.read().await;
            assert!(cache.is_empty());
        }
    }

    #[tokio::test]
    async fn test_custom_validation_config() {
        let mut server = Server::new_async().await;

        let jwks_content = std::fs::read_to_string("test_data/mock_jwks.json").unwrap();
        let _jwks_mock = server
            .mock("GET", "/.well-known/jwks")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(&jwks_content)
            .create_async()
            .await;

        // Create validator with custom config requiring workflow claim
        let custom_config = ValidationConfig {
            required_claims: vec!["repository".to_string(), "workflow".to_string()],
            allowed_issuers: vec!["https://token.actions.githubusercontent.com".to_string()],
            max_token_age: 300,
        };

        let mut validator = JwtValidator::new_with_config(custom_config, 300, false)
            .await
            .unwrap();
        validator.set_jwks_url(format!("{}/.well-known/jwks", server.url()));

        let test_token = test_helpers::create_test_jwt_token();
        let result = validator.validate_token(&test_token).await;

        // Should succeed because our test token includes workflow claim
        match result {
            Ok(_) => {} // Expected success
            Err(e) => {
                eprintln!("Custom validation config test failed with error: {:?}", e);
                panic!(
                    "Expected successful validation with custom config, got error: {:?}",
                    e
                );
            }
        }
    }

    #[tokio::test]
    async fn test_empty_jwk_set_handling() {
        let mut server = Server::new_async().await;

        // Mock empty JWK set
        let empty_jwk_set = r#"{"keys": []}"#;
        let _jwks_mock = server
            .mock("GET", "/.well-known/jwks")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(empty_jwk_set)
            .create_async()
            .await;

        let validator = JwtValidator::new_with_url(&format!("{}/.well-known/jwks", server.url()))
            .await
            .unwrap();
        let test_token = test_helpers::create_test_jwt_token();

        let result = validator.validate_token(&test_token).await;
        assert!(result.is_err());

        match result.unwrap_err() {
            AuthError::KeyNotFound => {} // Expected for empty JWK set
            _ => panic!("Expected KeyNotFound error for empty JWK set"),
        }
    }

    #[tokio::test]
    async fn test_production_mode_validation() {
        let mut server = Server::new_async().await;

        let jwks_content = std::fs::read_to_string("test_data/mock_jwks.json").unwrap();
        let _jwks_mock = server
            .mock("GET", "/.well-known/jwks")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(&jwks_content)
            .create_async()
            .await;

        // Test with production mode enabled
        let mut validator = JwtValidator::new_with_config(
            ValidationConfig::default(),
            300,
            true, // Production mode
        ).await.unwrap();
        validator.set_jwks_url(format!("{}/.well-known/jwks", server.url()));

        let test_token = test_helpers::create_test_jwt_token();
        let result = validator.validate_token(&test_token).await;

        // Should still succeed with valid token in production mode
        assert!(result.is_ok());
    }
}
