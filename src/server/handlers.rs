use crate::auth::github::GitHubClaims;
use crate::security::InputValidator;
use crate::server::app::AppState;
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::Json,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{info, warn};

#[derive(Serialize)]
pub struct HealthResponse {
    status: &'static str,
    service: &'static str,
    version: &'static str,
}

#[derive(Serialize, Debug)]
pub struct SecretsResponse {
    repository: String,
    secrets: HashMap<String, String>,
    metadata: SecretsMetadata,
}

#[derive(Serialize, Debug)]
pub struct SecretsMetadata {
    retrieved_at: String,
    repository_owner: String,
}

#[derive(Serialize, Debug)]
pub struct RepositoriesResponse {
    repositories: Vec<String>,
}

#[derive(Deserialize)]
pub struct SignTokenRequest {
    repository: String,
    repository_owner: String,
}

#[derive(Serialize)]
pub struct SignTokenResponse {
    token: String,
    key_id: String,
    expires_at: i64,
}

/// Health check endpoint
pub async fn health_check() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "healthy",
        service: "github-authorized-secrets",
        version: env!("CARGO_PKG_VERSION"),
    })
}

/// Extract and validate JWT claims from request headers
async fn extract_and_validate_claims(
    headers: &HeaderMap,
    state: &AppState,
    validator: &InputValidator,
) -> Result<GitHubClaims, StatusCode> {
    // Extract Authorization header
    let auth_header = headers
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .ok_or(StatusCode::UNAUTHORIZED)?;

    // Extract token from "Bearer <token>" format
    let token = auth_header
        .strip_prefix("Bearer ")
        .ok_or(StatusCode::UNAUTHORIZED)?;

    // Validate token format
    validator.validate_token(token).map_err(|e| {
        warn!("Token validation failed: {}", e);
        StatusCode::UNAUTHORIZED
    })?;

    // Validate JWT with GitHub's JWKs
    let claims = state
        .jwt_validator
        .validate_token(token)
        .await
        .map_err(|e| {
            warn!("JWT validation failed: {}", e);
            StatusCode::UNAUTHORIZED
        })?;

    // Validate repository format
    validator
        .validate_repository(&claims.repository)
        .map_err(|e| {
            warn!("Repository validation failed: {}", e);
            StatusCode::BAD_REQUEST
        })?;

    Ok(claims)
}

/// Sign a JWT token for local testing (only available in local testing mode)
pub async fn sign_token(
    State(state): State<AppState>,
    Json(request): Json<SignTokenRequest>,
) -> Result<Json<SignTokenResponse>, crate::error::AppError> {
    // Only allow token signing in local testing mode
    if !state.config.server.is_local_testing_mode() {
        warn!("Token signing endpoint accessed but local testing mode is not enabled");
        return Err(crate::error::AppError::Server(
            crate::error::ServerError::HandlerError(
                "token signing is only available in local testing mode".to_string(),
            ),
        ));
    }

    let local_jwks = state.local_jwks.as_ref().ok_or_else(|| {
        crate::error::AppError::Server(crate::error::ServerError::HandlerError(
            "local JWKs not available".to_string(),
        ))
    })?;

    let signer = local_jwks.get_signer().ok_or_else(|| {
        crate::error::AppError::Server(crate::error::ServerError::HandlerError(
            "no signing key available".to_string(),
        ))
    })?;

    // Create test claims with hardcoded defaults for workflow, actor, etc.
    let claims =
        crate::auth::signing::create_test_claims(&request.repository, &request.repository_owner);

    // Sign the token
    let token = signer
        .sign_token(&claims)
        .map_err(crate::error::AppError::Auth)?;

    info!("Signed JWT token for repository: {}", request.repository);

    Ok(Json(SignTokenResponse {
        token,
        key_id: signer.key_id().to_string(),
        expires_at: claims.exp,
    }))
}

/// Get secrets for authenticated repository
pub async fn get_secrets(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<SecretsResponse>, StatusCode> {
    let validator = InputValidator::new(state.config.is_production_mode());

    // Extract and validate JWT token
    let claims = extract_and_validate_claims(&headers, &state, &validator).await?;

    // Get secrets for the repository
    let secrets = state
        .secret_store
        .get_secrets(&claims.repository)
        .ok_or(StatusCode::NOT_FOUND)?;

    // Log successful secret retrieval
    info!(
        "Retrieved {} secrets for repository: {}",
        secrets.len(),
        claims.repository
    );

    let response = SecretsResponse {
        repository: claims.repository.clone(),
        secrets,
        metadata: SecretsMetadata {
            retrieved_at: chrono::Utc::now().to_rfc3339(),
            repository_owner: claims.repository_owner,
        },
    };

    Ok(Json(response))
}

/// List available repositories
pub async fn list_repositories(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<RepositoriesResponse>, StatusCode> {
    let validator = InputValidator::new(state.config.is_production_mode());

    // Extract and validate JWT token (user must be authenticated)
    let _claims = extract_and_validate_claims(&headers, &state, &validator).await?;

    // Get all available repositories
    let repositories: Vec<String> = state
        .secret_store
        .list_repositories()
        .into_iter()
        .map(|repo| repo.replace('.', "/")) // Convert internal format back to "owner/repo"
        .collect();

    info!("Listed {} available repositories", repositories.len());

    let response = RepositoriesResponse { repositories };

    Ok(Json(response))
}

/// Serve JWKs for local testing
pub async fn serve_jwks(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, crate::error::AppError> {
    match &state.local_jwks {
        Some(local_jwks) => {
            info!("Serving local JWKS for testing");
            let jwks_json = local_jwks.to_json().map_err(crate::error::AppError::Auth)?;
            let jwks_value: serde_json::Value = serde_json::from_str(&jwks_json).map_err(|e| {
                crate::error::AppError::Auth(crate::error::AuthError::JwksClientError(format!(
                    "failed to parse JWKs JSON: {e}"
                )))
            })?;
            Ok(Json(jwks_value))
        }
        None => {
            warn!("JWKS endpoint accessed but local testing mode is not enabled");
            Err(crate::error::AppError::Server(
                crate::error::ServerError::HandlerError(
                    "local testing mode not enabled".to_string(),
                ),
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use axum::http::{HeaderMap, HeaderName, HeaderValue};
    use std::str::FromStr;

    /// Create a test configuration for testing
    async fn create_test_config() -> Config {
        use std::collections::HashMap;

        let mut repositories = HashMap::new();
        let mut test_secrets = HashMap::new();
        test_secrets.insert("api_key".to_string(), "test_key".to_string());
        repositories.insert("github.octocat".to_string(), test_secrets);

        Config {
            server: crate::config::types::ServerConfig {
                host: "127.0.0.1".to_string(),
                port: 8080,
                jwt_cache_duration: 300,
                local_testing_mode: Some(true),
                local_testing_num_keys: Some(1),
            },
            validation: Some(crate::config::types::ValidationConfig {
                required_claims: Some(vec![
                    "repository".to_string(),
                    "repository_owner".to_string(),
                ]),
                allowed_issuers: Some(vec![
                    "https://token.actions.githubusercontent.com".to_string()
                ]),
                max_token_age: Some(300),
                max_token_lifetime: Some(28800),
            }),
            repositories,
        }
    }

    /// Create test app state
    async fn create_test_app_state() -> AppState {
        let config = create_test_config().await;
        AppState::new(config)
            .await
            .expect("Failed to create app state")
    }

    #[tokio::test]
    async fn test_health_check() {
        let Json(response) = health_check().await;
        assert_eq!(response.status, "healthy");
        assert_eq!(response.service, "github-authorized-secrets");
        assert!(!response.version.is_empty());
    }

    #[tokio::test]
    async fn test_extract_bearer_token_valid() {
        // This test just checks that we can parse a well-formed authorization header
        let validator = InputValidator::default();
        let mut headers = HeaderMap::new();
        headers.insert(
            "authorization",
            "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwczovL3Rva2VuLmFjdGlvbnMuZ2l0aHViLmNvbSIsImF1ZCI6Imh0dHBzOi8vZ2l0aHViLmNvbS9vd25lciIsInJlcG9zaXRvcnkiOiJvd25lci9yZXBvIiwicmVwb3NpdG9yeV9vd25lciI6Im93bmVyIn0.signature"
                .parse()
                .unwrap(),
        );

        // Since we can't easily mock JWT validation, let's just test that the function
        // tries to validate and fails gracefully
        let result =
            extract_and_validate_claims(&headers, &create_test_app_state().await, &validator).await;
        // In local testing mode with a mock JWT, this will likely fail, which is expected
        assert!(
            result.is_err(),
            "Expected JWT validation to fail with mock token"
        );
    }

    #[tokio::test]
    async fn test_extract_bearer_token_missing_header() {
        let validator = InputValidator::default();
        let headers = HeaderMap::new();

        let result =
            extract_and_validate_claims(&headers, &create_test_app_state().await, &validator).await;
        assert!(result.is_err());

        match result.unwrap_err() {
            StatusCode::UNAUTHORIZED => {
                // Expected error type
            }
            _ => panic!("Expected UNAUTHORIZED error"),
        }
    }

    #[tokio::test]
    async fn test_extract_bearer_token_invalid_format() {
        let validator = InputValidator::default();
        let mut headers = HeaderMap::new();
        headers.insert("authorization", "InvalidFormat token_here".parse().unwrap());

        let result =
            extract_and_validate_claims(&headers, &create_test_app_state().await, &validator).await;
        assert!(result.is_err());

        match result.unwrap_err() {
            StatusCode::UNAUTHORIZED => {
                // Expected error type
            }
            _ => panic!("Expected UNAUTHORIZED error"),
        }
    }

    #[tokio::test]
    async fn test_extract_bearer_token_invalid_token_structure() {
        let validator = InputValidator::default();
        let mut headers = HeaderMap::new();
        headers.insert(
            "authorization",
            "Bearer invalid.token.structure@here".parse().unwrap(),
        );

        let result =
            extract_and_validate_claims(&headers, &create_test_app_state().await, &validator).await;
        assert!(result.is_err());

        // The token format validation should catch this, but it might be caught at JWT validation level
        match result.unwrap_err() {
            StatusCode::UNAUTHORIZED | StatusCode::BAD_REQUEST => {
                // Either error is acceptable for invalid token
            }
            _ => panic!("Expected UNAUTHORIZED or BAD_REQUEST error for invalid token structure"),
        }
    }

    #[tokio::test]
    async fn test_get_secrets_missing_auth_header() {
        let app_state = create_test_app_state().await;
        let headers = HeaderMap::new();

        let result = get_secrets(State(app_state), headers).await;
        assert!(result.is_err());

        match result.unwrap_err() {
            StatusCode::UNAUTHORIZED => {
                // Expected error type
            }
            _ => panic!("Expected UNAUTHORIZED error"),
        }
    }

    #[tokio::test]
    async fn test_list_repositories_missing_auth_header() {
        let app_state = create_test_app_state().await;
        let headers = HeaderMap::new();

        let result = list_repositories(State(app_state), headers).await;
        assert!(result.is_err());

        match result.unwrap_err() {
            StatusCode::UNAUTHORIZED => {
                // Expected error type
            }
            _ => panic!("Expected UNAUTHORIZED error"),
        }
    }

    #[tokio::test]
    async fn test_handler_with_malformed_token() {
        let app_state = create_test_app_state().await;
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_str("authorization").unwrap(),
            HeaderValue::from_str("Bearer malformed").unwrap(),
        );

        let secrets_result = get_secrets(State(app_state), headers).await;
        assert!(secrets_result.is_err());
    }

    #[tokio::test]
    async fn test_input_sanitization() {
        let validator = InputValidator::default();

        let dirty_input = "test\nwith\tcontrol\rchars\x00and binary";
        let sanitized = validator.sanitize_log_input(dirty_input);

        assert!(!sanitized.contains('\n'));
        assert!(!sanitized.contains('\t'));
        assert!(!sanitized.contains('\r'));
        assert!(!sanitized.contains('\x00'));
        assert!(sanitized.contains("testwithcontrolcharsand binary"));
    }
}
