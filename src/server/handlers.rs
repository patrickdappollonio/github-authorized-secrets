use crate::error::AppError;
use crate::secrets::{RepositoryListResponse, SecretsMetadata, SecretsResponse};
use crate::server::AppState;
use crate::security::{InputValidator, SecurityAuditor};
use axum::{extract::State, http::HeaderMap, Json};
use chrono::Utc;
use tracing::{info, warn};

/// Health check endpoint with performance monitoring
pub async fn health_check() -> Result<Json<serde_json::Value>, AppError> {
    Ok(Json(serde_json::json!({
        "status": "healthy",
        "service": "github-authorized-secrets",
        "version": env!("CARGO_PKG_VERSION"),
        "timestamp": Utc::now()
    })))
}

/// Extract JWT bearer token from Authorization header with validation
fn extract_bearer_token(headers: &HeaderMap, validator: &InputValidator) -> Result<String, AppError> {
    let auth_header = headers
        .get("authorization")
        .ok_or_else(|| AppError::Auth(crate::error::AuthError::InvalidToken))?
        .to_str()
        .map_err(|_| AppError::Auth(crate::error::AuthError::MalformedToken))?;

    if !auth_header.starts_with("Bearer ") {
        return Err(AppError::Auth(crate::error::AuthError::MalformedToken));
    }

    let token = auth_header[7..].to_string(); // Remove "Bearer " prefix

    // Validate token format
    validator.validate_token(&token)
        .map_err(|e| AppError::Security(e))?;

    Ok(token)
}

/// Extract client information from headers for audit logging
fn extract_client_info(headers: &HeaderMap) -> (Option<String>, Option<String>) {
    let user_agent = headers
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let ip_address = headers
        .get("x-forwarded-for")
        .or_else(|| headers.get("x-real-ip"))
        .and_then(|v| v.to_str().ok())
        .map(|s| s.split(',').next().unwrap_or(s).trim().to_string());

    (ip_address, user_agent)
}

/// Get secrets for authenticated repository with comprehensive performance monitoring
pub async fn get_secrets(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<SecretsResponse>, AppError> {
    let validator = InputValidator::new(state.config.is_production_mode());
    let auditor = SecurityAuditor::new(
        state.config.get_security_config().detailed_audit_logging,
        Some(state.config.get_security_config().into()),
    );

    // Extract client information for audit logging
    let (ip_address, user_agent) = extract_client_info(&headers);

    // Extract and validate JWT token
    let token = extract_bearer_token(&headers, &validator)?;

    // Enforce security policies
    let scheme = if state.config.server.should_enable_tls() { "https" } else { "http" };
    auditor.enforce_security_policies(scheme, user_agent.as_deref(), &token)
        .map_err(|e| AppError::Security(e))?;

    // Validate JWT token and extract claims
    let claims = match state.jwt_validator.validate_token(&token).await {
        Ok(claims) => {
            // Audit successful authentication
            auditor.audit_authentication(
                &claims.repository,
                true,
                None,
                ip_address.clone(),
                user_agent.clone(),
            );
            claims
        }
        Err(e) => {
            // Audit failed authentication
            auditor.audit_authentication(
                "unknown",
                false,
                Some(&e.to_string()),
                ip_address,
                user_agent,
            );
            return Err(AppError::Auth(e));
        }
    };

    // Validate repository format
    validator.validate_repository(&claims.repository)
        .map_err(|e| AppError::Security(e))?;

    // Detect suspicious activity
    let suspicious_events = auditor.detect_suspicious_activity(
        &claims.repository,
        ip_address.clone(),
        user_agent,
        std::collections::HashMap::new(),
    );

    if !suspicious_events.is_empty() {
        warn!("Suspicious activity detected for repository: {}", claims.repository);
        // Continue processing but log the suspicious activity
    }

    // Get secrets for the repository from the claims
    let secrets = state
        .secret_store
        .get_secrets(&claims.repository)
        .ok_or_else(|| AppError::Client(crate::error::ClientError::RepositoryNotFound))?;

    // Audit secret access
    auditor.audit_secret_access(&claims.repository, secrets.len(), ip_address);

    // Log successful secret retrieval
    info!(
        "Secret retrieval successful for repository: {} ({} secrets)",
        validator.sanitize_log_input(&claims.repository),
        secrets.len()
    );

    // Create response with metadata
    let response = SecretsResponse {
        repository: claims.repository.clone(),
        secrets,
        metadata: SecretsMetadata {
            retrieved_at: Utc::now(),
            repository_owner: claims.repository_owner,
        },
    };

    Ok(Json(response))
}

/// List available repositories with performance monitoring
pub async fn list_repositories(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<RepositoryListResponse>, AppError> {
    let validator = InputValidator::new(state.config.is_production_mode());
    let auditor = SecurityAuditor::new(
        state.config.get_security_config().detailed_audit_logging,
        Some(state.config.get_security_config().into()),
    );

    // Extract client information for audit logging
    let (ip_address, user_agent) = extract_client_info(&headers);

    // Extract and validate JWT token
    let token = extract_bearer_token(&headers, &validator)?;

    // Enforce security policies
    let scheme = if state.config.server.should_enable_tls() { "https" } else { "http" };
    auditor.enforce_security_policies(scheme, user_agent.as_deref(), &token)
        .map_err(|e| AppError::Security(e))?;

    // Validate JWT token to ensure user is authenticated
    let claims = match state.jwt_validator.validate_token(&token).await {
        Ok(claims) => {
            // Audit successful authentication
            auditor.audit_authentication(
                &claims.repository,
                true,
                None,
                ip_address.clone(),
                user_agent.clone(),
            );
            claims
        }
        Err(e) => {
            // Audit failed authentication
            auditor.audit_authentication(
                "unknown",
                false,
                Some(&e.to_string()),
                ip_address,
                user_agent,
            );
            return Err(AppError::Auth(e));
        }
    };

    // Detect suspicious activity
    let suspicious_events = auditor.detect_suspicious_activity(
        &claims.repository,
        ip_address.clone(),
        user_agent,
        std::collections::HashMap::new(),
    );

    if !suspicious_events.is_empty() {
        warn!("Suspicious activity detected during repository listing from: {}", claims.repository);
    }

    // Get list of all available repositories from the secret store
    let repositories = state.secret_store.list_repositories();

    // Log repository access
    info!(
        "Repository list accessed by: {} (found {} repositories)",
        validator.sanitize_log_input(&claims.repository),
        repositories.len()
    );

    let response = RepositoryListResponse { repositories };

    Ok(Json(response))
}

/// Security audit endpoint (requires authentication) with performance monitoring
pub async fn security_audit(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, AppError> {
    let validator = InputValidator::new(state.config.is_production_mode());
    let auditor = SecurityAuditor::new(
        state.config.get_security_config().detailed_audit_logging,
        Some(state.config.get_security_config().into()),
    );

    // Extract client information
    let (_ip_address, _user_agent) = extract_client_info(&headers);

    // Extract and validate JWT token
    let token = extract_bearer_token(&headers, &validator)?;

    // Validate JWT token to ensure user is authenticated
    let claims = state.jwt_validator.validate_token(&token).await?;

    // Perform security audit
    let audit_report = auditor.perform_security_audit()
        .map_err(|e| AppError::Security(e))?;

    // Log security audit access
    info!(
        "Security audit performed by: {} (found {} findings)",
        validator.sanitize_log_input(&claims.repository),
        audit_report.findings.len()
    );

    // Return audit results (without sensitive details)
    Ok(Json(serde_json::json!({
        "timestamp": audit_report.timestamp,
        "findings_count": audit_report.findings.len(),
        "has_critical_findings": audit_report.has_critical_findings(),
        "summary": {
            "low": audit_report.get_findings_by_severity(crate::security::audit::SecuritySeverity::Low).len(),
            "medium": audit_report.get_findings_by_severity(crate::security::audit::SecuritySeverity::Medium).len(),
            "high": audit_report.get_findings_by_severity(crate::security::audit::SecuritySeverity::High).len(),
            "critical": audit_report.get_findings_by_severity(crate::security::audit::SecuritySeverity::Critical).len(),
        }
    })))
}

/// Serve JWKs for local testing mode
pub async fn serve_jwks(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, AppError> {
    match &state.local_jwks {
        Some(local_jwks) => {
            info!("Serving local JWKS for testing");
            let jwks_json = local_jwks.to_json().map_err(|e| AppError::Auth(e))?;
            let jwks_value: serde_json::Value = serde_json::from_str(&jwks_json)
                .map_err(|e| AppError::Auth(crate::error::AuthError::JwksClientError(
                    format!("failed to parse JWKs JSON: {}", e)
                )))?;
            Ok(Json(jwks_value))
        }
        None => {
            warn!("JWKS endpoint accessed but local testing mode is not enabled");
            Err(AppError::Server(crate::error::ServerError::HandlerError(
                "local testing mode not enabled".to_string()
            )))
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
        Config::from_file("test_data/test_config.toml").expect("Failed to load test config")
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
        let result = health_check().await;
        assert!(result.is_ok());

        let Json(response) = result.unwrap();
        assert_eq!(response["status"], "healthy");
        assert_eq!(response["service"], "github-authorized-secrets");
        assert!(response["version"].is_string());
        assert!(response["timestamp"].is_string());
    }

    #[tokio::test]
    async fn test_extract_bearer_token_valid() {
        let validator = InputValidator::default();
        let mut headers = HeaderMap::new();

        // Create a valid JWT-like token
        let valid_token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwczovL3Rva2VuLmFjdGlvbnMuZ2l0aHViLmNvbSIsImF1ZCI6Imh0dHBzOi8vZ2l0aHViLmNvbS9vY3RvY2F0IiwicmVwb3NpdG9yeSI6Im9jdG9jYXQvSGVsbG8tV29ybGQiLCJyZWYiOiJyZWZzL2hlYWRzL21haW4ifQ.signature";

        headers.insert(
            HeaderName::from_str("authorization").unwrap(),
            HeaderValue::from_str(&format!("Bearer {}", valid_token)).unwrap(),
        );

        let result = extract_bearer_token(&headers, &validator);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), valid_token);
    }

    #[tokio::test]
    async fn test_extract_bearer_token_invalid_format() {
        let validator = InputValidator::default();
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_str("authorization").unwrap(),
            HeaderValue::from_str("Basic invalid_format").unwrap(),
        );

        let result = extract_bearer_token(&headers, &validator);
        assert!(result.is_err());

        match result.unwrap_err() {
            AppError::Auth(crate::error::AuthError::MalformedToken) => {
                // Expected error type
            }
            _ => panic!("Expected MalformedToken error"),
        }
    }

    #[tokio::test]
    async fn test_extract_bearer_token_invalid_token_structure() {
        let validator = InputValidator::default();
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_str("authorization").unwrap(),
            HeaderValue::from_str("Bearer invalid.token").unwrap(), // Only 2 parts
        );

        let result = extract_bearer_token(&headers, &validator);
        assert!(result.is_err());

        match result.unwrap_err() {
            AppError::Security(_) => {
                // Expected error type for validation failure
            }
            _ => panic!("Expected Security error for invalid token structure"),
        }
    }

    #[tokio::test]
    async fn test_extract_client_info() {
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_str("user-agent").unwrap(),
            HeaderValue::from_str("github-actions/1.0").unwrap(),
        );
        headers.insert(
            HeaderName::from_str("x-forwarded-for").unwrap(),
            HeaderValue::from_str("192.168.1.1, 10.0.0.1").unwrap(),
        );

        let (ip_address, user_agent) = extract_client_info(&headers);

        assert_eq!(ip_address, Some("192.168.1.1".to_string()));
        assert_eq!(user_agent, Some("github-actions/1.0".to_string()));
    }

    #[tokio::test]
    async fn test_extract_client_info_x_real_ip() {
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_str("x-real-ip").unwrap(),
            HeaderValue::from_str("203.0.113.1").unwrap(),
        );

        let (ip_address, user_agent) = extract_client_info(&headers);

        assert_eq!(ip_address, Some("203.0.113.1".to_string()));
        assert_eq!(user_agent, None);
    }

    #[tokio::test]
    async fn test_get_secrets_missing_auth_header() {
        let app_state = create_test_app_state().await;
        let headers = HeaderMap::new();

        let result = get_secrets(State(app_state), headers).await;
        assert!(result.is_err());

        match result.unwrap_err() {
            AppError::Auth(crate::error::AuthError::InvalidToken) => {
                // Expected error type
            }
            _ => panic!("Expected InvalidToken error"),
        }
    }

    #[tokio::test]
    async fn test_list_repositories_missing_auth_header() {
        let app_state = create_test_app_state().await;
        let headers = HeaderMap::new();

        let result = list_repositories(State(app_state), headers).await;
        assert!(result.is_err());

        match result.unwrap_err() {
            AppError::Auth(crate::error::AuthError::InvalidToken) => {
                // Expected error type
            }
            _ => panic!("Expected InvalidToken error"),
        }
    }

    #[tokio::test]
    async fn test_security_audit_missing_auth_header() {
        let app_state = create_test_app_state().await;
        let headers = HeaderMap::new();

        let result = security_audit(State(app_state), headers).await;
        assert!(result.is_err());

        match result.unwrap_err() {
            AppError::Auth(crate::error::AuthError::InvalidToken) => {
                // Expected error type
            }
            _ => panic!("Expected InvalidToken error"),
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
