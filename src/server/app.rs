use crate::auth::jwt::JwtValidator;
use crate::auth::signing::LocalJwks;
use crate::config::Config;
use crate::error::AppError;
use crate::secrets::SecretStore;
use crate::security::SecurityAuditor;
use crate::server::handlers::{get_secrets, health_check, list_repositories, security_audit, serve_jwks};
use crate::server::middleware::{cors_layer, logging_middleware};
use axum::{
    middleware,
    routing::{get, post},
    Router,
};
use std::sync::Arc;
use tower::ServiceBuilder;
use tower_http::trace::TraceLayer;
use tracing::{info, warn};

/// Shared application state
#[derive(Clone)]
pub struct AppState {
    pub jwt_validator: Arc<JwtValidator>,
    pub secret_store: Arc<SecretStore>,
    pub config: Arc<Config>,
    pub security_auditor: Arc<SecurityAuditor>,
    /// Local JWKs for testing mode (None in production)
    pub local_jwks: Option<Arc<LocalJwks>>,
}

impl AppState {
    /// Create new application state
    pub async fn new(config: Config) -> Result<Self, AppError> {
        // Handle local testing mode
        let (jwt_validator, local_jwks) = if config.server.is_local_testing_mode() {
            info!("Starting in local testing mode");

            // Generate local JWKs
            let num_keys = config.server.get_local_testing_num_keys();
            let local_jwks = LocalJwks::new(num_keys).map_err(|e| AppError::Auth(e))?;

            info!("Generated {} RSA key pairs for local testing", num_keys);
            info!("Local JWKS JSON:");
            println!("{}", local_jwks.to_json().map_err(|e| AppError::Auth(e))?);

            // Create JWT validator with local JWKs URL
            let local_jwks_url = format!("http://{}:{}/.well-known/jwks", config.server.host, config.server.port);
            let jwt_validator = Arc::new(
                JwtValidator::new_with_url(&local_jwks_url).await?,
            );

            warn!("WARNING: Local testing mode is enabled. Do not use in production!");

            (jwt_validator, Some(Arc::new(local_jwks)))
        } else {
            // Create JWT validator with production mode detection for GitHub JWKs
            let jwt_validator = Arc::new(
                JwtValidator::new_with_config(
                    config.validation.clone().unwrap_or_default().into(),
                    config.server.jwt_cache_duration as i64,
                    config.is_production_mode(),
                )
                .await?,
            );

            (jwt_validator, None)
        };

        // Create secret store with secure memory if enabled
        let secret_store = Arc::new(SecretStore::from_config(&config.repositories));

        // Create security auditor
        let security_config = config.get_security_config();
        let security_auditor = Arc::new(SecurityAuditor::new(
            security_config.detailed_audit_logging,
            Some(security_config.into()),
        ));

        // Perform initial security audit
        let audit_report = security_auditor
            .perform_security_audit()
            .map_err(|e| AppError::Security(e))?;

        if audit_report.has_critical_findings() {
            return Err(AppError::Security(
                crate::error::SecurityError::SecurityAuditFailed {
                    reason: "critical security findings detected during startup".to_string(),
                },
            ));
        }

        info!(
            "Application state initialized with {} security findings",
            audit_report.findings.len()
        );

        let config_arc = Arc::new(config);

        Ok(Self {
            jwt_validator,
            secret_store,
            config: config_arc,
            security_auditor,
            local_jwks,
        })
    }
}

/// Create the main application router
pub fn create_app(state: AppState) -> Router {
    let middleware_stack = ServiceBuilder::new()
        .layer(TraceLayer::new_for_http())
        .layer(cors_layer())
        .layer(middleware::from_fn(logging_middleware));

    Router::new()
        .route("/health", get(health_check))
        .route("/secrets", post(get_secrets))
        .route("/secrets/repositories", get(list_repositories))
        .route("/security/audit", get(security_audit))
        .route("/.well-known/jwks", get(serve_jwks))
        .layer(middleware_stack)
        .with_state(state)
}

/// Run the server
pub async fn run_server(config_path: &str) -> Result<(), AppError> {
    // Load configuration
    let config = Config::from_file(config_path)?;

    // Validate server configuration
    config.server.validate().map_err(|e| AppError::Config(e))?;

    // Create application state
    let state = AppState::new(config.clone()).await?;

    // Create the application
    let app = create_app(state);

    // Determine bind address
    let bind_addr = format!("{}:{}", config.server.host, config.server.port);

    info!("Starting server on {}", bind_addr);
    info!("Production mode: {}", config.is_production_mode());
    info!("TLS enabled: {}", config.server.should_enable_tls());

    // Start the server
    let listener = tokio::net::TcpListener::bind(&bind_addr)
        .await
        .map_err(|e| {
            AppError::Server(crate::error::ServerError::BindError {
                address: bind_addr.clone(),
                source: e,
            })
        })?;

    info!("Server listening on {}", bind_addr);

    axum::serve(listener, app)
        .await
        .map_err(|e| AppError::Server(crate::error::ServerError::StartupError(e.to_string())))?;

    Ok(())
}

// Convert SecurityConfig to audit module type
impl From<crate::config::types::SecurityConfig> for crate::security::audit::SecurityPolicies {
    fn from(config: crate::config::types::SecurityConfig) -> Self {
        Self {
            max_auth_failures_per_hour: config.max_auth_failures_per_hour.unwrap_or(100),
            max_secret_access_per_minute: config.max_secret_access_per_minute.unwrap_or(60),
            require_https: config.production_mode,
            block_suspicious_user_agents: config.blocked_user_agents.unwrap_or_else(|| {
                vec![
                    "curl".to_string(),
                    "wget".to_string(),
                    "python-requests".to_string(),
                ]
            }),
            min_token_length: config.min_token_length.unwrap_or(100),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;

    async fn create_test_app() -> Router {
        let config =
            Config::from_file("test_data/test_config.toml").expect("Failed to load test config");
        let state = AppState::new(config)
            .await
            .expect("Failed to create test app state");
        create_app(state)
    }

    #[tokio::test]
    async fn test_health_endpoint() {
        let app = create_test_app().await;

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_security_audit_endpoint_unauthorized() {
        let app = create_test_app().await;

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/security/audit")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        // Should return unauthorized without proper JWT
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_secrets_endpoint_unauthorized() {
        let app = create_test_app().await;

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/secrets")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        // Should return unauthorized without proper JWT
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_repositories_endpoint_unauthorized() {
        let app = create_test_app().await;

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/secrets/repositories")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        // Should return unauthorized without proper JWT
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_app_state_creation() {
        let config =
            Config::from_file("test_data/test_config.toml").expect("Failed to load test config");

        let state = AppState::new(config).await;
        assert!(state.is_ok(), "App state creation should succeed");
    }

    #[tokio::test]
    async fn test_config_validation_conversions() {
        use crate::config::types::{SecurityConfig, ValidationConfig};

        // Test ValidationConfig conversion
        let validation_config = ValidationConfig {
            required_claims: Some(vec!["repository".to_string()]),
            allowed_issuers: Some(vec![
                "https://token.actions.githubusercontent.com".to_string()
            ]),
            max_token_age: Some(600),
        };

        let auth_config: crate::auth::github::ValidationConfig = validation_config.into();
        assert_eq!(auth_config.required_claims, vec!["repository"]);
        assert_eq!(auth_config.max_token_age, 600);

        // Test SecurityConfig conversion
        let security_config = SecurityConfig {
            production_mode: true,
            max_auth_failures_per_hour: Some(50),
            blocked_user_agents: Some(vec!["test-agent".to_string()]),
            ..Default::default()
        };

        let audit_policies: crate::security::audit::SecurityPolicies = security_config.into();
        assert_eq!(audit_policies.max_auth_failures_per_hour, 50);
        assert!(audit_policies.require_https);
        assert!(audit_policies
            .block_suspicious_user_agents
            .contains(&"test-agent".to_string()));
    }

    #[tokio::test]
    async fn test_production_mode_detection() {
        use crate::config::types::{Config, SecurityConfig, ServerConfig};
        use std::collections::HashMap;

        let production_config = Config {
            server: ServerConfig::default(),
            validation: None,
            security: Some(SecurityConfig {
                production_mode: true,
                ..Default::default()
            }),
            repositories: HashMap::new(),
        };

        let state = AppState::new(production_config).await;
        assert!(state.is_ok(), "Production config should be valid");
    }
}
