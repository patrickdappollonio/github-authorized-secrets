use crate::auth::jwt::JwtValidator;
use crate::auth::signing::LocalJwks;
use crate::config::Config;
use crate::error::AppError;
use crate::secrets::SecretStore;
use crate::server::handlers::{
    get_secrets, health_check, list_repositories, serve_jwks, sign_token,
};
use crate::server::middleware::{cors_layer, logging_middleware};
use axum::{
    middleware,
    routing::{get, post},
    Router,
};
use std::sync::Arc;
use tower::ServiceBuilder;
use tower_http::trace::TraceLayer;
use tracing::info;

/// Shared application state
#[derive(Clone)]
pub struct AppState {
    pub jwt_validator: Arc<JwtValidator>,
    pub secret_store: Arc<SecretStore>,
    pub config: Arc<Config>,
    /// Local JWKs for testing mode (None in production)
    pub local_jwks: Option<Arc<LocalJwks>>,
}

impl AppState {
    /// Create new application state
    pub async fn new(config: Config) -> Result<Self, AppError> {
        // Handle local testing mode
        let (jwt_validator, local_jwks) = if config.server.is_local_testing_mode() {
            info!("Starting in local testing mode");

            // Generate local JWKs - always use 1 key pair for simplicity
            let local_jwks = LocalJwks::new().map_err(AppError::Auth)?;

            info!("Generated 1 RSA key pair for local testing");

            // Create JWT validator with local JWKs URL
            let local_jwks_url = format!(
                "http://{}:{}/.well-known/jwks",
                config.server.host, config.server.port
            );
            let jwt_validator = Arc::new(JwtValidator::new_with_url(&local_jwks_url).await?);

            (jwt_validator, Some(Arc::new(local_jwks)))
        } else {
            // Use GitHub's official JWKs in production with proper config handling
            let validation_config = config
                .validation
                .as_ref()
                .map(|v| v.clone().into())
                .unwrap_or_default();
            let jwt_validator = Arc::new(
                JwtValidator::new_with_config(
                    validation_config,
                    config.server.jwt_cache_duration as i64,
                    config.is_production_mode(),
                )
                .await?,
            );
            (jwt_validator, None)
        };

        // Create secret store from configuration
        let secret_store = Arc::new(SecretStore::from_config(&config.repositories));

        info!(
            "Application state initialized for {} repositories",
            config.repositories.len()
        );

        let config_arc = Arc::new(config);

        Ok(Self {
            jwt_validator,
            secret_store,
            config: config_arc,
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

    let mut router = Router::new()
        .route("/health", get(health_check))
        .route("/secrets", post(get_secrets))
        .route("/secrets/repositories", get(list_repositories))
        .route("/.well-known/jwks", get(serve_jwks));

    // Add token signing endpoint only in local testing mode
    if state.config.server.is_local_testing_mode() {
        router = router.route("/sign-token", post(sign_token));
        info!("Added /sign-token endpoint for local testing mode");
    }

    router.layer(middleware_stack).with_state(state)
}

/// Run the server
pub async fn run_server(config: Config) -> Result<(), AppError> {
    let bind_addr = format!("{}:{}", config.server.host, config.server.port);

    // Create application state
    let state = AppState::new(config).await?;

    // Create the application
    let app = create_app(state);

    info!("Starting server on {}", bind_addr);

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
