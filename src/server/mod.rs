pub mod app;
pub mod handlers;
pub mod middleware;

pub use app::{create_app, AppState};
pub use handlers::{health_check, get_secrets, list_repositories, serve_jwks};

use crate::config::Config;
use crate::error::AppError;
use std::net::SocketAddr;
use std::str::FromStr;
use tokio::net::TcpListener;
use tokio::signal;
use tracing::info;

/// Run the server with the given configuration file
pub async fn run_server(config_path: &str) -> Result<(), AppError> {
    info!("Loading configuration from: {}", config_path);

    // Load configuration
    let config = Config::from_file(config_path)?;
    info!("Configuration loaded successfully");

    // Create application state
    let app_state = AppState::new(config.clone()).await?;
    info!("Application state initialized");

    // Create the Axum app
    let app = create_app(app_state);

    // Create socket address
    let addr = SocketAddr::from_str(&format!("{}:{}", config.server.host, config.server.port))
        .map_err(|e| AppError::Server(crate::error::ServerError::StartupError(
            format!("invalid server address: {}", e)
        )))?;

    // Create TCP listener
    let listener = TcpListener::bind(&addr)
        .await
        .map_err(|e| AppError::Server(crate::error::ServerError::BindError {
            address: addr.to_string(),
            source: e,
        }))?;

    info!("Server listening on http://{}", addr);

    // Run the server with graceful shutdown
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .map_err(|e| AppError::Server(crate::error::ServerError::StartupError(
            format!("server error: {}", e)
        )))?;

    info!("Server shutdown complete");
    Ok(())
}

/// Wait for shutdown signal (Ctrl+C or SIGTERM)
async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {
            info!("Received Ctrl+C, shutting down gracefully...");
        },
        _ = terminate => {
            info!("Received SIGTERM, shutting down gracefully...");
        },
    }

    // Give some time for connections to close gracefully
    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
}
