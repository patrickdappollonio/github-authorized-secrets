use thiserror::Error;

/// Application-wide error type
#[derive(Debug, Error)]
pub enum AppError {
    #[error("authentication failed: {0}")]
    Auth(#[from] AuthError),

    #[error("configuration error: {0}")]
    Config(#[from] ConfigError),

    #[error("client error: {0}")]
    Client(#[from] ClientError),

    #[error("server error: {0}")]
    Server(#[from] ServerError),

    #[error("security error: {0}")]
    Security(#[from] SecurityError),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("join error: {0}")]
    Join(#[from] tokio::task::JoinError),
}

/// Security-specific errors
#[derive(Debug, Error)]
pub enum SecurityError {
    #[error("input validation failed: {message}")]
    InputValidationFailed { message: String },

    #[error("rate limit exceeded for {resource}")]
    RateLimitExceeded { resource: String },

    #[error("suspicious activity detected: {details}")]
    SuspiciousActivity { details: String },

    #[error("insecure configuration detected: {issue}")]
    InsecureConfiguration { issue: String },

    #[error("access denied for resource: {resource}")]
    AccessDenied { resource: String },

    #[error("security audit failed: {reason}")]
    SecurityAuditFailed { reason: String },
}

/// Authentication and JWT validation errors
#[derive(Debug, Error)]
pub enum AuthError {
    #[error("invalid jwt token")]
    InvalidToken,

    #[error("missing key id in jwt header")]
    MissingKeyId,

    #[error("failed to fetch jwks: {0}")]
    JwksFetchFailed(#[source] reqwest::Error),

    #[error("key not found in jwks")]
    KeyNotFound,

    #[error("invalid issuer")]
    InvalidIssuer,

    #[error("token is too old")]
    TokenTooOld,

    #[error("token lifetime is too long")]
    TokenLifetimeTooLong,

    #[error("token has expired")]
    TokenExpired,

    #[error("missing required claim: {claim}")]
    MissingClaim { claim: String },

    #[error("invalid token format or structure")]
    MalformedToken,

    #[error("token signature verification failed")]
    InvalidSignature,

    #[error("token replay attack detected")]
    TokenReplayDetected,

    #[error("jwt decode error: {0}")]
    JwtDecodeError(#[from] jsonwebtoken::errors::Error),

    #[error("jwks client error: {0}")]
    JwksClientError(String),
}

/// Configuration loading and validation errors
#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("failed to read config file: {0}")]
    FileReadError(#[from] std::io::Error),

    #[error("invalid toml format: {message}")]
    TomlParseError { message: String },

    #[error("invalid repository format: {repo} (expected format: owner.repository)")]
    InvalidRepositoryFormat { repo: String },

    #[error("missing server configuration")]
    MissingServerConfig,

    #[error("invalid port number: {port}")]
    InvalidPort { port: u16 },

    #[error("invalid host: {host}")]
    InvalidHost { host: String },

    #[error("validation error: {message}")]
    ValidationError { message: String },

    #[error("insecure configuration: {issue}")]
    InsecureConfig { issue: String },

    #[error("configuration contains forbidden values: {details}")]
    ForbiddenValues { details: String },
}

/// Client-specific errors for CLI operations
#[derive(Debug, Error)]
pub enum ClientError {
    #[error("request failed: {0}")]
    RequestFailed(#[from] reqwest::Error),

    #[error("api returned error status: {status}")]
    ApiError { status: reqwest::StatusCode },

    #[error("not running in github actions environment")]
    NotInGitHubActions,

    #[error("failed to fetch token from github: {status}")]
    TokenFetchFailed { status: reqwest::StatusCode },

    #[error("invalid token response format")]
    InvalidTokenResponse,

    #[error("serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),

    #[error("yaml serialization error: {0}")]
    YamlSerializationError(#[from] serde_yaml::Error),

    #[error("repository not found or access denied")]
    RepositoryNotFound,

    #[error("invalid output format")]
    InvalidOutputFormat,

    #[error("client input validation failed: {field}")]
    InvalidInput { field: String },
}

impl ClientError {
    /// Get a user-friendly error message for common HTTP status codes
    pub fn user_friendly_message(&self) -> String {
        match self {
            ClientError::ApiError { status } => match status.as_u16() {
                401 => "unauthorized - invalid or expired token".to_string(),
                403 => "forbidden - insufficient permissions for this repository".to_string(),
                404 => "not found - repository does not exist or is not configured".to_string(),
                429 => "rate limited - too many requests, please try again later".to_string(),
                500 => {
                    "server error - the secrets server encountered an internal error".to_string()
                }
                502 | 503 => "service unavailable - the secrets server is temporarily unavailable"
                    .to_string(),
                _ => format!("api error - server returned status {status}"),
            },
            ClientError::RequestFailed(e) => {
                // Check for common connection errors
                let error_str = e.to_string().to_lowercase();
                if error_str.contains("connection refused") {
                    "connection refused - is the server running?".to_string()
                } else if error_str.contains("timeout") {
                    "request timeout - the server did not respond in time".to_string()
                } else if error_str.contains("record overflow")
                    || error_str.contains("tls")
                    || error_str.contains("ssl")
                {
                    "TLS/SSL error - you may be using HTTPS with an HTTP-only server. Try adding --scheme http".to_string()
                } else if error_str.contains("dns") || error_str.contains("name resolution") {
                    "DNS error - could not resolve server hostname".to_string()
                } else {
                    format!("network error - {e}")
                }
            }
            _ => self.to_string(),
        }
    }
}

/// Server-specific errors
#[derive(Debug, Error)]
pub enum ServerError {
    #[error("failed to bind to address {address}: {source}")]
    BindError {
        address: String,
        #[source]
        source: std::io::Error,
    },

    #[error("server startup failed: {0}")]
    StartupError(String),

    #[error("middleware error: {0}")]
    MiddlewareError(String),

    #[error("handler error: {0}")]
    HandlerError(String),

    #[error("tls configuration error: {0}")]
    TlsError(String),

    #[error("security middleware violation: {details}")]
    SecurityViolation { details: String },
}

/// Convenience type for Results
pub type Result<T> = std::result::Result<T, AppError>;

// Axum error response implementations
impl axum::response::IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        use axum::{http::StatusCode, Json};
        use serde_json::json;
        use tracing::warn;

        // Log security-related errors for audit purposes
        match &self {
            AppError::Security(ref err) => {
                warn!("Security error: {}", err);
            }
            AppError::Auth(ref err) => {
                warn!("Authentication error: {}", err);
            }
            _ => {}
        }

        let (status, error_message) = match &self {
            AppError::Auth(AuthError::InvalidToken) => (StatusCode::UNAUTHORIZED, "invalid token"),
            AppError::Auth(AuthError::TokenExpired) => (StatusCode::UNAUTHORIZED, "token expired"),
            AppError::Auth(AuthError::TokenTooOld) => (StatusCode::UNAUTHORIZED, "token too old"),
            AppError::Auth(AuthError::InvalidIssuer) => {
                (StatusCode::UNAUTHORIZED, "invalid issuer")
            }
            AppError::Auth(AuthError::MalformedToken) => {
                (StatusCode::BAD_REQUEST, "malformed token")
            }
            AppError::Auth(AuthError::InvalidSignature) => {
                (StatusCode::UNAUTHORIZED, "invalid signature")
            }
            AppError::Auth(AuthError::TokenReplayDetected) => {
                (StatusCode::UNAUTHORIZED, "token replay detected")
            }
            AppError::Auth(_) => (StatusCode::UNAUTHORIZED, "authentication failed"),
            AppError::Security(SecurityError::InputValidationFailed { .. }) => {
                (StatusCode::BAD_REQUEST, "invalid input")
            }
            AppError::Security(SecurityError::RateLimitExceeded { .. }) => {
                (StatusCode::TOO_MANY_REQUESTS, "rate limit exceeded")
            }
            AppError::Security(SecurityError::AccessDenied { .. }) => {
                (StatusCode::FORBIDDEN, "access denied")
            }
            AppError::Security(_) => (StatusCode::FORBIDDEN, "security violation"),
            AppError::Client(ClientError::RepositoryNotFound) => {
                (StatusCode::NOT_FOUND, "repository not found")
            }
            AppError::Client(ClientError::InvalidInput { .. }) => {
                (StatusCode::BAD_REQUEST, "invalid input")
            }
            AppError::Config(_) => (StatusCode::INTERNAL_SERVER_ERROR, "configuration error"),
            AppError::Server(_) => (StatusCode::INTERNAL_SERVER_ERROR, "server error"),
            _ => (StatusCode::INTERNAL_SERVER_ERROR, "internal server error"),
        };

        let body = Json(json!({
            "error": error_message,
            "message": self.to_string()
        }));

        (status, body).into_response()
    }
}
