# GitHub Authorized Secrets - Development Plan

## Overview

This project implements a secure secret management system for GitHub Actions workflows. It consists of a web server that validates GitHub Actions JWT tokens and returns repository-specific secrets, plus a CLI client for testing and interaction.

## Architecture

### High-Level Components

1. **JWT Validation Service**: Validates GitHub Actions OIDC tokens using JWKs from GitHub
2. **Configuration Management**: TOML-based configuration mapping repositories to secrets
3. **Web Server**: REST API for secret retrieval with JWT authentication
4. **CLI Client**: Command-line interface for interacting with the server
5. **Secret Storage**: In-memory secret storage loaded from TOML configuration

### Core Flow

```
GitHub Actions Runner → Request JWT → GitHub OIDC → JWT Token
                                                        ↓
JWT Token → Our Web Server → Validate with GitHub JWKs → Extract Claims
                                                        ↓
Repository/Owner Claims → Match TOML Config → Return Secrets → GitHub Actions
```

## Technical Stack

### Dependencies

```toml
[dependencies]
# Web framework
axum = "0.7"
tokio = { version = "1.0", features = ["full"] }
tower = "0.4"
tower-http = { version = "0.5", features = ["cors", "trace"] }

# JWT validation
jsonwebtoken = "9.0"
jwks-client = "0.2"

# Configuration and serialization
serde = { version = "1.0", features = ["derive"] }
toml = "0.8"

# HTTP client for JWK fetching
reqwest = { version = "0.11", features = ["json"] }

# CLI framework
clap = { version = "4.0", features = ["derive"] }

# Output formatting
serde_yaml = "0.9"
shell-escape = "0.1"
urlencoding = "2.1"

# Logging and error handling
tracing = "0.1"
tracing-subscriber = "0.3"
anyhow = "1.0"
thiserror = "1.0"

# Time handling for JWT validation
chrono = { version = "0.4", features = ["serde"] }

[dev-dependencies]
# Testing
mockito = "1.2"
tokio-test = "0.4"
```

## Project Structure

```
src/
├── main.rs                 # Entry point with CLI argument parsing
├── lib.rs                  # Library exports
├── server/
│   ├── mod.rs             # Server module exports
│   ├── app.rs             # Axum application setup
│   ├── handlers.rs        # HTTP request handlers
│   └── middleware.rs      # Custom middleware (logging, CORS)
├── client/
│   ├── mod.rs             # Client module exports
│   └── api.rs             # CLI client implementation
├── auth/
│   ├── mod.rs             # Authentication module exports
│   ├── jwt.rs             # JWT validation logic
│   └── github.rs          # GitHub-specific JWT claims and validation
├── config/
│   ├── mod.rs             # Configuration module exports
│   ├── loader.rs          # TOML configuration loading
│   └── types.rs           # Configuration data structures
├── secrets/
│   ├── mod.rs             # Secret management module exports
│   └── store.rs           # In-memory secret store
└── error.rs               # Custom error types
```

## Configuration Schema

### TOML Configuration Format

```toml
# Server configuration
[server]
host = "127.0.0.1"
port = 8080
jwt_cache_duration = 300  # seconds to cache JWKs

# Repository secrets mapping
# Format: [organization.repository]
[github.octocat]
api_key = "secret_api_key_value"
database_url = "postgresql://user:pass@localhost/db"
deployment_token = "ghp_xxxxxxxxxxxx"

[organization.repo]
key1 = "value1"
key2 = "value2"
private_key = """-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC...
-----END PRIVATE KEY-----"""

# Validation rules (optional)
[validation]
required_claims = ["repository", "repository_owner"]
allowed_issuers = ["https://token.actions.githubusercontent.com"]
max_token_age = 300  # seconds
```

## Implementation Phases

### Phase 1: Core JWT Validation (Week 1)

**Deliverables:**
- JWT validation service using GitHub JWKs
- GitHub claims parsing and validation
- Error handling for invalid tokens

**Key Files:**
- `src/auth/jwt.rs`
- `src/auth/github.rs`
- `src/error.rs`

**Implementation Details:**

```rust
// JWT Claims structure matching GitHub Actions tokens
#[derive(Debug, Serialize, Deserialize)]
pub struct GitHubClaims {
    pub iss: String,                    // "https://token.actions.githubusercontent.com"
    pub sub: String,                    // Subject claim
    pub aud: String,                    // Audience
    pub repository: String,             // "owner/repo"
    pub repository_owner: String,       // "owner"
    pub repository_id: String,          // Repository ID
    pub ref_: String,                   // Git ref
    pub sha: String,                    // Commit SHA
    pub workflow: String,               // Workflow name
    pub actor: String,                  // Actor who triggered
    pub run_id: String,                 // Workflow run ID
    pub exp: i64,                       // Expiration time
    pub iat: i64,                       // Issued at
    pub nbf: i64,                       // Not before
}

// JWT validation service
pub struct JwtValidator {
    jwks_client: JwksClient,
    validation_config: ValidationConfig,
}

impl JwtValidator {
    pub async fn new() -> Result<Self, AuthError> {
        let jwks_url = "https://token.actions.githubusercontent.com/.well-known/jwks";
        let jwks_client = JwksClient::builder()
            .jwks_url(jwks_url)
            .build()
            .await?;

        Ok(Self {
            jwks_client,
            validation_config: ValidationConfig::default(),
        })
    }

    pub async fn validate_token(&self, token: &str) -> Result<GitHubClaims, AuthError> {
        // Decode header to get kid
        let header = decode_header(token)?;
        let kid = header.kid.ok_or(AuthError::MissingKeyId)?;

        // Get JWK for kid
        let jwk = self.jwks_client.get_key(&kid).await?;

        // Validate token
        let validation = Validation::new(Algorithm::RS256);
        let token_data = decode::<GitHubClaims>(token, &jwk, &validation)?;

        // Additional GitHub-specific validations
        self.validate_github_claims(&token_data.claims)?;

        Ok(token_data.claims)
    }

    fn validate_github_claims(&self, claims: &GitHubClaims) -> Result<(), AuthError> {
        // Validate issuer
        if claims.iss != "https://token.actions.githubusercontent.com" {
            return Err(AuthError::InvalidIssuer);
        }

        // Validate token age
        let now = chrono::Utc::now().timestamp();
        if now - claims.iat > self.validation_config.max_token_age {
            return Err(AuthError::TokenTooOld);
        }

        Ok(())
    }
}
```

### Phase 2: Configuration Management (Week 1)

**Deliverables:**
- TOML configuration loading and parsing
- Repository to secrets mapping
- Configuration validation

**Key Files:**
- `src/config/loader.rs`
- `src/config/types.rs`

**Implementation Details:**

```rust
#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    pub server: ServerConfig,
    pub validation: Option<ValidationConfig>,
    #[serde(flatten)]
    pub repositories: HashMap<String, HashMap<String, String>>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub jwt_cache_duration: u64,
}

impl Config {
    pub fn from_file(path: &str) -> Result<Self, ConfigError> {
        let content = std::fs::read_to_string(path)?;
        let config: Config = toml::from_str(&content)?;
        config.validate()?;
        Ok(config)
    }

    pub fn get_secrets(&self, repository: &str) -> Option<&HashMap<String, String>> {
        // Parse repository string "owner/repo" into "owner.repo"
        let key = repository.replace('/', ".");
        self.repositories.get(&key)
    }

    fn validate(&self) -> Result<(), ConfigError> {
        // Validate repository names follow "owner.repo" format
        for key in self.repositories.keys() {
            if !key.contains('.') {
                return Err(ConfigError::InvalidRepositoryFormat(key.clone()));
            }
        }
        Ok(())
    }
}
```

### Phase 3: Web Server Implementation (Week 2)

**Deliverables:**
- REST API endpoints for secret retrieval
- JWT middleware for authentication
- Error handling and logging

**Key Files:**
- `src/server/app.rs`
- `src/server/handlers.rs`
- `src/server/middleware.rs`

**API Endpoints:**

```
GET /health                    # Health check endpoint
POST /secrets                  # Get secrets for authenticated repository
GET /secrets/repositories      # List available repositories (authenticated)
```

**Implementation Details:**

```rust
// Main application state
#[derive(Clone)]
pub struct AppState {
    pub jwt_validator: Arc<JwtValidator>,
    pub config: Arc<Config>,
}

// Secret retrieval handler
pub async fn get_secrets(
    State(state): State<AppState>,
    TypedHeader(auth): TypedHeader<Authorization<Bearer>>,
) -> Result<Json<SecretsResponse>, AppError> {
    // Validate JWT token
    let claims = state.jwt_validator.validate_token(auth.token()).await?;

    // Get secrets for repository
    let secrets = state.config
        .get_secrets(&claims.repository)
        .ok_or(AppError::RepositoryNotFound)?;

    // Return secrets (excluding sensitive metadata)
    Ok(Json(SecretsResponse {
        repository: claims.repository,
        secrets: secrets.clone(),
        metadata: SecretsMetadata {
            retrieved_at: chrono::Utc::now(),
            repository_owner: claims.repository_owner,
        },
    }))
}

// Axum application setup
pub fn create_app(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health_check))
        .route("/secrets", post(get_secrets))
        .route("/secrets/repositories", get(list_repositories))
        .layer(TraceLayer::new_for_http())
        .layer(CorsLayer::permissive())
        .with_state(state)
}
```

### Phase 4: CLI Client Implementation (Week 2)

**Deliverables:**
- CLI client for interacting with the server
- Automatic GitHub Actions JWT token fetching
- Multiple output formats (JSON, Bash, Env, YAML)
- Security-conscious output masking for CI/CD

**Benefits of Auto-Token Fetching:**
- **Zero Configuration**: Works out-of-box in GitHub Actions without manual token handling
- **Security**: No need to expose JWT tokens in workflow logs or commands
- **Simplicity**: Single command replaces complex curl/jq chains
- **Reliability**: Handles token audience and validation automatically

**Key Files:**
- `src/client/api.rs`
- `src/client/token.rs`
- `src/main.rs` (CLI argument parsing)

**Additional Error Types:**

```rust
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("Request failed: {0}")]
    RequestFailed(#[from] reqwest::Error),

    #[error("API returned error status: {0}")]
    ApiError(reqwest::StatusCode),

    #[error("Not running in GitHub Actions environment")]
    NotInGitHubActions,

    #[error("Failed to fetch token from GitHub: {0}")]
    TokenFetchFailed(reqwest::StatusCode),

    #[error("Invalid token response format")]
    InvalidTokenResponse,

    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),
}
```

**CLI Interface:**

```bash
# Start the server
github-authorized-secrets server --config config.toml

# CLI client commands (automatically detects GitHub Actions environment)
github-authorized-secrets pull --host secrets.example.com --format bash
github-authorized-secrets pull --host secrets.example.com --format json
github-authorized-secrets pull --host secrets.example.com --format env
github-authorized-secrets list --host secrets.example.com

# Advanced formatting options
github-authorized-secrets pull --host secrets.example.com --format bash --prefix DEPLOY_ --uppercase
github-authorized-secrets pull --host secrets.example.com --format env --prefix APP_ --uppercase

# Manual token mode (for testing outside GitHub Actions)
github-authorized-secrets pull --host secrets.example.com --token <jwt_token> --format bash --prefix PROD_
```

**Implementation Details:**

```rust
#[derive(Parser)]
#[command(name = "github-authorized-secrets")]
#[command(about = "GitHub Actions authorized secrets management")]
pub enum Cli {
    Server {
        #[arg(short, long, default_value = "config.toml")]
        config: String,
    },
    Pull {
        #[arg(long, env = "HOST")]
        host: String,
        #[arg(short, long)]
        token: Option<String>,
        #[arg(short, long, default_value = "env")]
        format: OutputFormat,
        #[arg(long, default_value = "https")]
        scheme: String,
        #[arg(long)]
        audience: Option<String>,
        #[arg(long)]
        prefix: Option<String>,
        #[arg(long)]
        uppercase: bool,
    },
    List {
        #[arg(long, env = "HOST")]
        host: String,
        #[arg(short, long)]
        token: Option<String>,
        #[arg(long, default_value = "https")]
        scheme: String,
        #[arg(long)]
        audience: Option<String>,
    },
}

#[derive(Clone, ValueEnum)]
pub enum OutputFormat {
    Json,
    Bash,
    Env,
    Yaml,
}

// GitHub Actions token fetcher
pub struct GitHubTokenFetcher {
    client: reqwest::Client,
}

impl GitHubTokenFetcher {
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::new(),
        }
    }

    pub async fn fetch_token(&self, audience: Option<&str>) -> Result<String, ClientError> {
        let token_url = std::env::var("ACTIONS_ID_TOKEN_REQUEST_URL")
            .map_err(|_| ClientError::NotInGitHubActions)?;
        let request_token = std::env::var("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
            .map_err(|_| ClientError::NotInGitHubActions)?;

        let mut url = token_url;
        if let Some(aud) = audience {
            url = format!("{}&audience={}", url, urlencoding::encode(aud));
        }

        let response = self
            .client
            .get(&url)
            .bearer_auth(&request_token)
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(ClientError::TokenFetchFailed(response.status()));
        }

        let token_response: TokenResponse = response.json().await?;
        Ok(token_response.value)
    }
}

#[derive(Deserialize)]
struct TokenResponse {
    value: String,
}

// Enhanced client implementation
pub struct ApiClient {
    base_url: String,
    client: reqwest::Client,
    token_fetcher: GitHubTokenFetcher,
}

impl ApiClient {
    pub fn new(host: &str, scheme: &str) -> Self {
        let base_url = format!("{}://{}", scheme, host);
        Self {
            base_url,
            client: reqwest::Client::new(),
            token_fetcher: GitHubTokenFetcher::new(),
        }
    }

    pub async fn get_secrets_with_auto_auth(
        &self,
        token: Option<&str>,
        audience: Option<&str>,
    ) -> Result<SecretsResponse, ClientError> {
        let auth_token = match token {
            Some(t) => t.to_string(),
            None => self.token_fetcher.fetch_token(audience).await?,
        };

        self.get_secrets(&auth_token).await
    }

    pub async fn get_secrets(&self, token: &str) -> Result<SecretsResponse, ClientError> {
        let response = self
            .client
            .post(&format!("{}/secrets", self.base_url))
            .bearer_auth(token)
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(ClientError::ApiError(response.status()));
        }

        Ok(response.json().await?)
    }

    pub async fn list_repositories_with_auto_auth(
        &self,
        token: Option<&str>,
        audience: Option<&str>,
    ) -> Result<RepositoryListResponse, ClientError> {
        let auth_token = match token {
            Some(t) => t.to_string(),
            None => self.token_fetcher.fetch_token(audience).await?,
        };

        self.list_repositories(&auth_token).await
    }
}

// Output formatting
impl OutputFormat {
    pub fn format_secrets(
        &self,
        secrets: &HashMap<String, String>,
        prefix: Option<&str>,
        uppercase: bool
    ) -> String {
        let transform_key = |key: &str| -> String {
            let mut transformed_key = key.to_string();

            if uppercase {
                transformed_key = transformed_key.to_uppercase();
            }

            if let Some(prefix) = prefix {
                transformed_key = format!("{}{}", prefix, transformed_key);
            }

            transformed_key
        };

        match self {
            OutputFormat::Json => {
                let transformed_secrets: HashMap<String, String> = secrets
                    .iter()
                    .map(|(key, value)| (transform_key(key), value.clone()))
                    .collect();
                serde_json::to_string_pretty(&transformed_secrets).unwrap()
            }
            OutputFormat::Bash => {
                secrets
                    .iter()
                    .map(|(key, value)| {
                        let transformed_key = transform_key(key);
                        format!("export {}={}", transformed_key, shell_escape::escape_bash(value))
                    })
                    .collect::<Vec<_>>()
                    .join("\n")
            }
            OutputFormat::Env => {
                secrets
                    .iter()
                    .map(|(key, value)| {
                        let transformed_key = transform_key(key);
                        format!("{}={}", transformed_key, value)
                    })
                    .collect::<Vec<_>>()
                    .join("\n")
            }
            OutputFormat::Yaml => {
                let transformed_secrets: HashMap<String, String> = secrets
                    .iter()
                    .map(|(key, value)| (transform_key(key), value.clone()))
                    .collect();
                serde_yaml::to_string(&transformed_secrets).unwrap()
            }
        }
    }
}

// Secret masking utilities - future-proofed for GitHub Actions changes
pub struct SecretMasker;

impl SecretMasker {
    pub fn mask_secrets(secrets: &HashMap<String, String>) {
        if std::env::var("GITHUB_ACTIONS").is_ok() {
            for (_, value) in secrets {
                Self::mask_value(value);
            }
        }
    }

    fn mask_value(value: &str) {
        // Current method (as of 2025) - this implementation should be updated
        // if GitHub deprecates workflow commands in favor of alternative approaches
        println!("::add-mask::{}", value);

        // TODO: Monitor GitHub changelog for workflow command deprecations
        // Alternative approaches might include:
        // - Environment file-based masking
        // - API-based secret registration
        // - New workflow command syntax
    }
}

// Main CLI handler
async fn handle_pull_command(
    host: String,
    token: Option<String>,
    format: OutputFormat,
    scheme: String,
    audience: Option<String>,
    prefix: Option<String>,
    uppercase: bool,
) -> Result<(), ClientError> {
    let client = ApiClient::new(&host, &scheme);

    let secrets_response = client
        .get_secrets_with_auto_auth(token.as_deref(), audience.as_deref())
        .await?;

    let formatted_output = format.format_secrets(
        &secrets_response.secrets,
        prefix.as_deref(),
        uppercase
    );

    // Mask sensitive values in GitHub Actions logs using future-proof implementation
    SecretMasker::mask_secrets(&secrets_response.secrets);

    println!("{}", formatted_output);

    Ok(())
}

async fn handle_list_command(
    host: String,
    token: Option<String>,
    scheme: String,
    audience: Option<String>,
) -> Result<(), ClientError> {
    let client = ApiClient::new(&host, &scheme);

    let repos_response = client
        .list_repositories_with_auto_auth(token.as_deref(), audience.as_deref())
        .await?;

    println!("Available repositories:");
    for repo in &repos_response.repositories {
        println!("  - {}", repo);
    }

    Ok(())
}
```

### Phase 5: Testing and Documentation (Week 3)

**Deliverables:**
- Unit tests for all components
- Integration tests with mock GitHub JWKs
- API documentation
- Usage examples

**Testing Strategy:**

```rust
// Mock JWT validation for testing
#[cfg(test)]
mod tests {
    use super::*;
    use mockito::Server;

    #[tokio::test]
    async fn test_jwt_validation() {
        let mut server = Server::new_async().await;

        // Mock JWKs endpoint
        let jwks_mock = server.mock("GET", "/.well-known/jwks")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(include_str!("../test_data/mock_jwks.json"))
            .create_async()
            .await;

        let validator = JwtValidator::new_with_url(&server.url()).await.unwrap();
        let test_token = create_test_jwt_token();

        let result = validator.validate_token(&test_token).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_config_loading() {
        let config = Config::from_file("test_data/test_config.toml").unwrap();
        assert_eq!(config.server.port, 8080);
        assert!(config.get_secrets("github/octocat").is_some());
    }

    #[tokio::test]
    async fn test_secret_retrieval_endpoint() {
        let app = create_test_app().await;
        let response = app
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/secrets")
                    .header("authorization", "Bearer valid_jwt_token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_github_token_fetching() {
        let mut server = Server::new_async().await;

        // Mock GitHub Actions token endpoint
        let token_mock = server.mock("GET", "/token")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"value": "mock_jwt_token"}"#)
            .create_async()
            .await;

        // Set environment variables to simulate GitHub Actions
        std::env::set_var("ACTIONS_ID_TOKEN_REQUEST_URL", format!("{}/token", server.url()));
        std::env::set_var("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "mock_request_token");

        let fetcher = GitHubTokenFetcher::new();
        let token = fetcher.fetch_token(Some("my-audience")).await.unwrap();

        assert_eq!(token, "mock_jwt_token");

        // Clean up environment variables
        std::env::remove_var("ACTIONS_ID_TOKEN_REQUEST_URL");
        std::env::remove_var("ACTIONS_ID_TOKEN_REQUEST_TOKEN");
    }

    #[tokio::test]
    async fn test_output_formatting() {
        let mut secrets = HashMap::new();
        secrets.insert("api_key".to_string(), "secret123".to_string());
        secrets.insert("db_url".to_string(), "postgresql://localhost/db".to_string());

        // Basic formatting without transformations
        let bash_output = OutputFormat::Bash.format_secrets(&secrets, None, false);
        assert!(bash_output.contains("export api_key="));
        assert!(bash_output.contains("export db_url="));

        let env_output = OutputFormat::Env.format_secrets(&secrets, None, false);
        assert!(env_output.contains("api_key=secret123"));
        assert!(env_output.contains("db_url=postgresql://localhost/db"));

        let json_output = OutputFormat::Json.format_secrets(&secrets, None, false);
        let parsed: serde_json::Value = serde_json::from_str(&json_output).unwrap();
        assert_eq!(parsed["api_key"], "secret123");
    }

    #[tokio::test]
    async fn test_output_formatting_with_prefix_and_uppercase() {
        let mut secrets = HashMap::new();
        secrets.insert("api_key".to_string(), "secret123".to_string());
        secrets.insert("db_url".to_string(), "postgresql://localhost/db".to_string());

        // Test with prefix and uppercase
        let bash_output = OutputFormat::Bash.format_secrets(&secrets, Some("DEPLOY_"), true);
        assert!(bash_output.contains("export DEPLOY_API_KEY="));
        assert!(bash_output.contains("export DEPLOY_DB_URL="));

        let env_output = OutputFormat::Env.format_secrets(&secrets, Some("APP_"), true);
        assert!(env_output.contains("APP_API_KEY=secret123"));
        assert!(env_output.contains("APP_DB_URL=postgresql://localhost/db"));

        let json_output = OutputFormat::Json.format_secrets(&secrets, Some("PREFIX_"), true);
        let parsed: serde_json::Value = serde_json::from_str(&json_output).unwrap();
        assert_eq!(parsed["PREFIX_API_KEY"], "secret123");
        assert_eq!(parsed["PREFIX_DB_URL"], "postgresql://localhost/db");

        // Test with only uppercase
        let yaml_output = OutputFormat::Yaml.format_secrets(&secrets, None, true);
        assert!(yaml_output.contains("API_KEY:"));
        assert!(yaml_output.contains("DB_URL:"));

        // Test with only prefix
        let env_output_prefix_only = OutputFormat::Env.format_secrets(&secrets, Some("TEST_"), false);
        assert!(env_output_prefix_only.contains("TEST_api_key=secret123"));
        assert!(env_output_prefix_only.contains("TEST_db_url=postgresql://localhost/db"));
    }
}
```

## Security Considerations

### JWT Validation
- **JWK Caching**: Cache JWKs with TTL to prevent excessive requests to GitHub
- **Token Expiration**: Strict validation of `exp`, `iat`, and `nbf` claims
- **Issuer Validation**: Only accept tokens from `https://token.actions.githubusercontent.com`
- **Algorithm Restriction**: Only allow RS256 algorithm

### Secret Management
- **Memory Security**: Clear secrets from memory when possible
- **Configuration Validation**: Validate TOML configuration on startup
- **Access Logging**: Log all secret access attempts with repository information
- **Output Masking**: Automatically mask sensitive values in GitHub Actions logs using the current GitHub-recommended method (currently `::add-mask::`, but implementation will adapt to GitHub's evolving security standards)
- **Security Standard Compliance**: Monitor GitHub security announcements and changelog for updates to secret handling best practices

### Network Security
- **HTTPS Only**: Production deployment should use HTTPS
- **CORS Configuration**: Restrict CORS to necessary origins
- **Rate Limiting**: Implement rate limiting to prevent abuse

## Deployment Considerations

### Configuration Example
```toml
[server]
host = "0.0.0.0"
port = 8080
jwt_cache_duration = 300

[validation]
max_token_age = 300
required_claims = ["repository", "repository_owner", "workflow"]

[github.my-org-actions]
database_url = "postgresql://user:pass@db:5432/prod"
api_key = "sk-1234567890abcdef"
redis_url = "redis://redis:6379"

[acme-corp.web-app]
deploy_key = """-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA...
-----END RSA PRIVATE KEY-----"""
webhook_secret = "supersecret123"
```

### Docker Deployment
```dockerfile
FROM rust:1.75-slim as builder
WORKDIR /app
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates
COPY --from=builder /app/target/release/github-authorized-secrets /usr/local/bin/
EXPOSE 8080
CMD ["github-authorized-secrets", "server", "--config", "/config/config.toml"]
```

### GitHub Actions Integration Example
```yaml
name: Deploy
on: [push]

permissions:
  id-token: write
  contents: read

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - name: Download secrets client
        run: |
          curl -L https://github.com/org/github-authorized-secrets/releases/latest/download/github-authorized-secrets-linux-x86_64.tar.gz | tar xz
          chmod +x github-authorized-secrets

      - name: Load deployment secrets
        run: |
          ./github-authorized-secrets pull --format bash --prefix DEPLOY_ --uppercase >> $GITHUB_ENV
        env:
          HOST: secrets.example.com

      - name: Deploy with secrets
        run: |
          # All secrets are now available as environment variables with DEPLOY_ prefix and uppercase
          deploy-script --api-key="$DEPLOY_API_KEY" --db-url="$DEPLOY_DATABASE_URL"

      # Alternative: Export to specific variables
      - name: Load secrets to outputs
        id: secrets
        run: |
          SECRETS=$(./github-authorized-secrets pull --format json)
          echo "api_key=$(echo $SECRETS | jq -r .API_KEY)" >> $GITHUB_OUTPUT
          echo "::add-mask::$(echo $SECRETS | jq -r .API_KEY)"
        env:
          HOST: secrets.example.com

      # Alternative: Custom audience with specific prefix
      - name: Load secrets with custom audience
        run: |
          ./github-authorized-secrets pull --format env --audience "my-service" --prefix SERVICE_ --uppercase >> $GITHUB_ENV
        env:
          HOST: secrets.example.com
```

## Success Criteria

1. **Security**: JWT tokens are properly validated using GitHub's JWKs
2. **Functionality**: Secrets are correctly mapped and returned based on repository
3. **Usability**: CLI provides intuitive interface for testing and interaction
4. **Reliability**: Comprehensive error handling and logging
5. **Performance**: Sub-100ms response times for secret retrieval
6. **Documentation**: Clear setup and usage instructions
