use clap::Parser;
use github_authorized_secrets::{
    auth::signing::{create_test_claims, LocalJwks},
    client::{handle_client_command, OutputFormat},
    config::Config,
    error::AppError,
    server::{AppState, create_app},
};
use tracing::info;

#[cfg(test)]
use serial_test::serial;

#[derive(Parser)]
#[command(name = "github-authorized-secrets")]
#[command(about = "GitHub Actions authorized secrets management")]
#[command(version = env!("CARGO_PKG_VERSION"))]
pub enum Cli {
    /// Start the secrets server
    Server {
        #[arg(short, long, default_value = "config.toml")]
        config: String,
        /// Enable local testing mode with generated JWKs
        #[arg(long, env = "LOCAL_TESTING_MODE")]
        local_testing: bool,
        /// Number of RSA key pairs to generate for local testing
        #[arg(long, default_value = "1")]
        local_keys: usize,
        /// Host to bind to (overrides config)
        #[arg(long, env = "SERVER_HOST")]
        host: Option<String>,
        /// Port to bind to (overrides config)
        #[arg(long, env = "SERVER_PORT")]
        port: Option<u16>,
    },
    /// Pull secrets from the server
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
    /// List available repositories
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
    /// Sign a JWT token for testing
    Sign {
        /// Repository in the format "owner/repo"
        #[arg(short, long)]
        repository: String,
        /// Repository owner
        #[arg(short, long)]
        owner: Option<String>,
        /// Workflow name
        #[arg(short, long)]
        workflow: Option<String>,
        /// Actor who triggered the workflow
        #[arg(short, long)]
        actor: Option<String>,
        /// Git reference
        #[arg(long)]
        ref_name: Option<String>,
        /// Commit SHA
        #[arg(long)]
        sha: Option<String>,
        /// Token audience
        #[arg(long)]
        audience: Option<String>,
        /// Server host to use for JWKs generation (defaults to localhost:8080)
        #[arg(long, default_value = "localhost:8080")]
        server: String,
        /// Output only the token (useful for scripting)
        #[arg(long)]
        token_only: bool,
    },
}

#[tokio::main]
async fn main() -> Result<(), AppError> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("github_authorized_secrets=info".parse().unwrap()),
        )
        .init();

    let cli = Cli::parse();

    match cli {
        Cli::Server {
            config,
            local_testing,
            local_keys,
            host,
            port
        } => {
            info!("Starting GitHub Authorized Secrets server");
            handle_server_command(config, local_testing, local_keys, host, port).await
        }
        Cli::Pull {
            host,
            token,
            format,
            scheme,
            audience,
            prefix,
            uppercase,
        } => handle_client_command(host, token, format, scheme, audience, prefix, uppercase).await,
        Cli::List {
            host,
            token,
            scheme,
            audience,
        } => {
            handle_client_command(
                host,
                token,
                OutputFormat::Json,
                scheme,
                audience,
                None,
                false,
            )
            .await
        }
        Cli::Sign {
            repository,
            owner,
            workflow,
            actor,
            ref_name,
            sha,
            audience,
            server,
            token_only,
        } => handle_sign_command(
            repository,
            owner,
            workflow,
            actor,
            ref_name,
            sha,
            audience,
            server,
            token_only,
        ).await,
    }
}

/// Handle server command with local testing options
async fn handle_server_command(
    config_path: String,
    local_testing: bool,
    local_keys: usize,
    host_override: Option<String>,
    port_override: Option<u16>,
) -> Result<(), AppError> {
    // Load base configuration
    let mut config = Config::from_file(&config_path)?;

    // Apply CLI overrides
    if local_testing {
        config.server.local_testing_mode = Some(true);
        config.server.local_testing_num_keys = Some(local_keys);
        info!("Local testing mode enabled with {} keys", local_keys);
    }

    if let Some(host) = host_override {
        config.server.host = host;
    }

    if let Some(port) = port_override {
        config.server.port = port;
    }

    // Validate server configuration
    config.server.validate().map_err(|e| AppError::Config(e))?;

    // Create application state with modified config
    let state = AppState::new(config.clone()).await?;

    // Create the application
    let app = create_app(state);

    // Determine bind address
    let bind_addr = format!("{}:{}", config.server.host, config.server.port);

    info!("Starting server on {}", bind_addr);
    info!("Production mode: {}", config.is_production_mode());
    info!("Local testing mode: {}", config.server.is_local_testing_mode());

    // Start the server
    let listener = tokio::net::TcpListener::bind(&bind_addr)
        .await
        .map_err(|e| {
            AppError::Server(github_authorized_secrets::error::ServerError::BindError {
                address: bind_addr.clone(),
                source: e,
            })
        })?;

    info!("Server listening on {}", bind_addr);

    axum::serve(listener, app)
        .await
        .map_err(|e| AppError::Server(github_authorized_secrets::error::ServerError::StartupError(e.to_string())))?;

    Ok(())
}

/// Handle sign command for creating test JWT tokens
async fn handle_sign_command(
    repository: String,
    owner: Option<String>,
    workflow: Option<String>,
    actor: Option<String>,
    ref_name: Option<String>,
    sha: Option<String>,
    audience: Option<String>,
    server: String,
    token_only: bool,
) -> Result<(), AppError> {
    // Extract owner from repository if not provided
    let repository_owner = match owner {
        Some(o) => o,
        None => {
            let parts: Vec<&str> = repository.split('/').collect();
            if parts.len() != 2 {
                return Err(AppError::Client(
                    github_authorized_secrets::error::ClientError::InvalidInput {
                        field: "repository must be in format 'owner/repo'".to_string()
                    }
                ));
            }
            parts[0].to_string()
        }
    };

    // Validate repository format
    if !repository.contains('/') {
        return Err(AppError::Client(
            github_authorized_secrets::error::ClientError::InvalidInput {
                field: "repository must be in format 'owner/repo'".to_string()
            }
        ));
    }

    info!("Creating JWT token for repository: {}", repository);

    // Create local JWKs for signing
    let local_jwks = LocalJwks::new(1).map_err(|e| AppError::Auth(e))?;
    let signer = local_jwks.get_signer().ok_or_else(|| {
        AppError::Auth(github_authorized_secrets::error::AuthError::JwksClientError(
            "failed to get signer from local JWKs".to_string()
        ))
    })?;

    // Create test claims
    let claims = create_test_claims(
        &repository,
        &repository_owner,
        workflow.as_deref(),
        actor.as_deref(),
        ref_name.as_deref(),
        sha.as_deref(),
        audience.as_deref(),
    );

    // Sign the token
    let token = signer.sign_token(&claims).map_err(|e| AppError::Auth(e))?;

    if token_only {
        println!("{}", token);
    } else {
        println!("Generated JWT Token:");
        println!("{}", token);
        println!();

        println!("Token Claims:");
        println!("  Repository: {}", claims.repository);
        println!("  Owner: {}", claims.repository_owner);
        println!("  Workflow: {}", claims.workflow);
        println!("  Actor: {}", claims.actor);
        println!("  Ref: {}", claims.ref_);
        println!("  SHA: {}", claims.sha);
        println!("  Audience: {}", claims.aud);
        println!("  Expires: {}", chrono::DateTime::from_timestamp(claims.exp, 0)
            .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
            .unwrap_or("Invalid timestamp".to_string()));

        println!();
        println!("JWKs for validation (use this on your server):");
        println!("{}", local_jwks.to_json().map_err(|e| AppError::Auth(e))?);

        println!();
        println!("Key ID: {}", signer.key_id());
        println!();
        println!("To test this token, start the server with --local-testing and use:");
        println!("  curl -X POST -H 'Authorization: Bearer {}' http://{}/secrets", token, server);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    // TASK 12: CLI Command Parsing Tests

    #[test]
    fn test_server_command_argument_parsing() {
        // Test with default config
        let args = vec!["github-authorized-secrets", "server"];
        let cli = Cli::try_parse_from(args).unwrap();

        match cli {
            Cli::Server { config, .. } => {
                assert_eq!(config, "config.toml");
            }
            _ => panic!("Expected Server command"),
        }

        // Test with custom config
        let args = vec!["github-authorized-secrets", "server", "--config", "custom.toml"];
        let cli = Cli::try_parse_from(args).unwrap();

        match cli {
            Cli::Server { config, .. } => {
                assert_eq!(config, "custom.toml");
            }
            _ => panic!("Expected Server command"),
        }

        // Test with short config option
        let args = vec!["github-authorized-secrets", "server", "-c", "short.toml"];
        let cli = Cli::try_parse_from(args).unwrap();

        match cli {
            Cli::Server { config, .. } => {
                assert_eq!(config, "short.toml");
            }
            _ => panic!("Expected Server command"),
        }
    }

    #[test]
    fn test_pull_command_with_various_options() {
        // Test basic pull command
        let args = vec!["github-authorized-secrets", "pull", "--host", "example.com"];
        let cli = Cli::try_parse_from(args).unwrap();

        match cli {
            Cli::Pull { host, token, format, scheme, audience, prefix, uppercase } => {
                assert_eq!(host, "example.com");
                assert!(token.is_none());
                assert!(matches!(format, OutputFormat::Env)); // default
                assert_eq!(scheme, "https"); // default
                assert!(audience.is_none());
                assert!(prefix.is_none());
                assert!(!uppercase);
            }
            _ => panic!("Expected Pull command"),
        }

        // Test pull with all options
        let args = vec![
            "github-authorized-secrets", "pull",
            "--host", "api.example.com",
            "--token", "test-token",
            "--format", "json",
            "--scheme", "http",
            "--audience", "my-service",
            "--prefix", "DEPLOY_",
            "--uppercase",
        ];
        let cli = Cli::try_parse_from(args).unwrap();

        match cli {
            Cli::Pull { host, token, format, scheme, audience, prefix, uppercase } => {
                assert_eq!(host, "api.example.com");
                assert_eq!(token, Some("test-token".to_string()));
                assert!(matches!(format, OutputFormat::Json));
                assert_eq!(scheme, "http");
                assert_eq!(audience, Some("my-service".to_string()));
                assert_eq!(prefix, Some("DEPLOY_".to_string()));
                assert!(uppercase);
            }
            _ => panic!("Expected Pull command"),
        }

        // Test pull with short options
        let args = vec![
            "github-authorized-secrets", "pull",
            "--host", "short.example.com",
            "-t", "short-token",
            "-f", "bash",
        ];
        let cli = Cli::try_parse_from(args).unwrap();

        match cli {
            Cli::Pull { host, token, format, .. } => {
                assert_eq!(host, "short.example.com");
                assert_eq!(token, Some("short-token".to_string()));
                assert!(matches!(format, OutputFormat::Bash));
            }
            _ => panic!("Expected Pull command"),
        }
    }

    #[test]
    fn test_list_command_functionality() {
        // Test basic list command
        let args = vec!["github-authorized-secrets", "list", "--host", "api.example.com"];
        let cli = Cli::try_parse_from(args).unwrap();

        match cli {
            Cli::List { host, token, scheme, audience } => {
                assert_eq!(host, "api.example.com");
                assert!(token.is_none());
                assert_eq!(scheme, "https"); // default
                assert!(audience.is_none());
            }
            _ => panic!("Expected List command"),
        }

        // Test list with all options
        let args = vec![
            "github-authorized-secrets", "list",
            "--host", "list.example.com",
            "--token", "list-token",
            "--scheme", "http",
            "--audience", "list-audience",
        ];
        let cli = Cli::try_parse_from(args).unwrap();

        match cli {
            Cli::List { host, token, scheme, audience } => {
                assert_eq!(host, "list.example.com");
                assert_eq!(token, Some("list-token".to_string()));
                assert_eq!(scheme, "http");
                assert_eq!(audience, Some("list-audience".to_string()));
            }
            _ => panic!("Expected List command"),
        }

        // Test list with short options
        let args = vec![
            "github-authorized-secrets", "list",
            "--host", "short-list.example.com",
            "-t", "short-list-token",
        ];
        let cli = Cli::try_parse_from(args).unwrap();

        match cli {
            Cli::List { host, token, .. } => {
                assert_eq!(host, "short-list.example.com");
                assert_eq!(token, Some("short-list-token".to_string()));
            }
            _ => panic!("Expected List command"),
        }
    }

    #[test]
    fn test_prefix_and_uppercase_argument_parsing() {
        // Test prefix only
        let args = vec![
            "github-authorized-secrets", "pull",
            "--host", "example.com",
            "--prefix", "TEST_",
        ];
        let cli = Cli::try_parse_from(args).unwrap();

        match cli {
            Cli::Pull { prefix, uppercase, .. } => {
                assert_eq!(prefix, Some("TEST_".to_string()));
                assert!(!uppercase);
            }
            _ => panic!("Expected Pull command"),
        }

        // Test uppercase only
        let args = vec![
            "github-authorized-secrets", "pull",
            "--host", "example.com",
            "--uppercase",
        ];
        let cli = Cli::try_parse_from(args).unwrap();

        match cli {
            Cli::Pull { prefix, uppercase, .. } => {
                assert!(prefix.is_none());
                assert!(uppercase);
            }
            _ => panic!("Expected Pull command"),
        }

        // Test both prefix and uppercase
        let args = vec![
            "github-authorized-secrets", "pull",
            "--host", "example.com",
            "--prefix", "PROD_",
            "--uppercase",
        ];
        let cli = Cli::try_parse_from(args).unwrap();

        match cli {
            Cli::Pull { prefix, uppercase, .. } => {
                assert_eq!(prefix, Some("PROD_".to_string()));
                assert!(uppercase);
            }
            _ => panic!("Expected Pull command"),
        }
    }

    #[test]
    fn test_output_format_parsing() {
        let test_cases = vec![
            ("json", OutputFormat::Json),
            ("bash", OutputFormat::Bash),
            ("env", OutputFormat::Env),
            ("yaml", OutputFormat::Yaml),
        ];

        for (format_str, expected_format) in test_cases {
            let args = vec![
                "github-authorized-secrets", "pull",
                "--host", "example.com",
                "--format", format_str,
            ];
            let cli = Cli::try_parse_from(args).unwrap();

            match cli {
                Cli::Pull { format, .. } => {
                    match (format, expected_format) {
                        (OutputFormat::Json, OutputFormat::Json) => (),
                        (OutputFormat::Bash, OutputFormat::Bash) => (),
                        (OutputFormat::Env, OutputFormat::Env) => (),
                        (OutputFormat::Yaml, OutputFormat::Yaml) => (),
                        _ => panic!("Format mismatch for {}", format_str),
                    }
                }
                _ => panic!("Expected Pull command"),
            }
        }
    }

    #[test]
    #[serial]
    fn test_invalid_arguments() {
        // Clean up any HOST environment variable first
        std::env::remove_var("HOST");

        // Test missing required host argument
        let args = vec!["github-authorized-secrets", "pull"];
        let result = Cli::try_parse_from(args);
        assert!(result.is_err());

        // Test invalid format
        let args = vec![
            "github-authorized-secrets", "pull",
            "--host", "example.com",
            "--format", "invalid",
        ];
        let result = Cli::try_parse_from(args);
        assert!(result.is_err());

        // Test missing host for list command (clean environment first)
        std::env::remove_var("HOST");
        let args = vec!["github-authorized-secrets", "list"];
        let result = Cli::try_parse_from(args);
        assert!(result.is_err());
    }

    #[test]
    #[serial]
    fn test_environment_variable_support() {
        // Clean up first to ensure test isolation
        std::env::remove_var("HOST");

        // Test that HOST environment variable works for pull command
        std::env::set_var("HOST", "env.example.com");

        let args = vec!["github-authorized-secrets", "pull"];
        let cli = Cli::try_parse_from(args).unwrap();

        match cli {
            Cli::Pull { host, .. } => {
                assert_eq!(host, "env.example.com");
            }
            _ => panic!("Expected Pull command"),
        }

        // Test that HOST environment variable works for list command
        let args = vec!["github-authorized-secrets", "list"];
        let cli = Cli::try_parse_from(args).unwrap();

        match cli {
            Cli::List { host, .. } => {
                assert_eq!(host, "env.example.com");
            }
            _ => panic!("Expected List command"),
        }

        // Cleanup
        std::env::remove_var("HOST");
    }

    #[test]
    fn test_scheme_validation() {
        let schemes = vec!["http", "https"];

        for scheme in schemes {
            let args = vec![
                "github-authorized-secrets", "pull",
                "--host", "example.com",
                "--scheme", scheme,
            ];
            let cli = Cli::try_parse_from(args).unwrap();

            match cli {
                Cli::Pull { scheme: parsed_scheme, .. } => {
                    assert_eq!(parsed_scheme, scheme);
                }
                _ => panic!("Expected Pull command"),
            }
        }
    }

    #[test]
    fn test_complex_argument_combinations() {
        // Test complex combination of arguments
        let args = vec![
            "github-authorized-secrets", "pull",
            "--host", "complex.example.com",
            "--token", "complex-token-123",
            "--format", "yaml",
            "--scheme", "http",
            "--audience", "complex-audience",
            "--prefix", "COMPLEX_PREFIX_",
            "--uppercase",
        ];
        let cli = Cli::try_parse_from(args).unwrap();

        match cli {
            Cli::Pull {
                host,
                token,
                format,
                scheme,
                audience,
                prefix,
                uppercase
            } => {
                assert_eq!(host, "complex.example.com");
                assert_eq!(token, Some("complex-token-123".to_string()));
                assert!(matches!(format, OutputFormat::Yaml));
                assert_eq!(scheme, "http");
                assert_eq!(audience, Some("complex-audience".to_string()));
                assert_eq!(prefix, Some("COMPLEX_PREFIX_".to_string()));
                assert!(uppercase);
            }
            _ => panic!("Expected Pull command"),
        }
    }

    #[test]
    fn test_prefix_edge_cases() {
        // Test empty prefix (should be allowed)
        let args = vec![
            "github-authorized-secrets", "pull",
            "--host", "example.com",
            "--prefix", "",
        ];
        let cli = Cli::try_parse_from(args).unwrap();

        match cli {
            Cli::Pull { prefix, .. } => {
                assert_eq!(prefix, Some("".to_string()));
            }
            _ => panic!("Expected Pull command"),
        }

        // Test prefix with special characters
        let args = vec![
            "github-authorized-secrets", "pull",
            "--host", "example.com",
            "--prefix", "TEST_123_ABC_",
        ];
        let cli = Cli::try_parse_from(args).unwrap();

        match cli {
            Cli::Pull { prefix, .. } => {
                assert_eq!(prefix, Some("TEST_123_ABC_".to_string()));
            }
            _ => panic!("Expected Pull command"),
        }
    }

    #[test]
    fn test_help_and_version_flags() {
        // Test help flag
        let args = vec!["github-authorized-secrets", "--help"];
        let result = Cli::try_parse_from(args);
        assert!(result.is_err()); // Help flag causes early exit

        // Test version flag
        let args = vec!["github-authorized-secrets", "--version"];
        let result = Cli::try_parse_from(args);
        assert!(result.is_err()); // Version flag causes early exit

        // Test subcommand help
        let args = vec!["github-authorized-secrets", "pull", "--help"];
        let result = Cli::try_parse_from(args);
        assert!(result.is_err()); // Help flag causes early exit
    }

    #[test]
    fn test_sign_command_argument_parsing() {
        // Test basic sign command
        let args = vec!["github-authorized-secrets", "sign", "--repository", "owner/repo"];
        let cli = Cli::try_parse_from(args).unwrap();

        match cli {
            Cli::Sign { repository, owner, workflow, actor, ref_name, sha, audience, server, token_only } => {
                assert_eq!(repository, "owner/repo");
                assert!(owner.is_none());
                assert!(workflow.is_none());
                assert!(actor.is_none());
                assert!(ref_name.is_none());
                assert!(sha.is_none());
                assert!(audience.is_none());
                assert_eq!(server, "localhost:8080"); // default
                assert!(!token_only); // default
            }
            _ => panic!("Expected Sign command"),
        }

        // Test sign with all options including token_only
        let args = vec![
            "github-authorized-secrets", "sign",
            "--repository", "test/repo",
            "--owner", "test-owner",
            "--workflow", "test-workflow",
            "--actor", "test-actor",
            "--ref-name", "refs/heads/main",
            "--sha", "abc123",
            "--audience", "test-audience",
            "--server", "example.com:9000",
            "--token-only",
        ];
        let cli = Cli::try_parse_from(args).unwrap();

        match cli {
            Cli::Sign { repository, owner, workflow, actor, ref_name, sha, audience, server, token_only } => {
                assert_eq!(repository, "test/repo");
                assert_eq!(owner, Some("test-owner".to_string()));
                assert_eq!(workflow, Some("test-workflow".to_string()));
                assert_eq!(actor, Some("test-actor".to_string()));
                assert_eq!(ref_name, Some("refs/heads/main".to_string()));
                assert_eq!(sha, Some("abc123".to_string()));
                assert_eq!(audience, Some("test-audience".to_string()));
                assert_eq!(server, "example.com:9000");
                assert!(token_only);
            }
            _ => panic!("Expected Sign command"),
        }

        // Test sign with short options
        let args = vec![
            "github-authorized-secrets", "sign",
            "-r", "short/repo",
            "-o", "short-owner",
            "-w", "short-workflow",
            "-a", "short-actor",
        ];
        let cli = Cli::try_parse_from(args).unwrap();

        match cli {
            Cli::Sign { repository, owner, workflow, actor, token_only, .. } => {
                assert_eq!(repository, "short/repo");
                assert_eq!(owner, Some("short-owner".to_string()));
                assert_eq!(workflow, Some("short-workflow".to_string()));
                assert_eq!(actor, Some("short-actor".to_string()));
                assert!(!token_only); // default when not specified
            }
            _ => panic!("Expected Sign command"),
        }
    }

    #[test]
    fn test_sign_command_token_only_flag() {
        // Test token_only flag is false by default
        let args = vec!["github-authorized-secrets", "sign", "--repository", "owner/repo"];
        let cli = Cli::try_parse_from(args).unwrap();

        match cli {
            Cli::Sign { token_only, .. } => {
                assert!(!token_only);
            }
            _ => panic!("Expected Sign command"),
        }

        // Test token_only flag can be set
        let args = vec![
            "github-authorized-secrets", "sign",
            "--repository", "owner/repo",
            "--token-only",
        ];
        let cli = Cli::try_parse_from(args).unwrap();

        match cli {
            Cli::Sign { token_only, .. } => {
                assert!(token_only);
            }
            _ => panic!("Expected Sign command"),
        }
    }

    #[test]
    fn test_sign_command_required_repository() {
        // Test that repository is required
        let args = vec!["github-authorized-secrets", "sign"];
        let result = Cli::try_parse_from(args);
        assert!(result.is_err());

        // Test that repository must be provided
        let args = vec!["github-authorized-secrets", "sign", "--token-only"];
        let result = Cli::try_parse_from(args);
        assert!(result.is_err());
    }
}
