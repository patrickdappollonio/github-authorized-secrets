pub mod api;

pub use api::{ApiClient, GitHubTokenFetcher, OutputFormat, SecretMasker};

use crate::error::AppError;

/// Configuration for client command execution
pub struct ClientConfig {
    pub host: String,
    pub token: Option<String>,
    pub format: OutputFormat,
    pub scheme: String,
    pub prefix: Option<String>,
    pub uppercase: bool,
    pub audience: Option<String>,
    pub github_env: bool,
}

/// Handle client commands from CLI
pub async fn handle_client_command(config: ClientConfig) -> Result<(), AppError> {
    let client = ApiClient::new_with_audience(&config.host, &config.scheme, config.audience);

    // Distinguish between Pull and List commands
    // List commands are called with format=Json, prefix=None, uppercase=false
    let is_list_command =
        matches!(config.format, OutputFormat::Json) && config.prefix.is_none() && !config.uppercase;

    let result: Result<(), crate::error::ClientError> = if is_list_command {
        // Handle List command
        match client
            .list_repositories_with_auto_auth(config.token.as_deref())
            .await
        {
            Ok(repos_response) => {
                println!("Available repositories:");
                for repo in &repos_response.repositories {
                    println!("  - {repo}");
                }
                Ok(())
            }
            Err(e) => Err(e),
        }
    } else {
        // Handle Pull command
        match client
            .get_secrets_with_auto_auth(config.token.as_deref())
            .await
        {
            Ok(secrets_response) => {
                // Mask sensitive values in GitHub Actions logs
                SecretMasker::mask_secrets(&secrets_response.secrets);

                // Format and output the secrets
                let formatted_output = config.format.format_secrets(
                    &secrets_response.secrets,
                    config.prefix.as_deref(),
                    config.uppercase,
                );

                // Handle GitHub Environment file writing
                if config.github_env && matches!(config.format, OutputFormat::Env) {
                    if let Ok(github_env_path) = std::env::var("GITHUB_ENV") {
                        use std::io::Write;
                        match std::fs::OpenOptions::new()
                            .create(true)
                            .append(true)
                            .open(&github_env_path)
                        {
                            Ok(mut file) => {
                                if let Err(e) = writeln!(file, "{formatted_output}") {
                                    eprintln!("failed to write to GITHUB_ENV file: {e}");
                                    std::process::exit(1);
                                }
                            }
                            Err(e) => {
                                eprintln!("failed to open GITHUB_ENV file: {e}");
                                std::process::exit(1);
                            }
                        }
                    } else {
                        eprintln!("GITHUB_ENV environment variable not set");
                        std::process::exit(1);
                    }
                } else {
                    println!("{formatted_output}");
                }
                Ok(())
            }
            Err(e) => Err(e),
        }
    };

    // Convert ClientError to user-friendly messages
    if let Err(client_error) = result {
        eprintln!("Error: {}", client_error.user_friendly_message());
        std::process::exit(1);
    }

    Ok(())
}
