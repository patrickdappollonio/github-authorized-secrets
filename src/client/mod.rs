pub mod api;

pub use api::{ApiClient, GitHubTokenFetcher, OutputFormat, SecretMasker};

use crate::error::AppError;

/// Handle client commands from CLI
pub async fn handle_client_command(
    host: String,
    token: Option<String>,
    format: OutputFormat,
    scheme: String,
    audience: Option<String>,
    prefix: Option<String>,
    uppercase: bool,
) -> Result<(), AppError> {
    let client = ApiClient::new(&host, &scheme);

    // Distinguish between Pull and List commands
    // List commands are called with format=Json, prefix=None, uppercase=false
    let is_list_command = matches!(format, OutputFormat::Json) && prefix.is_none() && !uppercase;

    if is_list_command {
        // Handle List command
        let repos_response = client
            .list_repositories_with_auto_auth(token.as_deref(), audience.as_deref())
            .await?;

        println!("Available repositories:");
        for repo in &repos_response.repositories {
            println!("  - {}", repo);
        }
    } else {
        // Handle Pull command
        let secrets_response = client
            .get_secrets_with_auto_auth(token.as_deref(), audience.as_deref())
            .await?;

        // Mask sensitive values in GitHub Actions logs
        SecretMasker::mask_secrets(&secrets_response.secrets);

        // Format and output the secrets
        let formatted_output =
            format.format_secrets(&secrets_response.secrets, prefix.as_deref(), uppercase);

        println!("{}", formatted_output);
    }

    Ok(())
}
