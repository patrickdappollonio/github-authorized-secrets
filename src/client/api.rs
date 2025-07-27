use crate::error::ClientError;
use crate::secrets::{RepositoryListResponse, SecretsResponse};
use reqwest::Client;
use serde::Deserialize;
use std::collections::HashMap;
use std::time::Duration;

/// GitHub Actions token fetcher with optimized HTTP client
pub struct GitHubTokenFetcher {
    client: Client,
}

impl GitHubTokenFetcher {
    /// Create a new token fetcher with optimized HTTP client
    pub fn new() -> Self {
        let client = Self::create_optimized_client();

        Self {
            client,
        }
    }

    /// Create an optimized HTTP client with connection pooling
    fn create_optimized_client() -> Client {
        Client::builder()
            .pool_max_idle_per_host(5) // GitHub Actions doesn't need as many connections
            .pool_idle_timeout(Duration::from_secs(30))
            .timeout(Duration::from_secs(10))
            .connect_timeout(Duration::from_secs(5))
            .tcp_keepalive(Duration::from_secs(60))
            .user_agent("github-authorized-secrets/0.1.0")
            .build()
            .expect("failed to create HTTP client")
    }

    /// Fetch GitHub Actions ID token
    ///
    /// This method automatically fetches a JWT token from the GitHub Actions environment
    /// using the ACTIONS_ID_TOKEN_REQUEST_URL and ACTIONS_ID_TOKEN_REQUEST_TOKEN environment variables.
    ///
    /// # Arguments
    /// * `audience` - Optional audience parameter to include in the token request
    ///
    /// # Returns
    /// * `Ok(String)` - The JWT token from GitHub Actions
    /// * `Err(ClientError)` - Error if not in GitHub Actions environment or token fetch fails
    pub async fn fetch_token(&self, audience: Option<&str>) -> Result<String, ClientError> {
        // Check if we're running in GitHub Actions environment
        let token_url = std::env::var("ACTIONS_ID_TOKEN_REQUEST_URL")
            .map_err(|_| ClientError::NotInGitHubActions)?;

        let request_token = std::env::var("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
            .map_err(|_| ClientError::NotInGitHubActions)?;

        // Build the request URL with optional audience parameter
        let mut url = token_url;
        if let Some(aud) = audience {
            url = format!("{}&audience={}", url, urlencoding::encode(aud));
        }

        // Make the request to GitHub Actions token endpoint
        let response = self
            .client
            .get(&url)
            .bearer_auth(&request_token)
            .send()
            .await?;

        // Check if the request was successful
        if !response.status().is_success() {
            return Err(ClientError::TokenFetchFailed {
                status: response.status(),
            });
        }

        // Parse the token response
        let token_response: TokenResponse = response
            .json()
            .await
            .map_err(|_| ClientError::InvalidTokenResponse)?;

        Ok(token_response.value)
    }

    /// Check if we're running in a GitHub Actions environment
    ///
    /// This method checks for the presence of required GitHub Actions environment variables
    /// without actually making a token request.
    ///
    /// # Returns
    /// * `true` if all required environment variables are present
    /// * `false` if any required environment variables are missing
    pub fn is_github_actions_environment(&self) -> bool {
        std::env::var("ACTIONS_ID_TOKEN_REQUEST_URL").is_ok()
            && std::env::var("ACTIONS_ID_TOKEN_REQUEST_TOKEN").is_ok()
    }
}

/// API client for interacting with the secrets server with optimized HTTP client
pub struct ApiClient {
    base_url: String,
    client: Client,
    token_fetcher: GitHubTokenFetcher,
}

impl ApiClient {
    /// Create a new API client with optimized HTTP client
    pub fn new(host: &str, scheme: &str) -> Self {
        let base_url = format!("{}://{}", scheme, host);
        let client = Self::create_optimized_client();

        Self {
            base_url,
            client,
            token_fetcher: GitHubTokenFetcher::new(),
        }
    }

    /// Create an optimized HTTP client with connection pooling
    fn create_optimized_client() -> Client {
        Client::builder()
            .pool_max_idle_per_host(10) // Server connections benefit from more pooling
            .pool_idle_timeout(Duration::from_secs(30))
            .timeout(Duration::from_secs(30)) // Longer timeout for secret operations
            .connect_timeout(Duration::from_secs(10))
            .tcp_keepalive(Duration::from_secs(60))
            .user_agent("github-authorized-secrets/0.1.0")
            .gzip(true) // Enable compression
            .build()
            .expect("failed to create HTTP client")
    }

    /// Get secrets with automatic authentication
    ///
    /// This method will attempt to use the provided token first, and if none is provided,
    /// it will automatically fetch a token from the GitHub Actions environment.
    ///
    /// # Arguments
    /// * `token` - Optional manual token to use instead of auto-fetching
    /// * `audience` - Optional audience parameter for token requests
    ///
    /// # Returns
    /// * `Ok(SecretsResponse)` - The secrets response from the server
    /// * `Err(ClientError)` - Error if authentication or request fails
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

    /// Get secrets with provided token
    ///
    /// This method makes a direct request to the secrets endpoint using the provided token.
    ///
    /// # Arguments
    /// * `token` - JWT token for authentication
    ///
    /// # Returns
    /// * `Ok(SecretsResponse)` - The secrets response from the server
    /// * `Err(ClientError)` - Error if request fails or token is invalid
    pub async fn get_secrets(&self, token: &str) -> Result<SecretsResponse, ClientError> {
        let response = self
            .client
            .post(&format!("{}/secrets", self.base_url))
            .bearer_auth(token)
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(ClientError::ApiError {
                status: response.status(),
            });
        }

        Ok(response.json().await?)
    }

    /// List repositories with automatic authentication
    ///
    /// This method will attempt to use the provided token first, and if none is provided,
    /// it will automatically fetch a token from the GitHub Actions environment.
    ///
    /// # Arguments
    /// * `token` - Optional manual token to use instead of auto-fetching
    /// * `audience` - Optional audience parameter for token requests
    ///
    /// # Returns
    /// * `Ok(RepositoryListResponse)` - The list of available repositories
    /// * `Err(ClientError)` - Error if authentication or request fails
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

    /// List repositories with provided token
    ///
    /// This method makes a direct request to the repositories endpoint using the provided token.
    ///
    /// # Arguments
    /// * `token` - JWT token for authentication
    ///
    /// # Returns
    /// * `Ok(RepositoryListResponse)` - The list of available repositories
    /// * `Err(ClientError)` - Error if request fails or token is invalid
    pub async fn list_repositories(
        &self,
        token: &str,
    ) -> Result<RepositoryListResponse, ClientError> {
        let response = self
            .client
            .get(&format!("{}/secrets/repositories", self.base_url))
            .bearer_auth(token)
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(ClientError::ApiError {
                status: response.status(),
            });
        }

        Ok(response.json().await?)
    }
}

/// Output format for secrets
#[derive(Clone, clap::ValueEnum)]
pub enum OutputFormat {
    Json,
    Bash,
    Env,
    Yaml,
}

impl OutputFormat {
    /// Format secrets according to the output format
    pub fn format_secrets(
        &self,
        secrets: &HashMap<String, String>,
        prefix: Option<&str>,
        uppercase: bool,
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
                serde_json::to_string_pretty(&transformed_secrets)
                    .unwrap_or_else(|_| "{}".to_string())
            }
            OutputFormat::Bash => secrets
                .iter()
                .map(|(key, value)| {
                    let transformed_key = transform_key(key);
                    format!(
                        "export {}={}",
                        transformed_key,
                        shell_escape::escape(value.into())
                    )
                })
                .collect::<Vec<_>>()
                .join("\n"),
            OutputFormat::Env => secrets
                .iter()
                .map(|(key, value)| {
                    let transformed_key = transform_key(key);
                    format!("{}={}", transformed_key, value)
                })
                .collect::<Vec<_>>()
                .join("\n"),
            OutputFormat::Yaml => {
                let transformed_secrets: HashMap<String, String> = secrets
                    .iter()
                    .map(|(key, value)| (transform_key(key), value.clone()))
                    .collect();
                serde_yaml::to_string(&transformed_secrets)
                    .unwrap_or_else(|_| "---\n{}\n".to_string())
            }
        }
    }
}

/// Secret masking utilities for GitHub Actions
pub struct SecretMasker;

impl SecretMasker {
    /// Mask secrets in GitHub Actions logs
    pub fn mask_secrets(secrets: &HashMap<String, String>) {
        if std::env::var("GITHUB_ACTIONS").is_ok() {
            for (_, value) in secrets {
                Self::mask_value(value);
            }
        }
    }

    /// Mask a single value
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

#[derive(Deserialize)]
struct TokenResponse {
    value: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// Create test secrets that match the github.octocat section in test_config.toml
    fn test_secrets() -> HashMap<String, String> {
        let mut secrets = HashMap::new();
        secrets.insert("api_key".to_string(), "test_api_key_123".to_string());
        secrets.insert(
            "database_url".to_string(),
            "postgresql://test:pass@localhost/testdb".to_string(),
        );
        secrets.insert(
            "deployment_token".to_string(),
            "ghp_test_deployment_token".to_string(),
        );
        secrets
    }

    /// Setup GitHub Actions environment variables for testing
    fn setup_github_actions_env(token_url: &str, request_token: &str) {
        std::env::set_var("ACTIONS_ID_TOKEN_REQUEST_URL", token_url);
        std::env::set_var("ACTIONS_ID_TOKEN_REQUEST_TOKEN", request_token);
        std::env::set_var("GITHUB_ACTIONS", "true");
    }

    /// Clean up GitHub Actions environment variables
    fn cleanup_github_actions_env() {
        std::env::remove_var("ACTIONS_ID_TOKEN_REQUEST_URL");
        std::env::remove_var("ACTIONS_ID_TOKEN_REQUEST_TOKEN");
        std::env::remove_var("GITHUB_ACTIONS");
    }

    // TASK 12: CLI Testing and Output Validation

    #[test]
    fn test_output_formatting() {
        // Use the test secrets that match test_config.toml
        let secrets = test_secrets();

        // Basic formatting without transformations
        let bash_output = OutputFormat::Bash.format_secrets(&secrets, None, false);
        assert!(bash_output.contains("export api_key="));
        assert!(bash_output.contains("export database_url="));
        assert!(bash_output.contains("export deployment_token="));

        let env_output = OutputFormat::Env.format_secrets(&secrets, None, false);
        assert!(env_output.contains("api_key=test_api_key_123"));
        assert!(env_output.contains("database_url=postgresql://test:pass@localhost/testdb"));

        let json_output = OutputFormat::Json.format_secrets(&secrets, None, false);
        let parsed: serde_json::Value = serde_json::from_str(&json_output).unwrap();
        assert_eq!(parsed["api_key"], "test_api_key_123");
        assert_eq!(parsed["deployment_token"], "ghp_test_deployment_token");
    }

    #[test]
    fn test_output_formatting_with_prefix_and_uppercase() {
        let secrets = test_secrets();

        // Test with prefix and uppercase
        let bash_output = OutputFormat::Bash.format_secrets(&secrets, Some("DEPLOY_"), true);
        assert!(bash_output.contains("export DEPLOY_API_KEY="));
        assert!(bash_output.contains("export DEPLOY_DATABASE_URL="));
        assert!(bash_output.contains("export DEPLOY_DEPLOYMENT_TOKEN="));

        let env_output = OutputFormat::Env.format_secrets(&secrets, Some("APP_"), true);
        assert!(env_output.contains("APP_API_KEY=test_api_key_123"));
        assert!(env_output.contains("APP_DATABASE_URL=postgresql://test:pass@localhost/testdb"));
        assert!(env_output.contains("APP_DEPLOYMENT_TOKEN=ghp_test_deployment_token"));

        let json_output = OutputFormat::Json.format_secrets(&secrets, Some("PREFIX_"), true);
        let parsed: serde_json::Value = serde_json::from_str(&json_output).unwrap();
        assert_eq!(parsed["PREFIX_API_KEY"], "test_api_key_123");
        assert_eq!(
            parsed["PREFIX_DATABASE_URL"],
            "postgresql://test:pass@localhost/testdb"
        );

        // Test with only uppercase
        let yaml_output = OutputFormat::Yaml.format_secrets(&secrets, None, true);
        assert!(yaml_output.contains("API_KEY:"));
        assert!(yaml_output.contains("DATABASE_URL:"));

        // Test with only prefix
        let env_output_prefix_only =
            OutputFormat::Env.format_secrets(&secrets, Some("TEST_"), false);
        assert!(env_output_prefix_only.contains("TEST_api_key=test_api_key_123"));
        assert!(env_output_prefix_only
            .contains("TEST_database_url=postgresql://test:pass@localhost/testdb"));
    }

    #[test]
    fn test_json_output_structure_and_validity() {
        let secrets = test_secrets();

        // Test basic JSON structure
        let json_output = OutputFormat::Json.format_secrets(&secrets, None, false);
        let parsed: serde_json::Value = serde_json::from_str(&json_output).unwrap();

        // Verify all keys from test_secrets() are present
        assert!(parsed.get("api_key").is_some());
        assert!(parsed.get("database_url").is_some());
        assert!(parsed.get("deployment_token").is_some());
        assert_eq!(parsed["api_key"], "test_api_key_123");
        assert_eq!(
            parsed["database_url"],
            "postgresql://test:pass@localhost/testdb"
        );
        assert_eq!(parsed["deployment_token"], "ghp_test_deployment_token");

        // Test with transformations
        let json_with_prefix = OutputFormat::Json.format_secrets(&secrets, Some("TEST_"), true);
        let parsed_with_prefix: serde_json::Value =
            serde_json::from_str(&json_with_prefix).unwrap();

        assert!(parsed_with_prefix.get("TEST_API_KEY").is_some());
        assert!(parsed_with_prefix.get("TEST_DATABASE_URL").is_some());
        assert_eq!(parsed_with_prefix["TEST_API_KEY"], "test_api_key_123");

        // Verify JSON is well-formed
        assert!(json_output.starts_with('{'));
        assert!(json_output.ends_with('}'));
    }

    #[test]
    fn test_bash_export_format_with_special_characters() {
        let secrets = test_secrets();

        // Test bash output format
        let bash_output = OutputFormat::Bash.format_secrets(&secrets, None, false);

        // Verify all exports are present
        assert!(bash_output.contains("export api_key="));
        assert!(bash_output.contains("export database_url="));
        assert!(bash_output.contains("export deployment_token="));

        // Verify proper escaping by checking each line
        let lines: Vec<&str> = bash_output.lines().collect();
        for line in lines {
            if line.contains("export ") {
                // Each line should be valid bash export syntax
                assert!(line.starts_with("export "));
                assert!(line.contains("="));
            }
        }

        // Test with prefix and uppercase
        let bash_with_transformations =
            OutputFormat::Bash.format_secrets(&secrets, Some("PROD_"), true);

        assert!(bash_with_transformations.contains("export PROD_API_KEY="));
        assert!(bash_with_transformations.contains("export PROD_DATABASE_URL="));
    }

    #[test]
    fn test_environment_variable_format() {
        let secrets = test_secrets();

        // Test env format
        let env_output = OutputFormat::Env.format_secrets(&secrets, None, false);

        // Check basic structure
        let lines: Vec<&str> = env_output.lines().filter(|line| !line.is_empty()).collect();
        assert!(!lines.is_empty());

        for line in lines {
            // Each line should have key=value format
            assert!(line.contains("="));
            let parts: Vec<&str> = line.split('=').collect();
            assert!(parts.len() >= 2); // Allow for = in values
        }

        // Test with prefix and uppercase
        let env_with_transformations =
            OutputFormat::Env.format_secrets(&secrets, Some("CI_"), true);

        assert!(env_with_transformations.contains("CI_API_KEY="));
        assert!(env_with_transformations.contains("CI_DATABASE_URL="));
        assert!(env_with_transformations.contains("CI_DEPLOYMENT_TOKEN="));
    }

    #[test]
    fn test_yaml_output_format() {
        let secrets = test_secrets();

        // Test YAML format
        let yaml_output = OutputFormat::Yaml.format_secrets(&secrets, None, false);

        // Verify YAML structure
        assert!(yaml_output.contains(":"));

        // Parse YAML to verify validity
        let parsed: serde_yaml::Value = serde_yaml::from_str(&yaml_output).unwrap();

        // Verify all keys are present
        assert!(parsed.get("api_key").is_some());
        assert!(parsed.get("database_url").is_some());
        assert!(parsed.get("deployment_token").is_some());

        // Test with transformations
        let yaml_with_transformations =
            OutputFormat::Yaml.format_secrets(&secrets, Some("DEPLOY_"), true);

        let parsed_transformed: serde_yaml::Value =
            serde_yaml::from_str(&yaml_with_transformations).unwrap();
        assert!(parsed_transformed.get("DEPLOY_API_KEY").is_some());
        assert!(parsed_transformed.get("DEPLOY_DATABASE_URL").is_some());
    }

    #[test]
    fn test_key_prefix_functionality_across_all_formats() {
        let secrets = test_secrets();
        let prefix = "MYAPP_";

        // Test prefix in JSON
        let json_output = OutputFormat::Json.format_secrets(&secrets, Some(prefix), false);
        let parsed: serde_json::Value = serde_json::from_str(&json_output).unwrap();
        assert!(parsed.get("MYAPP_api_key").is_some());
        assert!(parsed.get("MYAPP_database_url").is_some());
        assert!(parsed.get("api_key").is_none());

        // Test prefix in Bash
        let bash_output = OutputFormat::Bash.format_secrets(&secrets, Some(prefix), false);
        assert!(bash_output.contains("export MYAPP_api_key="));
        assert!(bash_output.contains("export MYAPP_database_url="));
        assert!(!bash_output.contains("export api_key="));

        // Test prefix in Env
        let env_output = OutputFormat::Env.format_secrets(&secrets, Some(prefix), false);
        assert!(env_output.contains("MYAPP_api_key="));
        assert!(env_output.contains("MYAPP_database_url="));
        // Make sure original keys without prefix are not present
        let lines: Vec<&str> = env_output.lines().collect();
        let has_original_key = lines.iter().any(|line| line.starts_with("api_key="));
        assert!(!has_original_key);

        // Test prefix in YAML
        let yaml_output = OutputFormat::Yaml.format_secrets(&secrets, Some(prefix), false);
        let parsed_yaml: serde_yaml::Value = serde_yaml::from_str(&yaml_output).unwrap();
        assert!(parsed_yaml.get("MYAPP_api_key").is_some());
        assert!(parsed_yaml.get("MYAPP_database_url").is_some());
        assert!(parsed_yaml.get("api_key").is_none());
    }

    #[test]
    fn test_uppercase_transformation_functionality() {
        let secrets = test_secrets();

        // Test uppercase in JSON
        let json_output = OutputFormat::Json.format_secrets(&secrets, None, true);
        let parsed: serde_json::Value = serde_json::from_str(&json_output).unwrap();
        assert!(parsed.get("API_KEY").is_some());
        assert!(parsed.get("DATABASE_URL").is_some());
        assert!(parsed.get("DEPLOYMENT_TOKEN").is_some());
        assert!(parsed.get("api_key").is_none());

        // Test uppercase in Bash
        let bash_output = OutputFormat::Bash.format_secrets(&secrets, None, true);
        assert!(bash_output.contains("export API_KEY="));
        assert!(bash_output.contains("export DATABASE_URL="));
        assert!(!bash_output.contains("export api_key="));

        // Test uppercase in Env
        let env_output = OutputFormat::Env.format_secrets(&secrets, None, true);
        assert!(env_output.contains("API_KEY="));
        assert!(env_output.contains("DATABASE_URL="));
        assert!(!env_output.contains("api_key="));

        // Test uppercase in YAML
        let yaml_output = OutputFormat::Yaml.format_secrets(&secrets, None, true);
        let parsed_yaml: serde_yaml::Value = serde_yaml::from_str(&yaml_output).unwrap();
        assert!(parsed_yaml.get("API_KEY").is_some());
        assert!(parsed_yaml.get("DATABASE_URL").is_some());
        assert!(parsed_yaml.get("api_key").is_none());
    }

    #[test]
    fn test_combined_prefix_and_uppercase_transformations() {
        let secrets = test_secrets();
        let prefix = "prod_";

        // Test combined transformations in all formats
        let json_output = OutputFormat::Json.format_secrets(&secrets, Some(prefix), true);
        let parsed: serde_json::Value = serde_json::from_str(&json_output).unwrap();

        // The current implementation applies uppercase first, then prefix
        // So "api_key" -> "API_KEY" -> "prod_API_KEY"
        assert!(parsed.get("prod_API_KEY").is_some());
        assert!(parsed.get("prod_DATABASE_URL").is_some());
        assert!(parsed.get("prod_DEPLOYMENT_TOKEN").is_some());
        assert!(parsed.get("api_key").is_none());
        assert!(parsed.get("prod_api_key").is_none());

        let bash_output = OutputFormat::Bash.format_secrets(&secrets, Some(prefix), true);
        assert!(bash_output.contains("export prod_API_KEY="));
        assert!(bash_output.contains("export prod_DATABASE_URL="));

        let env_output = OutputFormat::Env.format_secrets(&secrets, Some(prefix), true);
        assert!(env_output.contains("prod_API_KEY="));
        assert!(env_output.contains("prod_DATABASE_URL="));

        let yaml_output = OutputFormat::Yaml.format_secrets(&secrets, Some(prefix), true);
        let parsed_yaml: serde_yaml::Value = serde_yaml::from_str(&yaml_output).unwrap();
        assert!(parsed_yaml.get("prod_API_KEY").is_some());
        assert!(parsed_yaml.get("prod_DATABASE_URL").is_some());
    }

    #[tokio::test]
    async fn test_github_token_fetcher_environment_detection() {
        let token_fetcher = GitHubTokenFetcher::new();

        // First clean up any existing environment variables
        cleanup_github_actions_env();

        // Test when not in GitHub Actions environment
        assert!(!token_fetcher.is_github_actions_environment());

        // Test when in GitHub Actions environment
        setup_github_actions_env("https://mock.url", "mock_token");
        assert!(token_fetcher.is_github_actions_environment());

        // Clean up after test
        cleanup_github_actions_env();
    }

    #[tokio::test]
    async fn test_github_token_fetcher_not_in_github_actions() {
        let token_fetcher = GitHubTokenFetcher::new();

        // Ensure we're not in GitHub Actions environment
        cleanup_github_actions_env();

        // Test token fetching should fail
        let result = token_fetcher.fetch_token(None).await;
        assert!(matches!(result, Err(ClientError::NotInGitHubActions)));

        let result_with_audience = token_fetcher.fetch_token(Some("test-audience")).await;
        assert!(matches!(
            result_with_audience,
            Err(ClientError::NotInGitHubActions)
        ));
    }

    #[test]
    fn test_secret_masker_github_actions_detection() {
        let secrets = test_secrets();

        // Test when not in GitHub Actions environment
        cleanup_github_actions_env();

        // This should not panic and should not output masking commands
        SecretMasker::mask_secrets(&secrets);

        // Test when in GitHub Actions environment
        std::env::set_var("GITHUB_ACTIONS", "true");

        // This should not panic and should output masking commands to stdout
        SecretMasker::mask_secrets(&secrets);

        cleanup_github_actions_env();
    }

    #[test]
    fn test_api_client_creation() {
        let client = ApiClient::new("example.com", "https");
        assert_eq!(client.base_url, "https://example.com");

        let client_http = ApiClient::new("localhost:8080", "http");
        assert_eq!(client_http.base_url, "http://localhost:8080");
    }

    #[test]
    fn test_output_format_edge_cases() {
        // Test with empty secrets
        let empty_secrets = HashMap::new();

        let json_output = OutputFormat::Json.format_secrets(&empty_secrets, None, false);
        let parsed: serde_json::Value = serde_json::from_str(&json_output).unwrap();
        assert!(parsed.is_object());
        assert_eq!(parsed.as_object().unwrap().len(), 0);

        let bash_output = OutputFormat::Bash.format_secrets(&empty_secrets, None, false);
        assert!(bash_output.is_empty());

        let env_output = OutputFormat::Env.format_secrets(&empty_secrets, None, false);
        assert!(env_output.is_empty());

        let yaml_output = OutputFormat::Yaml.format_secrets(&empty_secrets, None, false);
        let parsed_yaml: serde_yaml::Value = serde_yaml::from_str(&yaml_output).unwrap();
        assert!(parsed_yaml.is_mapping());

        // Test with secrets containing empty values
        let mut secrets_with_empty = HashMap::new();
        secrets_with_empty.insert("empty_key".to_string(), "".to_string());
        secrets_with_empty.insert("non_empty_key".to_string(), "value".to_string());

        let json_empty = OutputFormat::Json.format_secrets(&secrets_with_empty, None, false);
        let parsed_empty: serde_json::Value = serde_json::from_str(&json_empty).unwrap();
        assert_eq!(parsed_empty["empty_key"], "");
        assert_eq!(parsed_empty["non_empty_key"], "value");

        let bash_empty = OutputFormat::Bash.format_secrets(&secrets_with_empty, None, false);
        assert!(bash_empty.contains("export empty_key="));
        assert!(bash_empty.contains("export non_empty_key="));
    }

    #[test]
    fn test_prefix_validation_edge_cases() {
        let secrets = test_secrets();

        // Test with various prefix formats
        let prefixes = vec!["", "_", "PREFIX_", "123_", "UPPER", "lower", "Mixed_Case_"];

        for prefix in prefixes {
            let json_output = OutputFormat::Json.format_secrets(
                &secrets,
                if prefix.is_empty() {
                    None
                } else {
                    Some(prefix)
                },
                false,
            );
            let parsed: serde_json::Value = serde_json::from_str(&json_output).unwrap();

            let expected_key = if prefix.is_empty() {
                "api_key".to_string()
            } else {
                format!("{}api_key", prefix)
            };

            assert!(parsed.get(&expected_key).is_some());
        }
    }

    #[test]
    fn test_uppercase_transformation_edge_cases() {
        let mut secrets = HashMap::new();
        secrets.insert("".to_string(), "empty_key_value".to_string());
        secrets.insert("123".to_string(), "numeric_key_value".to_string());
        secrets.insert(
            "key_with_underscores".to_string(),
            "underscore_value".to_string(),
        );
        secrets.insert("ALREADY_UPPER".to_string(), "upper_value".to_string());

        let json_output = OutputFormat::Json.format_secrets(&secrets, None, true);
        let parsed: serde_json::Value = serde_json::from_str(&json_output).unwrap();

        assert!(parsed.get("").is_some()); // Empty key stays empty
        assert!(parsed.get("123").is_some()); // Numeric keys stay same
        assert!(parsed.get("KEY_WITH_UNDERSCORES").is_some());
        assert!(parsed.get("ALREADY_UPPER").is_some());
    }
}
