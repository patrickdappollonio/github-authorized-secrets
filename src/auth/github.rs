use serde::{Deserialize, Serialize};

/// GitHub Actions JWT claims structure
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct GitHubClaims {
    /// Issuer - should be "https://token.actions.githubusercontent.com"
    pub iss: String,
    /// Subject claim
    pub sub: String,
    /// Audience
    pub aud: String,
    /// Repository in "owner/repo" format
    pub repository: String,
    /// Repository owner
    pub repository_owner: String,
    /// Repository ID
    pub repository_id: String,
    /// Git reference
    #[serde(rename = "ref")]
    pub ref_: String,
    /// Commit SHA
    pub sha: String,
    /// Workflow name
    pub workflow: String,
    /// Actor who triggered the workflow
    pub actor: String,
    /// Workflow run ID
    pub run_id: String,
    /// Expiration time (Unix timestamp)
    pub exp: i64,
    /// Issued at time (Unix timestamp)
    pub iat: i64,
    /// Not before time (Unix timestamp)
    pub nbf: i64,
}

/// Configuration for JWT validation
#[derive(Debug, Clone)]
pub struct ValidationConfig {
    /// Maximum age of token in seconds
    pub max_token_age: i64,
    /// Maximum token lifetime in seconds (exp - iat)
    pub max_token_lifetime: i64,
    /// Required claims that must be present
    pub required_claims: Vec<String>,
    /// Allowed issuers
    pub allowed_issuers: Vec<String>,
}

impl Default for ValidationConfig {
    fn default() -> Self {
        Self {
            max_token_age: 300, // 5 minutes
            max_token_lifetime: 28800, // 8 hours - default for GitHub Actions OIDC tokens
            required_claims: vec![
                "repository".to_string(),
                "repository_owner".to_string(),
            ],
            allowed_issuers: vec![
                "https://token.actions.githubusercontent.com".to_string(),
            ],
        }
    }
}

/// Convert from config::types::ValidationConfig to auth::github::ValidationConfig
impl From<crate::config::types::ValidationConfig> for ValidationConfig {
    fn from(config: crate::config::types::ValidationConfig) -> Self {
        Self {
            required_claims: config.required_claims.unwrap_or_else(|| {
                vec!["repository".to_string(), "repository_owner".to_string()]
            }),
            allowed_issuers: config.allowed_issuers.unwrap_or_else(|| {
                vec!["https://token.actions.githubusercontent.com".to_string()]
            }),
            max_token_age: config.max_token_age.unwrap_or(300) as i64,
            max_token_lifetime: config.max_token_lifetime.unwrap_or(28800) as i64,
        }
    }
}
