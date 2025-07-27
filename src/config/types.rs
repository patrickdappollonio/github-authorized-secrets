use crate::security::InputValidator;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
    pub server: ServerConfig,
    pub validation: Option<ValidationConfig>,
    #[serde(flatten)]
    pub repositories: HashMap<String, HashMap<String, String>>,
}

impl Config {
    /// Check if we're in production mode - simplified version
    pub fn is_production_mode(&self) -> bool {
        // Simple heuristic - if we're not in local testing mode, consider it production
        !self.server.is_local_testing_mode()
    }

    /// Validate configuration - simplified without security policy enforcement
    pub fn validate_security(&self) -> Result<(), String> {
        // Just do basic validation without policy enforcement
        let validator = InputValidator::new(self.is_production_mode());

        // Validate repository names in the configuration
        for repo_key in self.repositories.keys() {
            // Convert "owner.repo" format to "owner/repo" for validation
            let repo_name = repo_key.replace('.', "/");
            validator
                .validate_repository(&repo_name)
                .map_err(|e| format!("Invalid repository name '{repo_key}': {e}"))?;
        }

        Ok(())
    }

    /// Load configuration from file path
    pub fn from_file(path: &str) -> Result<Self, crate::error::ConfigError> {
        crate::config::ConfigLoader::from_file(path)
    }

    /// Get secrets for a specific repository
    /// Converts "owner/repo" format to "owner.repo" for lookup
    pub fn get_secrets(&self, repository: &str) -> Option<&HashMap<String, String>> {
        // Only accept "owner/repo" format - reject internal "owner.repo" format
        if !repository.contains('/') {
            return None;
        }

        // Convert "owner/repo" format to "owner.repo" for TOML key lookup
        let key = repository.replace('/', ".");
        self.repositories.get(&key)
    }
}

/// Server configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub jwt_cache_duration: u64,
    pub local_testing_mode: Option<bool>,
    pub local_testing_num_keys: Option<usize>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".to_string(),
            port: 8080,
            jwt_cache_duration: 300,
            local_testing_mode: None,
            local_testing_num_keys: None,
        }
    }
}

impl ServerConfig {
    /// Check if local testing mode is enabled
    pub fn is_local_testing_mode(&self) -> bool {
        self.local_testing_mode.unwrap_or(false)
    }

    /// Validate server configuration - simplified
    pub fn validate(&self) -> Result<(), String> {
        let validator = InputValidator::default();

        // Just validate host format
        validator
            .validate_host(&self.host)
            .map_err(|e| format!("Invalid server host: {e}"))?;

        // Basic port validation
        if self.port == 0 {
            return Err("Server port cannot be 0".to_string());
        }

        Ok(())
    }
}

/// Validation configuration (optional)
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ValidationConfig {
    pub required_claims: Option<Vec<String>>,
    pub allowed_issuers: Option<Vec<String>>,
    pub max_token_age: Option<u64>,
    pub max_token_lifetime: Option<u64>,
}

impl Default for ValidationConfig {
    fn default() -> Self {
        Self {
            required_claims: Some(vec![
                "repository".to_string(),
                "repository_owner".to_string(),
            ]),
            allowed_issuers: Some(vec![
                "https://token.actions.githubusercontent.com".to_string()
            ]),
            max_token_age: Some(300),
            max_token_lifetime: Some(28800), // 8 hours - default for GitHub Actions OIDC tokens
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_default() {
        let config = Config {
            server: ServerConfig::default(),
            validation: None,
            repositories: HashMap::new(),
        };

        assert_eq!(config.server.host, "127.0.0.1");
        assert_eq!(config.server.port, 8080);
        assert_eq!(config.server.jwt_cache_duration, 300);
        assert!(!config.server.is_local_testing_mode());
    }

    #[test]
    fn test_server_config_validation() {
        let mut server = ServerConfig::default();
        assert!(server.validate().is_ok());

        // Test invalid port
        server.port = 0;
        assert!(server.validate().is_err());

        // Test invalid host
        server.port = 8080; // Reset
        server.host = "".to_string();
        assert!(server.validate().is_err());
    }

    #[test]
    fn test_production_mode() {
        let mut config = Config {
            server: ServerConfig::default(),
            validation: None,
            repositories: HashMap::new(),
        };

        // Not local testing = production mode
        assert!(config.is_production_mode());

        // Local testing = not production mode
        config.server.local_testing_mode = Some(true);
        assert!(!config.is_production_mode());
    }

    #[test]
    fn test_repository_validation() {
        let config = Config {
            server: ServerConfig::default(),
            validation: None,
            repositories: {
                let mut repos = HashMap::new();
                repos.insert("github.octocat".to_string(), {
                    let mut secrets = HashMap::new();
                    secrets.insert("api_key".to_string(), "secret123".to_string());
                    secrets
                });
                // Test invalid repository key format
                repos.insert("invalid_format".to_string(), HashMap::new());
                repos
            },
        };

        // Should fail validation due to invalid repository name
        assert!(config.validate_security().is_err());
    }
}
