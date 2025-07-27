use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use crate::error::ConfigError;
use crate::security::InputValidator;

/// Main configuration structure
#[derive(Debug, Serialize, Clone)]
pub struct Config {
    /// Server configuration
    pub server: ServerConfig,
    /// Validation configuration (optional)
    pub validation: Option<ValidationConfig>,
    /// Security configuration (optional)
    pub security: Option<SecurityConfig>,
    /// Repository secrets mapping - flattened from TOML sections
    pub repositories: HashMap<String, HashMap<String, String>>,
}

impl Config {
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

    /// Validate configuration security settings
    pub fn validate_security(&self) -> Result<(), ConfigError> {
        let validator = InputValidator::new(self.is_production_mode());

        // Validate all repository keys
        for repo_key in self.repositories.keys() {
            validator.validate_config_key(repo_key)
                .map_err(|e| ConfigError::ValidationError {
                    message: format!("invalid repository key {}: {}", repo_key, e)
                })?;
        }

        // Validate secret keys and values
        for (repo_key, secrets) in &self.repositories {
            for (secret_key, secret_value) in secrets {
                validator.validate_config_key(secret_key)
                    .map_err(|e| ConfigError::ValidationError {
                        message: format!("invalid secret key {} in {}: {}", secret_key, repo_key, e)
                    })?;

                validator.validate_secret_value(secret_value)
                    .map_err(|e| ConfigError::ValidationError {
                        message: format!("invalid secret value for {} in {}: {}", secret_key, repo_key, e)
                    })?;
            }
        }

        // Validate server configuration
        validator.validate_host(&self.server.host)
            .map_err(|_e| ConfigError::InvalidHost {
                host: self.server.host.clone()
            })?;

        // Check for insecure configurations
        if self.is_production_mode() {
            if self.server.host == "0.0.0.0" && !self.security.as_ref().map(|s| s.allow_insecure_host).unwrap_or(false) {
                return Err(ConfigError::InsecureConfig {
                    issue: "binding to 0.0.0.0 in production without explicit allow_insecure_host setting".to_string()
                });
            }

            if self.server.port == 80 || self.server.port == 8080 {
                return Err(ConfigError::InsecureConfig {
                    issue: "using insecure HTTP port in production".to_string()
                });
            }
        }

        Ok(())
    }

    /// Check if running in production mode
    pub fn is_production_mode(&self) -> bool {
        self.security.as_ref()
            .map(|s| s.production_mode)
            .unwrap_or_else(|| std::env::var("RUST_ENV") == Ok("production".to_string()))
    }

    /// Get security configuration or defaults
    pub fn get_security_config(&self) -> SecurityConfig {
        self.security.clone().unwrap_or_default()
    }
}

/// Server configuration
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ServerConfig {
    /// Host to bind to
    pub host: String,
    /// Port to bind to
    pub port: u16,
    /// JWT cache duration in seconds
    pub jwt_cache_duration: u64,
    /// Enable TLS (HTTPS)
    pub enable_tls: Option<bool>,
    /// TLS certificate file path
    pub tls_cert_path: Option<String>,
    /// TLS private key file path
    pub tls_key_path: Option<String>,
    /// Enable local testing mode with generated JWKs
    pub local_testing_mode: Option<bool>,
    /// Number of RSA key pairs to generate for local testing
    pub local_testing_num_keys: Option<usize>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".to_string(),
            port: 8080,
            jwt_cache_duration: 300,
            enable_tls: None,
            tls_cert_path: None,
            tls_key_path: None,
            local_testing_mode: None,
            local_testing_num_keys: None,
        }
    }
}

impl ServerConfig {
    /// Validate server configuration
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.port == 0 {
            return Err(ConfigError::InvalidPort { port: self.port });
        }

        if self.host.is_empty() {
            return Err(ConfigError::InvalidHost { host: self.host.clone() });
        }

        // Validate TLS configuration
        if self.enable_tls == Some(true) {
            if self.tls_cert_path.is_none() {
                return Err(ConfigError::ValidationError {
                    message: "TLS certificate path required when TLS is enabled".to_string()
                });
            }
            if self.tls_key_path.is_none() {
                return Err(ConfigError::ValidationError {
                    message: "TLS private key path required when TLS is enabled".to_string()
                });
            }
        }

        Ok(())
    }

    /// Check if TLS should be enabled
    pub fn should_enable_tls(&self) -> bool {
        self.enable_tls.unwrap_or(false)
    }

    /// Check if local testing mode is enabled
    pub fn is_local_testing_mode(&self) -> bool {
        self.local_testing_mode.unwrap_or(false)
    }

    /// Get number of keys for local testing
    pub fn get_local_testing_num_keys(&self) -> usize {
        self.local_testing_num_keys.unwrap_or(1)
    }
}

/// Security configuration
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct SecurityConfig {
    /// Enable production mode with stricter security
    pub production_mode: bool,
    /// Enable detailed security audit logging
    pub detailed_audit_logging: bool,
    /// Allow insecure host binding (0.0.0.0) in production
    pub allow_insecure_host: bool,
    /// Maximum authentication failures per hour
    pub max_auth_failures_per_hour: Option<u32>,
    /// Maximum secret access attempts per minute
    pub max_secret_access_per_minute: Option<u32>,
    /// Blocked user agents
    pub blocked_user_agents: Option<Vec<String>>,
    /// Minimum JWT token length
    pub min_token_length: Option<usize>,
    /// Enable suspicious activity detection
    pub enable_suspicious_activity_detection: bool,
    /// Enable secure memory for secrets
    pub enable_secure_memory: bool,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            production_mode: false,
            detailed_audit_logging: false,
            allow_insecure_host: false,
            max_auth_failures_per_hour: None,
            max_secret_access_per_minute: None,
            blocked_user_agents: None,
            min_token_length: None,
            enable_suspicious_activity_detection: true,
            enable_secure_memory: true,
        }
    }
}

/// Validation configuration for JWT tokens
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ValidationConfig {
    /// Required claims that must be present in JWT
    pub required_claims: Option<Vec<String>>,
    /// Allowed token issuers
    pub allowed_issuers: Option<Vec<String>>,
    /// Maximum token age in seconds
    pub max_token_age: Option<i64>,
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
        }
    }
}

// Custom deserialization to handle the nested TOML structure
impl<'de> Deserialize<'de> for Config {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::{Error, MapAccess, Visitor};
        use std::fmt;

        struct ConfigVisitor;

        impl<'de> Visitor<'de> for ConfigVisitor {
            type Value = Config;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a config object")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut server = None;
                let mut validation = None;
                let mut security = None;
                let mut repositories = HashMap::new();

                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "server" => {
                            if server.is_some() {
                                return Err(Error::duplicate_field("server"));
                            }
                            server = Some(map.next_value()?);
                        }
                        "validation" => {
                            if validation.is_some() {
                                return Err(Error::duplicate_field("validation"));
                            }
                            validation = Some(map.next_value()?);
                        }
                        "security" => {
                            if security.is_some() {
                                return Err(Error::duplicate_field("security"));
                            }
                            security = Some(map.next_value()?);
                        }
                        _ => {
                            // Handle repository sections
                            let section_map: HashMap<String, toml::Value> = map.next_value()?;

                            for (sub_key, sub_value) in section_map {
                                let full_key = format!("{}.{}", key, sub_key);
                                if let toml::Value::Table(table) = sub_value {
                                    let mut secrets = HashMap::new();
                                    for (secret_key, secret_value) in table {
                                        if let toml::Value::String(secret_str) = secret_value {
                                            secrets.insert(secret_key, secret_str);
                                        }
                                    }
                                    repositories.insert(full_key, secrets);
                                }
                            }
                        }
                    }
                }

                let server = server.ok_or_else(|| Error::missing_field("server"))?;

                let config = Config {
                    server,
                    validation,
                    security,
                    repositories,
                };

                // Validate the configuration
                config.validate_security().map_err(|e| {
                    Error::custom(format!("Configuration validation failed: {}", e))
                })?;

                Ok(config)
            }
        }

        deserializer.deserialize_map(ConfigVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_server_config_validation() {
        let mut config = ServerConfig::default();
        assert!(config.validate().is_ok());

        // Test invalid port
        config.port = 0;
        assert!(config.validate().is_err());

        // Reset and test empty host
        config.port = 8080;
        config.host = "".to_string();
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_tls_config_validation() {
        let mut config = ServerConfig::default();
        config.enable_tls = Some(true);

        // Should fail without cert and key paths
        assert!(config.validate().is_err());

        // Add cert path but not key path
        config.tls_cert_path = Some("/path/to/cert.pem".to_string());
        assert!(config.validate().is_err());

        // Add key path - should now pass
        config.tls_key_path = Some("/path/to/key.pem".to_string());
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_security_config_defaults() {
        let config = SecurityConfig::default();
        assert!(!config.production_mode);
        assert!(!config.detailed_audit_logging);
        assert!(!config.allow_insecure_host);
        assert!(config.enable_suspicious_activity_detection);
        assert!(config.enable_secure_memory);
    }

    #[test]
    fn test_config_production_mode_detection() {
        let mut config = Config {
            server: ServerConfig::default(),
            validation: None,
            security: Some(SecurityConfig { production_mode: true, ..Default::default() }),
            repositories: HashMap::new(),
        };

        assert!(config.is_production_mode());

        // Test environment variable detection
        config.security = None;
        std::env::set_var("RUST_ENV", "production");
        assert!(config.is_production_mode());

        std::env::remove_var("RUST_ENV");
        assert!(!config.is_production_mode());
    }

    #[test]
    fn test_config_security_validation() {
        let mut repositories = HashMap::new();
        let mut secrets = HashMap::new();
        secrets.insert("valid_key".to_string(), "valid_value".to_string());
        repositories.insert("github.octocat".to_string(), secrets);

        let config = Config {
            server: ServerConfig::default(),
            validation: None,
            security: None,
            repositories,
        };

        assert!(config.validate_security().is_ok());
    }

    #[test]
    fn test_config_insecure_production_settings() {
        let config = Config {
            server: ServerConfig {
                host: "0.0.0.0".to_string(),
                port: 8080,
                ..Default::default()
            },
            validation: None,
            security: Some(SecurityConfig {
                production_mode: true,
                allow_insecure_host: false,
                ..Default::default()
            }),
            repositories: HashMap::new(),
        };

        // Should fail due to insecure host in production
        assert!(config.validate_security().is_err());
    }

    #[test]
    fn test_get_secrets_format_validation() {
        let mut repositories = HashMap::new();
        let mut secrets = HashMap::new();
        secrets.insert("api_key".to_string(), "secret123".to_string());
        repositories.insert("github.octocat".to_string(), secrets);

        let config = Config {
            server: ServerConfig::default(),
            validation: None,
            security: None,
            repositories,
        };

        // Valid format
        assert!(config.get_secrets("github/octocat").is_some());

        // Invalid formats
        assert!(config.get_secrets("github.octocat").is_none()); // Internal format
        assert!(config.get_secrets("github").is_none()); // No slash
        assert!(config.get_secrets("").is_none()); // Empty
    }
}
