use crate::config::types::Config;
use crate::error::ConfigError;
use crate::security::InputValidator;
use std::fs;
use tracing::{info, warn};

pub struct ConfigLoader;

impl ConfigLoader {
    /// Load configuration from file with security validation
    pub fn from_file(path: &str) -> Result<Config, ConfigError> {
        // Validate file path for security
        Self::validate_config_path(path)?;

        // Read the configuration file
        let content = fs::read_to_string(path)
            .map_err(|e| {
                warn!("Failed to read config file {}: {}", path, e);
                ConfigError::FileReadError(e)
            })?;

        // Validate file content before parsing
        Self::validate_config_content(&content)?;

        // Parse TOML
        let config: Config = toml::from_str(&content)
            .map_err(|e| {
                warn!("Failed to parse TOML in {}: {}", path, e);
                ConfigError::TomlParseError(e)
            })?;

        info!("Configuration loaded successfully from {}", path);
        Ok(config)
    }

    /// Validate configuration file path for security
    fn validate_config_path(path: &str) -> Result<(), ConfigError> {
        // Check for path traversal attempts
        if path.contains("../") || path.contains("..\\") {
            warn!("Configuration path contains path traversal: {}", path);
            return Err(ConfigError::ValidationError {
                message: "configuration path contains path traversal sequences".to_string(),
            });
        }

        // Check for null bytes and control characters
        if path.contains('\0') || path.chars().any(|c| c.is_control()) {
            warn!("Configuration path contains invalid characters");
            return Err(ConfigError::ValidationError {
                message: "configuration path contains invalid characters".to_string(),
            });
        }

        // Check reasonable path length
        if path.len() > 1024 {
            warn!("Configuration path too long: {} characters", path.len());
            return Err(ConfigError::ValidationError {
                message: format!("configuration path too long: {} characters", path.len()),
            });
        }

        // Check for suspicious patterns
        let suspicious_patterns = [
            "/proc/",
            "/sys/",
            "/dev/",
            "\\\\", // UNC paths
            "javascript:",
            "data:",
        ];

        for pattern in &suspicious_patterns {
            if path.to_lowercase().contains(pattern) {
                warn!("Configuration path contains suspicious pattern: {}", pattern);
                return Err(ConfigError::ValidationError {
                    message: format!("configuration path contains suspicious pattern: {}", pattern),
                });
            }
        }

        Ok(())
    }

    /// Validate configuration file content before parsing
    fn validate_config_content(content: &str) -> Result<(), ConfigError> {
        // Check reasonable file size (max 10MB)
        if content.len() > 10 * 1024 * 1024 {
            warn!("Configuration file too large: {} bytes", content.len());
            return Err(ConfigError::ValidationError {
                message: format!("configuration file too large: {} bytes", content.len()),
            });
        }

        // Check for binary content (should be text)
        if content.contains('\0') {
            warn!("Configuration file contains binary data");
            return Err(ConfigError::ValidationError {
                message: "configuration file appears to contain binary data".to_string(),
            });
        }

        // Check for potential injection attempts
        let dangerous_patterns = [
            "javascript:",
            "<script",
            "eval(",
            "exec(",
            "${", // Template injection
            "#{", // Ruby/ERB injection
        ];

        for pattern in &dangerous_patterns {
            if content.to_lowercase().contains(pattern) {
                warn!("Configuration content contains dangerous pattern: {}", pattern);
                return Err(ConfigError::ValidationError {
                    message: format!("configuration content contains dangerous pattern: {}", pattern),
                });
            }
        }

        // Validate basic TOML structure (quick check)
        if !content.trim().is_empty() && !Self::is_likely_toml(content) {
            warn!("Configuration content doesn't appear to be valid TOML");
            return Err(ConfigError::ValidationError {
                message: "configuration content doesn't appear to be valid TOML".to_string(),
            });
        }

        Ok(())
    }

    /// Quick heuristic check if content looks like TOML
    fn is_likely_toml(content: &str) -> bool {
        let content = content.trim();

        // Empty files are valid TOML
        if content.is_empty() {
            return true;
        }

        // Check for TOML-like patterns
        let toml_indicators = [
            "[", // Section headers
            "=", // Key-value pairs
            "#", // Comments
        ];

        // Should contain at least one TOML indicator
        toml_indicators.iter().any(|&indicator| content.contains(indicator))
    }

    /// Validate configuration keys and values for security
    pub fn validate_config_security(config: &Config) -> Result<(), ConfigError> {
        let validator = InputValidator::new(config.is_production_mode());

        // Validate server configuration
        validator.validate_host(&config.server.host)
            .map_err(|e| ConfigError::ValidationError {
                message: format!("invalid server host: {}", e),
            })?;

        if config.server.port == 0 {
            return Err(ConfigError::InvalidPort { port: config.server.port });
        }

        // Validate repository configurations
        for (repo_key, secrets) in &config.repositories {
            // Validate repository key format
            if !repo_key.contains('.') {
                return Err(ConfigError::InvalidRepositoryFormat {
                    repo: repo_key.clone(),
                });
            }

            // Validate repository key security
            validator.validate_config_key(repo_key)
                .map_err(|e| ConfigError::ValidationError {
                    message: format!("invalid repository key {}: {}", repo_key, e),
                })?;

            // Validate secret keys and values
            for (secret_key, secret_value) in secrets {
                validator.validate_config_key(secret_key)
                    .map_err(|e| ConfigError::ValidationError {
                        message: format!("invalid secret key {} in {}: {}", secret_key, repo_key, e),
                    })?;

                validator.validate_secret_value(secret_value)
                    .map_err(|e| ConfigError::ValidationError {
                        message: format!("invalid secret value for {} in {}: {}", secret_key, repo_key, e),
                    })?;

                // Check for secrets that look like they might be accidentally exposed
                if Self::looks_like_test_data(secret_value) {
                    warn!("Secret value for {} in {} looks like test data", secret_key, repo_key);
                }
            }
        }

        // Production-specific validations
        if config.is_production_mode() {
            Self::validate_production_config(config)?;
        }

        Ok(())
    }

    /// Validate production-specific configuration requirements
    fn validate_production_config(config: &Config) -> Result<(), ConfigError> {
        // Check for insecure host binding
        if config.server.host == "0.0.0.0" &&
           !config.security.as_ref().map(|s| s.allow_insecure_host).unwrap_or(false) {
            return Err(ConfigError::InsecureConfig {
                issue: "binding to 0.0.0.0 in production without explicit allow_insecure_host setting".to_string(),
            });
        }

        // Check for insecure ports
        if config.server.port == 80 || config.server.port == 8080 {
            return Err(ConfigError::InsecureConfig {
                issue: "using potentially insecure HTTP port in production".to_string(),
            });
        }

        // Require TLS in production
        if !config.server.should_enable_tls() {
            warn!("TLS not enabled in production mode - this is not recommended");
        }

        // Check JWT cache duration is reasonable
        if config.server.jwt_cache_duration > 3600 {
            warn!("JWT cache duration is very long: {}s", config.server.jwt_cache_duration);
        }

        Ok(())
    }

    /// Check if a secret value looks like test data
    fn looks_like_test_data(value: &str) -> bool {
        let test_patterns = [
            "test",
            "example",
            "demo",
            "sample",
            "mock",
            "fake",
            "placeholder",
            "changeme",
            "password",
            "123456",
            "secret123",
        ];

        let value_lower = value.to_lowercase();
        test_patterns.iter().any(|&pattern| value_lower.contains(pattern))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Write;
    use tempfile::tempdir;

    #[test]
    fn test_validate_config_path_valid() {
        let valid_paths = [
            "config.toml",
            "/etc/app/config.toml",
            "configs/production.toml",
            "./local_config.toml",
        ];

        for path in &valid_paths {
            assert!(ConfigLoader::validate_config_path(path).is_ok(),
                   "Path should be valid: {}", path);
        }
    }

    #[test]
    fn test_validate_config_path_invalid() {
        let invalid_paths = [
            "../../../etc/passwd",
            "config/../../../etc/shadow",
            "config\0.toml",
            "javascript:alert('xss')",
            "/proc/self/environ",
            "/sys/class/net",
            "\\\\server\\share\\config.toml",
            &"a".repeat(2000), // Too long
        ];

        for path in &invalid_paths {
            assert!(ConfigLoader::validate_config_path(path).is_err(),
                   "Path should be invalid: {}", path);
        }
    }

    #[test]
    fn test_validate_config_content_valid() {
        let valid_contents = [
            "[server]\nhost = \"127.0.0.1\"\nport = 8080",
            "# This is a comment\n[server]\nhost = \"localhost\"",
            "", // Empty file is valid TOML
            "[github.repo]\napi_key = \"valid_secret\"",
        ];

        for content in &valid_contents {
            assert!(ConfigLoader::validate_config_content(content).is_ok(),
                   "Content should be valid: {}", content);
        }
    }

    #[test]
    fn test_validate_config_content_invalid() {
        let invalid_contents = [
            "config\0with\0null\0bytes",
            "javascript:alert('xss')",
            "<script>alert('xss')</script>",
            "eval(malicious_code)",
            "${system.exit(1)}",
            "#{`rm -rf /`}",
            &"a".repeat(11 * 1024 * 1024), // Too large
        ];

        for content in &invalid_contents {
            assert!(ConfigLoader::validate_config_content(content).is_err(),
                   "Content should be invalid: {}", content);
        }
    }

    #[test]
    fn test_is_likely_toml() {
        let toml_like = [
            "[server]",
            "key = \"value\"",
            "# comment",
            "[section]\nkey = value",
        ];

        let not_toml_like = [
            "just plain text",
            "no toml indicators here",
            "12345",
        ];

        for content in &toml_like {
            assert!(ConfigLoader::is_likely_toml(content),
                   "Should be detected as TOML-like: {}", content);
        }

        for content in &not_toml_like {
            assert!(!ConfigLoader::is_likely_toml(content),
                   "Should not be detected as TOML-like: {}", content);
        }

        // Empty content should be considered valid TOML
        assert!(ConfigLoader::is_likely_toml(""));
        assert!(ConfigLoader::is_likely_toml("   \n  \t  "));
    }

    #[test]
    fn test_looks_like_test_data() {
        let test_data = [
            "test_secret",
            "example_api_key",
            "demo_password",
            "SECRET123",
            "changeme_password",
            "mock_token",
        ];

        let real_data = [
            "sk_live_abcd1234",
            "ghp_real_token",
            "prod_db_conn_xyz", // Changed from password to avoid triggering test pattern
            "production_api_key_456",
        ];

        for data in &test_data {
            assert!(ConfigLoader::looks_like_test_data(data),
                   "Should be detected as test data: {}", data);
        }

        for data in &real_data {
            assert!(!ConfigLoader::looks_like_test_data(data),
                   "Should not be detected as test data: {}", data);
        }
    }

    #[test]
    fn test_config_loading_with_valid_file() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("valid_config.toml");

        let config_content = r#"
[server]
host = "127.0.0.1"
port = 8080
jwt_cache_duration = 300

[github.octocat]
api_key = "valid_secret"
database_url = "postgresql://localhost/test"
"#;

        let mut file = File::create(&file_path).unwrap();
        file.write_all(config_content.as_bytes()).unwrap();

        let result = ConfigLoader::from_file(file_path.to_str().unwrap());
        assert!(result.is_ok(), "Should successfully load valid config");

        let config = result.unwrap();
        assert_eq!(config.server.host, "127.0.0.1");
        assert_eq!(config.server.port, 8080);
    }

    #[test]
    fn test_config_loading_with_invalid_path() {
        let result = ConfigLoader::from_file("../../../etc/passwd");
        assert!(result.is_err(), "Should reject path traversal");

        match result.unwrap_err() {
            ConfigError::ValidationError { .. } => {} // Expected
            _ => panic!("Expected ValidationError for path traversal"),
        }
    }

    #[test]
    fn test_config_loading_with_malicious_content() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("malicious_config.toml");

        let malicious_content = r#"
[server]
host = "127.0.0.1"
port = 8080

# This contains malicious content
evil = "javascript:alert('xss')"
"#;

        let mut file = File::create(&file_path).unwrap();
        file.write_all(malicious_content.as_bytes()).unwrap();

        let result = ConfigLoader::from_file(file_path.to_str().unwrap());
        assert!(result.is_err(), "Should reject malicious content");
    }

    #[test]
    fn test_config_loading_nonexistent_file() {
        let result = ConfigLoader::from_file("nonexistent_config.toml");
        assert!(result.is_err(), "Should fail for nonexistent file");

        match result.unwrap_err() {
            ConfigError::FileReadError(_) => {} // Expected
            _ => panic!("Expected FileReadError for nonexistent file"),
        }
    }

    #[test]
    fn test_config_loading_invalid_toml() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("invalid.toml");

        let invalid_toml = r#"
[server
host = "127.0.0.1" # Missing closing bracket
port = 8080
"#;

        let mut file = File::create(&file_path).unwrap();
        file.write_all(invalid_toml.as_bytes()).unwrap();

        let result = ConfigLoader::from_file(file_path.to_str().unwrap());
        assert!(result.is_err(), "Should fail for invalid TOML");

        match result.unwrap_err() {
            ConfigError::TomlParseError(_) => {} // Expected
            _ => panic!("Expected TomlParseError for invalid TOML"),
        }
    }

    #[test]
    fn test_production_config_validation() {
        use std::collections::HashMap;
        use crate::config::types::{Config, ServerConfig, SecurityConfig};

        let insecure_production_config = Config {
            server: ServerConfig {
                host: "0.0.0.0".to_string(),
                port: 8080,
                jwt_cache_duration: 300,
                enable_tls: Some(false),
                tls_cert_path: None,
                tls_key_path: None,
            },
            validation: None,
            security: Some(SecurityConfig {
                production_mode: true,
                allow_insecure_host: false,
                ..Default::default()
            }),
            repositories: HashMap::new(),
        };

        let result = ConfigLoader::validate_production_config(&insecure_production_config);
        assert!(result.is_err(), "Should reject insecure production config");
    }

    #[test]
    fn test_security_validation_with_invalid_keys() {
        use std::collections::HashMap;
        use crate::config::types::{Config, ServerConfig};

        let mut repositories = HashMap::new();
        let mut secrets = HashMap::new();
        secrets.insert("invalid key with spaces".to_string(), "value".to_string());
        repositories.insert("github.test".to_string(), secrets);

        let config = Config {
            server: ServerConfig::default(),
            validation: None,
            security: None,
            repositories,
        };

        let result = ConfigLoader::validate_config_security(&config);
        assert!(result.is_err(), "Should reject invalid secret keys");
    }

    #[test]
    fn test_config_with_suspicious_secret_values() {
        use std::collections::HashMap;
        use crate::config::types::{Config, ServerConfig};

        let mut repositories = HashMap::new();
        let mut secrets = HashMap::new();
        secrets.insert("api_key".to_string(), "<script>alert('xss')</script>".to_string());
        repositories.insert("github.test".to_string(), secrets);

        let config = Config {
            server: ServerConfig::default(),
            validation: None,
            security: None,
            repositories,
        };

        let result = ConfigLoader::validate_config_security(&config);
        assert!(result.is_err(), "Should reject suspicious secret values");
    }
}
