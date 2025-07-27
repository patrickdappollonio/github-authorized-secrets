use crate::error::SecurityError;
use regex::Regex;

/// Basic input validator for format checking
pub struct InputValidator {
    max_repository_length: usize,
    max_token_length: usize,
    max_host_length: usize,
}

impl Default for InputValidator {
    fn default() -> Self {
        Self {
            max_repository_length: 256,
            max_token_length: 8192, // JWT tokens can be quite long
            max_host_length: 253,   // RFC 1035 limit
        }
    }
}

impl InputValidator {
    /// Create a new validator
    pub fn new(_production_mode: bool) -> Self {
        // Ignore production mode - no policy enforcement
        Self::default()
    }

    /// Validate repository name format
    pub fn validate_repository(&self, repository: &str) -> Result<(), SecurityError> {
        // Check length
        if repository.len() > self.max_repository_length {
            return Err(SecurityError::InputValidationFailed {
                message: format!("repository name too long: {} characters", repository.len()),
            });
        }

        // Check format: must be "owner/repo"
        if !repository.contains('/') || repository.matches('/').count() != 1 {
            return Err(SecurityError::InputValidationFailed {
                message: "repository must be in format 'owner/repo'".to_string(),
            });
        }

        let parts: Vec<&str> = repository.split('/').collect();
        if parts.len() != 2 || parts[0].is_empty() || parts[1].is_empty() {
            return Err(SecurityError::InputValidationFailed {
                message: "both owner and repository name must be non-empty".to_string(),
            });
        }

        // Check for allowed characters (standard GitHub repository name rules)
        let allowed_chars = Regex::new(r"^[a-zA-Z0-9._-]+$").unwrap();
        for part in parts {
            if !allowed_chars.is_match(part) {
                return Err(SecurityError::InputValidationFailed {
                    message: format!("invalid characters in repository name: {part}"),
                });
            }
        }

        Ok(())
    }

    /// Validate JWT token format and basic structure
    pub fn validate_token(&self, token: &str) -> Result<(), SecurityError> {
        // Check length
        if token.len() > self.max_token_length {
            return Err(SecurityError::InputValidationFailed {
                message: format!("token too long: {} characters", token.len()),
            });
        }

        if token.is_empty() {
            return Err(SecurityError::InputValidationFailed {
                message: "token cannot be empty".to_string(),
            });
        }

        // Check JWT format (should have 3 parts separated by dots)
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return Err(SecurityError::InputValidationFailed {
                message: "token must have 3 parts separated by dots".to_string(),
            });
        }

        // Check each part is base64url encoded (basic check)
        let base64url_pattern = Regex::new(r"^[A-Za-z0-9_-]*$").unwrap(); // Allow empty parts too
        for (i, part) in parts.iter().enumerate() {
            if !base64url_pattern.is_match(part) {
                return Err(SecurityError::InputValidationFailed {
                    message: format!("token part {} contains invalid characters", i + 1),
                });
            }
        }

        Ok(())
    }

    /// Validate host/domain name
    pub fn validate_host(&self, host: &str) -> Result<(), SecurityError> {
        // Check length
        if host.len() > self.max_host_length {
            return Err(SecurityError::InputValidationFailed {
                message: format!("host name too long: {} characters", host.len()),
            });
        }

        if host.is_empty() {
            return Err(SecurityError::InputValidationFailed {
                message: "host cannot be empty".to_string(),
            });
        }

        // Basic hostname validation (RFC compliant) - allow localhost and IP addresses too
        let hostname_pattern =
            Regex::new(r"^[a-zA-Z0-9]([a-zA-Z0-9.-]{0,61}[a-zA-Z0-9])?$").unwrap();
        if !hostname_pattern.is_match(host) {
            return Err(SecurityError::InputValidationFailed {
                message: "invalid host name format".to_string(),
            });
        }

        Ok(())
    }

    /// Validate URL scheme - allow both HTTP and HTTPS
    pub fn validate_scheme(&self, scheme: &str) -> Result<(), SecurityError> {
        match scheme {
            "http" | "https" => Ok(()),
            _ => Err(SecurityError::InputValidationFailed {
                message: format!("scheme '{scheme}' is not supported, use 'http' or 'https'"),
            }),
        }
    }

    /// Validate configuration key names
    pub fn validate_config_key(&self, key: &str) -> Result<(), SecurityError> {
        if key.is_empty() {
            return Err(SecurityError::InputValidationFailed {
                message: "configuration key cannot be empty".to_string(),
            });
        }

        if key.len() > 256 {
            return Err(SecurityError::InputValidationFailed {
                message: format!("configuration key too long: {} characters", key.len()),
            });
        }

        // Allow alphanumeric, dots, underscores, and hyphens
        let key_pattern = Regex::new(r"^[a-zA-Z0-9._-]+$").unwrap();
        if !key_pattern.is_match(key) {
            return Err(SecurityError::InputValidationFailed {
                message: format!("invalid characters in configuration key: {key}"),
            });
        }

        Ok(())
    }

    /// Validate secret values (ensure they don't contain obvious malicious patterns)
    pub fn validate_secret_value(&self, value: &str) -> Result<(), SecurityError> {
        // Don't validate length for secrets as they can be very long (e.g., private keys)

        // Check for some obvious malicious patterns but be careful not to be too restrictive
        let dangerous_patterns = vec![
            Regex::new(r"(?i)<script").unwrap(),
            Regex::new(r"(?i)javascript:").unwrap(),
        ];

        for pattern in &dangerous_patterns {
            if pattern.is_match(value) {
                return Err(SecurityError::InputValidationFailed {
                    message: "secret value contains dangerous patterns".to_string(),
                });
            }
        }

        Ok(())
    }

    /// Validate output format prefix
    pub fn validate_prefix(&self, prefix: &str) -> Result<(), SecurityError> {
        if prefix.len() > 64 {
            return Err(SecurityError::InputValidationFailed {
                message: format!("prefix too long: {} characters", prefix.len()),
            });
        }

        // Allow common prefix patterns (alphanumeric and underscores)
        let prefix_pattern = Regex::new(r"^[A-Za-z0-9_]*$").unwrap();
        if !prefix_pattern.is_match(prefix) {
            return Err(SecurityError::InputValidationFailed {
                message: "prefix contains invalid characters".to_string(),
            });
        }

        Ok(())
    }

    /// Comprehensive input sanitization
    pub fn sanitize_log_input(&self, input: &str) -> String {
        input
            .chars()
            .filter(|c| c.is_ascii() && !c.is_control() || *c == ' ')
            .take(256) // Limit log input length
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_repository_valid() {
        let validator = InputValidator::default();

        let valid_repos = vec![
            "owner/repo",
            "github/octocat",
            "my-org/my-repo",
            "user123/project_name",
            "org.name/repo.name",
        ];

        for repo in valid_repos {
            assert!(
                validator.validate_repository(repo).is_ok(),
                "Repository '{repo}' should be valid"
            );
        }
    }

    #[test]
    fn test_validate_repository_invalid() {
        let validator = InputValidator::default();

        let invalid_repos = vec![
            "",
            "no-slash",
            "/empty-owner",
            "empty-repo/",
            "too/many/slashes",
            "owner/",
            "/repo",
            "owner with spaces/repo",
            "owner/repo with spaces",
        ];

        for repo in invalid_repos {
            assert!(
                validator.validate_repository(repo).is_err(),
                "Repository '{repo}' should be invalid"
            );
        }
    }

    #[test]
    fn test_validate_token_basic() {
        let validator = InputValidator::default();

        // Valid JWT-like tokens
        assert!(validator
            .validate_token("eyJ0eXAi.eyJzdWIi.SflKxwRJ")
            .is_ok());
        assert!(validator.validate_token("a.b.c").is_ok());
        assert!(validator.validate_token("..").is_ok()); // Allow empty parts

        // Invalid tokens
        assert!(validator.validate_token("").is_err());
        assert!(validator.validate_token("only.two").is_err());
        assert!(validator.validate_token("too.many.parts.here").is_err());
        assert!(validator
            .validate_token("invalid@characters.in.token")
            .is_err());
    }

    #[test]
    fn test_validate_host() {
        let validator = InputValidator::default();

        // Valid hosts
        assert!(validator.validate_host("example.com").is_ok());
        assert!(validator.validate_host("localhost").is_ok());
        assert!(validator.validate_host("api.github.com").is_ok());
        assert!(validator.validate_host("127.0.0.1").is_ok());

        // Invalid hosts
        assert!(validator.validate_host("").is_err());
        assert!(validator.validate_host(&"a".repeat(300)).is_err()); // Too long
    }

    #[test]
    fn test_validate_scheme() {
        let validator = InputValidator::default();

        // Both HTTP and HTTPS should be allowed
        assert!(validator.validate_scheme("http").is_ok());
        assert!(validator.validate_scheme("https").is_ok());

        // Invalid schemes
        assert!(validator.validate_scheme("ftp").is_err());
        assert!(validator.validate_scheme("file").is_err());
        assert!(validator.validate_scheme("").is_err());
    }

    #[test]
    fn test_validate_config_key() {
        let validator = InputValidator::default();

        // Valid keys
        assert!(validator.validate_config_key("api_key").is_ok());
        assert!(validator.validate_config_key("database.url").is_ok());
        assert!(validator.validate_config_key("app-name").is_ok());
        assert!(validator.validate_config_key("key123").is_ok());

        // Invalid keys
        assert!(validator.validate_config_key("").is_err());
        assert!(validator.validate_config_key(&"a".repeat(300)).is_err()); // Too long
        assert!(validator.validate_config_key("key with spaces").is_err());
        assert!(validator.validate_config_key("key@invalid").is_err());
    }
}
