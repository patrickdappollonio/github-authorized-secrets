use crate::error::SecurityError;
use regex::Regex;
use std::collections::HashSet;

/// Comprehensive input validator for security hardening
pub struct InputValidator {
    max_repository_length: usize,
    max_token_length: usize,
    max_host_length: usize,
    forbidden_patterns: Vec<Regex>,
    allowed_schemes: HashSet<String>,
}

impl Default for InputValidator {
    fn default() -> Self {
        let mut forbidden_patterns = Vec::new();

        // SQL injection patterns
        forbidden_patterns.push(
            Regex::new(r"(?i)(union|select|insert|update|delete|drop|exec|execute)").unwrap(),
        );

        // XSS patterns
        forbidden_patterns.push(Regex::new(r"(?i)(<script|javascript:|on\w+\s*=)").unwrap());

        // Command injection patterns
        forbidden_patterns.push(Regex::new(r"(?i)(\||&&|\$\(|`|;|\n|\r)").unwrap());

        // Path traversal patterns
        forbidden_patterns.push(Regex::new(r"(\.\./|\.\.\\)").unwrap());

        let mut allowed_schemes = HashSet::new();
        allowed_schemes.insert("https".to_string());
        allowed_schemes.insert("http".to_string()); // Only for development

        Self {
            max_repository_length: 256,
            max_token_length: 8192, // JWT tokens can be quite long
            max_host_length: 253,   // RFC 1035 limit
            forbidden_patterns,
            allowed_schemes,
        }
    }
}

impl InputValidator {
    /// Create a new validator with custom settings
    pub fn new(production_mode: bool) -> Self {
        let mut validator = Self::default();

        if production_mode {
            // In production, only allow HTTPS
            validator.allowed_schemes.clear();
            validator.allowed_schemes.insert("https".to_string());
        }

        validator
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

        // Check for forbidden characters
        let allowed_chars = Regex::new(r"^[a-zA-Z0-9._-]+$").unwrap();
        for part in parts {
            if !allowed_chars.is_match(part) {
                return Err(SecurityError::InputValidationFailed {
                    message: format!("invalid characters in repository name: {}", part),
                });
            }
        }

        // Check for forbidden patterns
        for pattern in &self.forbidden_patterns {
            if pattern.is_match(repository) {
                return Err(SecurityError::InputValidationFailed {
                    message: "repository name contains forbidden patterns".to_string(),
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
        for (i, part) in parts.iter().enumerate() {
            if part.is_empty() {
                return Err(SecurityError::InputValidationFailed {
                    message: format!("token part {} is empty", i + 1),
                });
            }

            // Base64url characters: A-Z, a-z, 0-9, -, _
            let base64url_pattern = Regex::new(r"^[A-Za-z0-9_-]+$").unwrap();
            if !base64url_pattern.is_match(part) {
                return Err(SecurityError::InputValidationFailed {
                    message: format!("token part {} contains invalid characters", i + 1),
                });
            }
        }

        // Check for suspicious patterns
        for pattern in &self.forbidden_patterns {
            if pattern.is_match(token) {
                return Err(SecurityError::InputValidationFailed {
                    message: "token contains suspicious patterns".to_string(),
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

        // Basic hostname validation (RFC compliant)
        let hostname_pattern = Regex::new(r"^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$").unwrap();
        if !hostname_pattern.is_match(host) {
            return Err(SecurityError::InputValidationFailed {
                message: "invalid host name format".to_string(),
            });
        }

        // Check for forbidden patterns
        for pattern in &self.forbidden_patterns {
            if pattern.is_match(host) {
                return Err(SecurityError::InputValidationFailed {
                    message: "host contains forbidden patterns".to_string(),
                });
            }
        }

        Ok(())
    }

    /// Validate URL scheme
    pub fn validate_scheme(&self, scheme: &str) -> Result<(), SecurityError> {
        if !self.allowed_schemes.contains(scheme) {
            return Err(SecurityError::InputValidationFailed {
                message: format!("scheme '{}' is not allowed", scheme),
            });
        }

        Ok(())
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
                message: format!("invalid characters in configuration key: {}", key),
            });
        }

        // Check for forbidden patterns
        for pattern in &self.forbidden_patterns {
            if pattern.is_match(key) {
                return Err(SecurityError::InputValidationFailed {
                    message: "configuration key contains forbidden patterns".to_string(),
                });
            }
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

        // Valid repository names
        let valid_repos = vec![
            "owner/repo",
            "github/octocat",
            "my-org/my-repo",
            "owner123/repo.name",
            "user_name/repo_name",
        ];

        for repo in valid_repos {
            assert!(
                validator.validate_repository(repo).is_ok(),
                "Expected {} to be valid",
                repo
            );
        }
    }

    #[test]
    fn test_validate_repository_invalid() {
        let validator = InputValidator::default();

        // Invalid repository names
        let invalid_repos = vec![
            "",
            "owner",
            "/repo",
            "owner/",
            "owner//repo",
            "owner/repo/extra",
            "owner with spaces/repo",
            "owner/repo with spaces",
            "owner/repo;DROP TABLE",
            "owner/repo<script>",
        ];

        for repo in invalid_repos {
            assert!(
                validator.validate_repository(repo).is_err(),
                "Expected {} to be invalid",
                repo
            );
        }
    }

    #[test]
    fn test_validate_token_valid() {
        let validator = InputValidator::default();

        // Mock JWT-like tokens
        let valid_tokens = vec![
            "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwczovL3Rva2VuLmFjdGlvbnMuZ2l0aHViLmNvbSIsImF1ZCI6Imh0dHBzOi8vZ2l0aHViLmNvbS9vY3RvY2F0IiwicmVwb3NpdG9yeSI6Im9jdG9jYXQvSGVsbG8tV29ybGQiLCJyZWYiOiJyZWZzL2hlYWRzL21haW4ifQ.signature",
        ];

        for token in valid_tokens {
            assert!(
                validator.validate_token(token).is_ok(),
                "Expected token to be valid"
            );
        }
    }

    #[test]
    fn test_validate_token_invalid() {
        let validator = InputValidator::default();

        let invalid_tokens = vec![
            "",
            "only-one-part",
            "two.parts",
            "four.parts.are.now.invalid",
            "contains spaces.in.token",
            "contains;dangerous.patterns.here",
        ];

        for token in invalid_tokens {
            assert!(
                validator.validate_token(token).is_err(),
                "Expected token {} to be invalid",
                token
            );
        }
    }

    #[test]
    fn test_validate_host_valid() {
        let validator = InputValidator::default();

        let valid_hosts = vec![
            "example.com",
            "api.github.com",
            "localhost",
            "127.0.0.1",
            "my-api.example.org",
            "sub.domain.example.co.uk",
        ];

        for host in valid_hosts {
            assert!(
                validator.validate_host(host).is_ok(),
                "Expected host {} to be valid",
                host
            );
        }
    }

    #[test]
    fn test_validate_host_invalid() {
        let validator = InputValidator::default();

        let invalid_hosts = vec![
            "",
            "host with spaces",
            "host;with;semicolons",
            "host|with|pipes",
            "-invalid-start.com",
            "invalid-end-.com",
            "way.too.many.characters.in.this.hostname.that.exceeds.the.maximum.allowed.length.for.a.hostname.according.to.rfc.standards.and.should.be.rejected.by.our.validation.function.because.it.is.simply.too.long.to.be.a.valid.hostname.under.any.reasonable.circumstances.example.com",
        ];

        for host in invalid_hosts {
            assert!(
                validator.validate_host(host).is_err(),
                "Expected host {} to be invalid",
                host
            );
        }
    }

    #[test]
    fn test_validate_scheme() {
        let validator = InputValidator::new(false); // Development mode

        assert!(validator.validate_scheme("https").is_ok());
        assert!(validator.validate_scheme("http").is_ok());
        assert!(validator.validate_scheme("ftp").is_err());
        assert!(validator.validate_scheme("file").is_err());

        let prod_validator = InputValidator::new(true); // Production mode
        assert!(prod_validator.validate_scheme("https").is_ok());
        assert!(prod_validator.validate_scheme("http").is_err());
    }

    #[test]
    fn test_validate_config_key() {
        let validator = InputValidator::default();

        let valid_keys = vec![
            "server.host",
            "validation.max_token_age",
            "github.octocat",
            "api_key",
            "database-url",
        ];

        for key in valid_keys {
            assert!(
                validator.validate_config_key(key).is_ok(),
                "Expected key {} to be valid",
                key
            );
        }

        let invalid_keys = vec![
            "",
            "key with spaces",
            "key;with;semicolons",
            "key|with|pipes",
            "key<script>",
        ];

        for key in invalid_keys {
            assert!(
                validator.validate_config_key(key).is_err(),
                "Expected key {} to be invalid",
                key
            );
        }
    }

    #[test]
    fn test_validate_prefix() {
        let validator = InputValidator::default();

        let valid_prefixes = vec!["API_", "TEST", "DB_CONNECTION", "", "123"];

        for prefix in valid_prefixes {
            assert!(
                validator.validate_prefix(prefix).is_ok(),
                "Expected prefix {} to be valid",
                prefix
            );
        }

        let long_prefix = "a".repeat(65);
        let invalid_prefixes = vec![
            "prefix with spaces",
            "prefix-with-dashes",
            "prefix.with.dots",
            "prefix;with;semicolons",
            &long_prefix, // Too long
        ];

        for prefix in invalid_prefixes {
            assert!(
                validator.validate_prefix(prefix).is_err(),
                "Expected prefix {} to be invalid",
                prefix
            );
        }
    }

    #[test]
    fn test_sanitize_log_input() {
        let validator = InputValidator::default();

        let input = "Valid log message with\ncontrol\tchars\rand\x00binary";
        let sanitized = validator.sanitize_log_input(input);

        assert!(!sanitized.contains('\n'));
        assert!(!sanitized.contains('\t'));
        assert!(!sanitized.contains('\r'));
        assert!(!sanitized.contains('\x00'));
        assert!(sanitized.contains("Valid log message with"));
    }
}
