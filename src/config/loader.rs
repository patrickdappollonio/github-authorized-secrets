use crate::config::types::Config;
use crate::error::ConfigError;
use std::fs;
use tracing::info;

/// Configuration loader with simplified validation
pub struct ConfigLoader;

impl ConfigLoader {
    /// Load configuration from file
    pub fn from_file(path: &str) -> Result<Config, ConfigError> {
        info!("Loading configuration from: {}", path);

        let config_content = fs::read_to_string(path).map_err(ConfigError::FileReadError)?;

        let config: Config =
            toml::from_str(&config_content).map_err(|e| ConfigError::TomlParseError {
                message: e.to_string(),
            })?;

        // Basic validation
        config
            .validate_security()
            .map_err(|e| ConfigError::ValidationError { message: e })?;

        info!(
            "Configuration loaded successfully with {} repositories",
            config.repositories.len()
        );

        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::tempdir;

    #[test]
    fn test_config_loading_nonexistent_file() {
        let result = ConfigLoader::from_file("nonexistent_config.toml");
        assert!(result.is_err());

        match result.unwrap_err() {
            ConfigError::FileReadError(_) => {} // Expected
            _ => panic!("Expected FileReadError for nonexistent file"),
        }
    }

    #[test]
    fn test_config_loading_with_malicious_content() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("malicious.toml");
        let mut file = std::fs::File::create(&file_path).unwrap();

        // This should be handled gracefully by TOML parser
        writeln!(
            file,
            r#"malicious_content = "<script>alert('xss')</script>""#
        )
        .unwrap();

        let result = ConfigLoader::from_file(file_path.to_str().unwrap());
        // Should either succeed (parsing the content) or fail gracefully
        // The main point is it shouldn't crash or execute malicious content
        match result {
            Ok(_) => {}                                    // Content was parsed successfully
            Err(ConfigError::TomlParseError { .. }) => {}  // Failed to parse, which is also OK
            Err(ConfigError::ValidationError { .. }) => {} // Failed validation, which is also OK
            Err(e) => panic!("Unexpected error type: {e:?}"),
        }
    }

    #[test]
    fn test_config_loading_with_invalid_path() {
        let result = ConfigLoader::from_file("nonexistent_file.toml");
        assert!(result.is_err(), "Should fail for nonexistent file");

        match result.unwrap_err() {
            ConfigError::FileReadError(_) => {} // Expected
            _ => panic!("Expected FileReadError for nonexistent file"),
        }
    }
}
