use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

/// In-memory secret store with thread-safe access and performance optimization
#[derive(Debug, Clone)]
pub struct SecretStore {
    /// Repository secrets mapping with thread-safe access
    inner: Arc<SecretStoreInner>,
}

#[derive(Debug)]
struct SecretStoreInner {
    /// Repository secrets mapping - keys are in "owner.repo" format
    secrets: RwLock<HashMap<String, HashMap<String, String>>>,
    /// Cached repository list for faster lookup
    repository_list_cache: RwLock<Option<Vec<String>>>,
}

impl SecretStore {
    /// Create a new empty secret store
    pub fn new() -> Self {
        Self {
            inner: Arc::new(SecretStoreInner {
                secrets: RwLock::new(HashMap::new()),
                repository_list_cache: RwLock::new(None),
            }),
        }
    }

    /// Create a secret store from configuration
    /// This loads all repository secrets from the TOML configuration
    pub fn from_config(repositories: &HashMap<String, HashMap<String, String>>) -> Self {
        let store = Self::new();

        // Validate and load repository secrets
        let mut secrets = store.inner.secrets.write().unwrap();
        let mut valid_repos = Vec::new();

        for (repo_key, repo_secrets) in repositories {
            // Validate repository key format
            if let Err(e) = Self::validate_repository_key(repo_key) {
                // Log the error but continue loading other repositories
                eprintln!(
                    "Warning: Skipping invalid repository key '{}': {}",
                    repo_key, e
                );
                continue;
            }

            // Validate and sanitize secrets
            let sanitized_secrets = Self::sanitize_secrets(repo_secrets);
            secrets.insert(repo_key.clone(), sanitized_secrets);
            valid_repos.push(Self::denormalize_repository_name(repo_key));
        }

        drop(secrets); // Explicitly drop the write lock

        // Pre-populate repository cache
        valid_repos.sort();
        *store.inner.repository_list_cache.write().unwrap() = Some(valid_repos);

        store
    }

    /// Get secrets for a repository with performance monitoring
    /// Accepts repository in "owner/repo" format and converts to "owner.repo" for lookup
    pub fn get_secrets(&self, repository: &str) -> Option<HashMap<String, String>> {
        let secrets = self.inner.secrets.read().unwrap();
        let result = secrets.get(&Self::normalize_repository_name(repository)).cloned();

        result
    }

    /// List available repositories in "owner/repo" format with caching
    pub fn list_repositories(&self) -> Vec<String> {
        // Check cache first
        {
            let cache = self.inner.repository_list_cache.read().unwrap();
            if let Some(ref cached_list) = *cache {
                return cached_list.clone();
            }
        }

        // Cache miss - rebuild cache
        let secrets = self.inner.secrets.read().unwrap();
        let mut repositories: Vec<String> = secrets
            .keys()
            .map(|key| Self::denormalize_repository_name(key))
            .collect();

        repositories.sort();

        // Update cache
        *self.inner.repository_list_cache.write().unwrap() = Some(repositories.clone());

        repositories
    }

    /// Check if a repository exists in the store with optimized lookup
    pub fn has_repository(&self, repository: &str) -> bool {
        let lookup_key = Self::normalize_repository_name(repository);
        let secrets = self.inner.secrets.read().unwrap();
        secrets.contains_key(&lookup_key)
    }

    /// Get the number of repositories in the store
    pub fn repository_count(&self) -> usize {
        let secrets = self.inner.secrets.read().unwrap();
        secrets.len()
    }

    /// Get the number of secrets for a specific repository
    pub fn secret_count(&self, repository: &str) -> Option<usize> {
        let lookup_key = Self::normalize_repository_name(repository);
        let secrets = self.inner.secrets.read().unwrap();
        secrets
            .get(&lookup_key)
            .map(|repo_secrets| repo_secrets.len())
    }

    // Private utility methods

    /// Convert "owner/repo" format to "owner.repo" format for internal storage
    fn normalize_repository_name(repository: &str) -> String {
        repository.replace('/', ".")
    }

    /// Convert "owner.repo" format back to "owner/repo" format for external use
    fn denormalize_repository_name(key: &str) -> String {
        // Find the first dot to split owner and repo
        if let Some(dot_pos) = key.find('.') {
            let (owner, repo) = key.split_at(dot_pos);
            format!("{}/{}", owner, &repo[1..]) // Skip the dot
        } else {
            // Fallback for malformed keys
            key.to_string()
        }
    }

    /// Validate repository key format (should be "owner.repo")
    fn validate_repository_key(key: &str) -> Result<(), String> {
        if key.is_empty() {
            return Err("repository key cannot be empty".to_string());
        }

        if !key.contains('.') {
            return Err(
                "repository key must contain a dot (expected format: owner.repo)".to_string(),
            );
        }

        let parts: Vec<&str> = key.split('.').collect();
        if parts.len() != 2 {
            return Err(
                "repository key must have exactly one dot (expected format: owner.repo)"
                    .to_string(),
            );
        }

        let (owner, repo) = (parts[0], parts[1]);
        if owner.is_empty() || repo.is_empty() {
            return Err("owner and repository name cannot be empty".to_string());
        }

        // Validate characters - basic GitHub naming rules
        for part in &[owner, repo] {
            if !part
                .chars()
                .all(|c| c.is_alphanumeric() || c == '-' || c == '_' || c == '.')
            {
                return Err(format!("invalid characters in repository name: {}", part));
            }
        }

        Ok(())
    }

    /// Sanitize secrets for safe storage with performance optimization
    /// This implements memory security best practices
    fn sanitize_secrets(secrets: &HashMap<String, String>) -> HashMap<String, String> {
        let mut sanitized = HashMap::with_capacity(secrets.len()); // Pre-allocate capacity

        for (key, value) in secrets {
            // Validate secret key
            if Self::is_valid_secret_key(key) {
                // Clone the value to ensure we own it
                // In a production system, you might want to use secure string types
                // that zero memory on drop
                sanitized.insert(key.clone(), value.clone());
            } else {
                eprintln!("Warning: Skipping invalid secret key '{}'", key);
            }
        }

        sanitized
    }

    /// Validate secret key format
    fn is_valid_secret_key(key: &str) -> bool {
        if key.is_empty() {
            return false;
        }

        // Secret keys should be reasonable length
        if key.len() > 255 {
            return false;
        }

        // Allow alphanumeric, underscores, hyphens, and dots
        key.chars()
            .all(|c| c.is_alphanumeric() || c == '_' || c == '-' || c == '.')
    }

    /// Clear sensitive data from memory (best effort)
    /// Note: Rust doesn't guarantee memory will be zeroed, but this is a best practice
    pub fn clear_secrets(&self) {
        let mut secrets = self.inner.secrets.write().unwrap();

        // Clear all secret values first
        for (_repo, repo_secrets) in secrets.iter_mut() {
            for (_key, value) in repo_secrets.iter_mut() {
                // Overwrite with zeros (best effort)
                unsafe {
                    let value_bytes = value.as_bytes_mut();
                    for byte in value_bytes.iter_mut() {
                        *byte = 0;
                    }
                }
            }
            repo_secrets.clear();
        }

        secrets.clear();

        // Clear cache as well
        *self.inner.repository_list_cache.write().unwrap() = None;
    }

    /// Refresh the repository cache (useful after configuration changes)
    pub fn refresh_cache(&self) {
        *self.inner.repository_list_cache.write().unwrap() = None;

        // Trigger cache rebuild
        self.list_repositories();
    }
}

impl Default for SecretStore {
    fn default() -> Self {
        Self::new()
    }
}

// Implement Drop to clear sensitive data when the store is dropped
impl Drop for SecretStoreInner {
    fn drop(&mut self) {
        // Clear sensitive data on drop (best effort)
        if let Ok(mut secrets) = self.secrets.write() {
            for (_repo, repo_secrets) in secrets.iter_mut() {
                for (_key, value) in repo_secrets.iter_mut() {
                    // Overwrite with zeros (best effort)
                    unsafe {
                        let value_bytes = value.as_bytes_mut();
                        for byte in value_bytes.iter_mut() {
                            *byte = 0;
                        }
                    }
                }
            }
        }
    }
}

/// Response structure for secret retrieval
#[derive(Debug, Serialize, Deserialize)]
pub struct SecretsResponse {
    /// Repository name in "owner/repo" format
    pub repository: String,
    /// Secret key-value pairs
    pub secrets: HashMap<String, String>,
    /// Metadata about the retrieval
    pub metadata: SecretsMetadata,
}

/// Metadata for secret retrieval
#[derive(Debug, Serialize, Deserialize)]
pub struct SecretsMetadata {
    /// When the secrets were retrieved
    pub retrieved_at: DateTime<Utc>,
    /// Repository owner
    pub repository_owner: String,
}

/// Response structure for repository listing
#[derive(Debug, Serialize, Deserialize)]
pub struct RepositoryListResponse {
    /// List of available repositories in "owner/repo" format
    pub repositories: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secret_store_creation() {
        let store = SecretStore::new();
        assert_eq!(store.repository_count(), 0);
        assert_eq!(store.list_repositories().len(), 0);
    }

    #[test]
    fn test_secret_store_from_config() {
        let mut config_repos = HashMap::new();
        let mut github_secrets = HashMap::new();
        github_secrets.insert("api_key".to_string(), "secret123".to_string());
        github_secrets.insert(
            "webhook_url".to_string(),
            "https://example.com/hook".to_string(),
        );
        config_repos.insert("github.octocat".to_string(), github_secrets);

        let store = SecretStore::from_config(&config_repos);
        assert_eq!(store.repository_count(), 1);
        assert!(store.has_repository("github/octocat"));
    }

    #[test]
    fn test_repository_name_normalization() {
        assert_eq!(
            SecretStore::normalize_repository_name("owner/repo"),
            "owner.repo"
        );
        assert_eq!(
            SecretStore::denormalize_repository_name("owner.repo"),
            "owner/repo"
        );
    }

    #[test]
    fn test_secret_retrieval() {
        let mut config_repos = HashMap::new();
        let mut secrets = HashMap::new();
        secrets.insert("key1".to_string(), "value1".to_string());
        secrets.insert("key2".to_string(), "value2".to_string());
        config_repos.insert("test.repo".to_string(), secrets.clone());

        let store = SecretStore::from_config(&config_repos);

        let retrieved = store.get_secrets("test/repo").unwrap();
        assert_eq!(retrieved.len(), 2);
        assert_eq!(retrieved.get("key1").unwrap(), "value1");
        assert_eq!(retrieved.get("key2").unwrap(), "value2");
    }

    #[test]
    fn test_repository_listing() {
        let mut config_repos = HashMap::new();
        config_repos.insert("github.octocat".to_string(), HashMap::new());
        config_repos.insert("acme.webapp".to_string(), HashMap::new());

        let store = SecretStore::from_config(&config_repos);
        let repos = store.list_repositories();

        assert_eq!(repos.len(), 2);
        assert!(repos.contains(&"github/octocat".to_string()));
        assert!(repos.contains(&"acme/webapp".to_string()));
    }

    #[test]
    fn test_repository_validation() {
        assert!(SecretStore::validate_repository_key("owner.repo").is_ok());
        assert!(SecretStore::validate_repository_key("").is_err());
        assert!(SecretStore::validate_repository_key("no-dot").is_err());
        assert!(SecretStore::validate_repository_key("too.many.dots").is_err());
        assert!(SecretStore::validate_repository_key(".empty-owner").is_err());
        assert!(SecretStore::validate_repository_key("empty-repo.").is_err());
    }

    #[test]
    fn test_secret_key_validation() {
        assert!(SecretStore::is_valid_secret_key("valid_key"));
        assert!(SecretStore::is_valid_secret_key("api-key"));
        assert!(SecretStore::is_valid_secret_key("key.with.dots"));
        assert!(!SecretStore::is_valid_secret_key(""));
        assert!(!SecretStore::is_valid_secret_key("key with spaces"));
        assert!(!SecretStore::is_valid_secret_key(&"a".repeat(256)));
    }

    #[test]
    fn test_thread_safety() {
        use std::sync::Arc;
        use std::thread;

        let mut config_repos = HashMap::new();
        let mut secrets = HashMap::new();
        secrets.insert("key".to_string(), "value".to_string());
        config_repos.insert("test.repo".to_string(), secrets);

        let store = Arc::new(SecretStore::from_config(&config_repos));
        let store_clone = Arc::clone(&store);

        let handle = thread::spawn(move || {
            let retrieved = store_clone.get_secrets("test/repo");
            assert!(retrieved.is_some());
        });

        assert!(store.has_repository("test/repo"));
        handle.join().unwrap();
    }
}
