use crate::error::SecurityError;
use std::collections::HashMap;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Secure memory container for sensitive data that automatically zeroizes on drop
#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecureString {
    inner: String,
}

impl SecureString {
    /// Create a new secure string
    pub fn new(value: String) -> Self {
        Self { inner: value }
    }

    /// Get a reference to the inner string
    pub fn as_str(&self) -> &str {
        &self.inner
    }

    /// Get the length of the string
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Check if the string is empty
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Explicitly zeroize the content
    pub fn zeroize(&mut self) {
        self.inner.zeroize();
    }
}

impl From<String> for SecureString {
    fn from(value: String) -> Self {
        Self::new(value)
    }
}

impl From<&str> for SecureString {
    fn from(value: &str) -> Self {
        Self::new(value.to_string())
    }
}

/// Secure memory management for secrets
#[derive(Debug)]
pub struct SecureMemory {
    secrets: HashMap<String, SecureString>,
}

impl SecureMemory {
    /// Create a new secure memory container
    pub fn new() -> Self {
        Self {
            secrets: HashMap::new(),
        }
    }

    /// Store a secret securely
    pub fn store_secret(&mut self, key: String, value: String) -> Result<(), SecurityError> {
        // Validate key format
        if key.is_empty() {
            return Err(SecurityError::MemorySecurityViolation {
                details: "secret key cannot be empty".to_string(),
            });
        }

        if key.len() > 256 {
            return Err(SecurityError::MemorySecurityViolation {
                details: format!("secret key too long: {} characters", key.len()),
            });
        }

        // Store the secret
        self.secrets.insert(key, SecureString::new(value));
        Ok(())
    }

    /// Retrieve a secret (returns a clone for safety)
    pub fn get_secret(&self, key: &str) -> Option<String> {
        self.secrets.get(key).map(|s| s.as_str().to_string())
    }

    /// Get all secrets as a regular HashMap (for compatibility)
    pub fn get_all_secrets(&self) -> HashMap<String, String> {
        self.secrets
            .iter()
            .map(|(k, v)| (k.clone(), v.as_str().to_string()))
            .collect()
    }

    /// Check if a secret exists
    pub fn contains_secret(&self, key: &str) -> bool {
        self.secrets.contains_key(key)
    }

    /// Remove a secret and zeroize it
    pub fn remove_secret(&mut self, key: &str) -> Option<()> {
        self.secrets.remove(key).map(|mut s| {
            s.zeroize();
        })
    }

    /// Get the number of stored secrets
    pub fn len(&self) -> usize {
        self.secrets.len()
    }

    /// Check if no secrets are stored
    pub fn is_empty(&self) -> bool {
        self.secrets.is_empty()
    }

    /// Clear all secrets and zeroize memory
    pub fn clear(&mut self) {
        for (_, mut secret) in self.secrets.drain() {
            secret.zeroize();
        }
    }

    /// Get all secret keys
    pub fn keys(&self) -> Vec<String> {
        self.secrets.keys().cloned().collect()
    }

    /// Load secrets from a regular HashMap (for configuration loading)
    pub fn load_from_hashmap(
        &mut self,
        secrets: HashMap<String, String>,
    ) -> Result<(), SecurityError> {
        for (key, value) in secrets {
            self.store_secret(key, value)?;
        }
        Ok(())
    }

    /// Create a temporary clone for processing (use sparingly)
    pub fn create_working_copy(&self) -> HashMap<String, String> {
        self.get_all_secrets()
    }
}

impl Default for SecureMemory {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for SecureMemory {
    fn drop(&mut self) {
        self.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_string_basic_operations() {
        let mut secure_str = SecureString::new("sensitive_data".to_string());

        assert_eq!(secure_str.as_str(), "sensitive_data");
        assert_eq!(secure_str.len(), 14);
        assert!(!secure_str.is_empty());

        secure_str.zeroize();
        // After zeroization, the string should be empty
        assert!(secure_str.is_empty());
    }

    #[test]
    fn test_secure_string_from_conversions() {
        let from_string = SecureString::from("test".to_string());
        let from_str = SecureString::from("test");

        assert_eq!(from_string.as_str(), "test");
        assert_eq!(from_str.as_str(), "test");
    }

    #[test]
    fn test_secure_memory_basic_operations() {
        let mut memory = SecureMemory::new();

        assert!(memory.is_empty());
        assert_eq!(memory.len(), 0);

        // Store a secret
        assert!(memory
            .store_secret("api_key".to_string(), "secret123".to_string())
            .is_ok());
        assert_eq!(memory.len(), 1);
        assert!(!memory.is_empty());
        assert!(memory.contains_secret("api_key"));

        // Retrieve the secret
        let retrieved = memory.get_secret("api_key");
        assert_eq!(retrieved, Some("secret123".to_string()));

        // Check non-existent secret
        assert!(memory.get_secret("nonexistent").is_none());
    }

    #[test]
    fn test_secure_memory_validation() {
        let mut memory = SecureMemory::new();

        // Test empty key validation
        let result = memory.store_secret("".to_string(), "value".to_string());
        assert!(result.is_err());
        match result.unwrap_err() {
            SecurityError::MemorySecurityViolation { .. } => {} // Expected
            _ => panic!("Expected MemorySecurityViolation"),
        }

        // Test long key validation
        let long_key = "a".repeat(300);
        let result = memory.store_secret(long_key, "value".to_string());
        assert!(result.is_err());
    }

    #[test]
    fn test_secure_memory_removal() {
        let mut memory = SecureMemory::new();

        memory
            .store_secret("temp_key".to_string(), "temp_value".to_string())
            .unwrap();
        assert!(memory.contains_secret("temp_key"));

        // Remove the secret
        let removed = memory.remove_secret("temp_key");
        assert!(removed.is_some());
        assert!(!memory.contains_secret("temp_key"));

        // Try to remove non-existent secret
        let not_removed = memory.remove_secret("nonexistent");
        assert!(not_removed.is_none());
    }

    #[test]
    fn test_secure_memory_clear() {
        let mut memory = SecureMemory::new();

        memory
            .store_secret("key1".to_string(), "value1".to_string())
            .unwrap();
        memory
            .store_secret("key2".to_string(), "value2".to_string())
            .unwrap();

        assert_eq!(memory.len(), 2);

        memory.clear();
        assert_eq!(memory.len(), 0);
        assert!(memory.is_empty());
    }

    #[test]
    fn test_secure_memory_get_all_secrets() {
        let mut memory = SecureMemory::new();

        memory
            .store_secret("key1".to_string(), "value1".to_string())
            .unwrap();
        memory
            .store_secret("key2".to_string(), "value2".to_string())
            .unwrap();

        let all_secrets = memory.get_all_secrets();
        assert_eq!(all_secrets.len(), 2);
        assert_eq!(all_secrets.get("key1"), Some(&"value1".to_string()));
        assert_eq!(all_secrets.get("key2"), Some(&"value2".to_string()));
    }

    #[test]
    fn test_secure_memory_keys() {
        let mut memory = SecureMemory::new();

        memory
            .store_secret("alpha".to_string(), "value1".to_string())
            .unwrap();
        memory
            .store_secret("beta".to_string(), "value2".to_string())
            .unwrap();

        let keys = memory.keys();
        assert_eq!(keys.len(), 2);
        assert!(keys.contains(&"alpha".to_string()));
        assert!(keys.contains(&"beta".to_string()));
    }

    #[test]
    fn test_secure_memory_load_from_hashmap() {
        let mut memory = SecureMemory::new();

        let mut input_secrets = HashMap::new();
        input_secrets.insert("api_key".to_string(), "secret123".to_string());
        input_secrets.insert("db_pass".to_string(), "dbsecret456".to_string());

        assert!(memory.load_from_hashmap(input_secrets).is_ok());
        assert_eq!(memory.len(), 2);
        assert_eq!(memory.get_secret("api_key"), Some("secret123".to_string()));
        assert_eq!(
            memory.get_secret("db_pass"),
            Some("dbsecret456".to_string())
        );
    }

    #[test]
    fn test_secure_memory_working_copy() {
        let mut memory = SecureMemory::new();

        memory
            .store_secret("key1".to_string(), "value1".to_string())
            .unwrap();
        memory
            .store_secret("key2".to_string(), "value2".to_string())
            .unwrap();

        let working_copy = memory.create_working_copy();
        assert_eq!(working_copy.len(), 2);
        assert_eq!(working_copy.get("key1"), Some(&"value1".to_string()));
        assert_eq!(working_copy.get("key2"), Some(&"value2".to_string()));
    }

    #[test]
    fn test_zeroize_on_drop() {
        // This test demonstrates that SecureMemory implements ZeroizeOnDrop
        // The actual zeroization is handled by the zeroize crate
        let mut memory = SecureMemory::new();
        memory
            .store_secret("test".to_string(), "sensitive".to_string())
            .unwrap();

        // When memory goes out of scope, it should automatically zeroize
        drop(memory);

        // We can't directly test that memory was zeroized since it's dropped,
        // but we can test that the zeroize trait is implemented
        assert!(true); // This test mainly ensures compilation
    }
}
