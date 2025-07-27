use chrono::{Duration, Utc};
use github_authorized_secrets::auth::GitHubClaims;
use jsonwebtoken::{encode, EncodingKey, Header};
use serde_json::json;
use std::collections::HashMap;

/// Create a test JWT token with default GitHub claims
pub fn create_test_jwt_token() -> String {
    create_test_jwt_token_with_claims(test_github_claims())
}

/// Create a test JWT token with custom claims
pub fn create_test_jwt_token_with_claims(claims: GitHubClaims) -> String {
    let mut header = Header::new(jsonwebtoken::Algorithm::RS256);
    header.kid = Some("test-key-1".to_string());

    // Use test private key (matching the public key in mock_jwks.json)
    let private_key = get_test_private_key();
    let encoding_key = EncodingKey::from_rsa_pem(private_key.as_bytes()).unwrap();

    encode(&header, &claims, &encoding_key).unwrap()
}

/// Create test GitHub claims with sensible defaults
pub fn test_github_claims() -> GitHubClaims {
    let now = Utc::now();
    GitHubClaims {
        iss: "https://token.actions.githubusercontent.com".to_string(),
        sub: "repo:github/octocat:ref:refs/heads/main".to_string(),
        aud: "https://github.com/github".to_string(),
        repository: "github/octocat".to_string(),
        repository_owner: "github".to_string(),
        repository_id: "123456789".to_string(),
        ref_: "refs/heads/main".to_string(),
        sha: "example_sha".to_string(),
        workflow: "CI".to_string(),
        actor: "octocat".to_string(),
        run_id: "987654321".to_string(),
        exp: (now + Duration::seconds(3600)).timestamp(),
        iat: now.timestamp(),
        nbf: now.timestamp(),
    }
}

/// Create expired test GitHub claims
pub fn expired_github_claims() -> GitHubClaims {
    let past = Utc::now() - Duration::seconds(3600);
    GitHubClaims {
        iss: "https://token.actions.githubusercontent.com".to_string(),
        sub: "repo:github/octocat:ref:refs/heads/main".to_string(),
        aud: "https://github.com/github".to_string(),
        repository: "github/octocat".to_string(),
        repository_owner: "github".to_string(),
        repository_id: "123456789".to_string(),
        ref_: "refs/heads/main".to_string(),
        sha: "example_sha".to_string(),
        workflow: "CI".to_string(),
        actor: "octocat".to_string(),
        run_id: "987654321".to_string(),
        exp: past.timestamp(),
        iat: past.timestamp(),
        nbf: past.timestamp(),
    }
}

/// Create test GitHub claims with invalid issuer
pub fn invalid_issuer_claims() -> GitHubClaims {
    let mut claims = test_github_claims();
    claims.iss = "https://evil.com".to_string();
    claims
}

/// Create test secrets HashMap
pub fn test_secrets() -> HashMap<String, String> {
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

/// Create test environment variables for GitHub Actions
pub fn setup_github_actions_env(token_url: &str, request_token: &str) {
    std::env::set_var("ACTIONS_ID_TOKEN_REQUEST_URL", token_url);
    std::env::set_var("ACTIONS_ID_TOKEN_REQUEST_TOKEN", request_token);
    std::env::set_var("GITHUB_ACTIONS", "true");
}

/// Clean up test environment variables
pub fn cleanup_github_actions_env() {
    std::env::remove_var("ACTIONS_ID_TOKEN_REQUEST_URL");
    std::env::remove_var("ACTIONS_ID_TOKEN_REQUEST_TOKEN");
    std::env::remove_var("GITHUB_ACTIONS");
}

/// Create a mock token response JSON
pub fn mock_token_response_json() -> String {
    json!({
        "value": create_test_jwt_token()
    })
    .to_string()
}

/// Read the test private key from file
pub fn get_test_private_key() -> String {
    std::fs::read_to_string("test_data/test_private_key.pem")
        .expect("Failed to read test private key")
}
