# GitHub Authorized Secrets

A secure secret management system for GitHub Actions workflows that validates GitHub Actions JWT tokens and returns repository-specific secrets.

## Overview

GitHub Authorized Secrets provides a secure way to manage secrets for GitHub Actions workflows by:

- **Validating GitHub Actions JWT tokens** using GitHub's JWKs (JSON Web Key Sets)
- **Mapping repositories to secrets** through TOML configuration
- **Providing a REST API** for secure secret retrieval
- **Offering a CLI client** with automatic token handling and multiple output formats
- **Supporting key transformations** with prefix and uppercase options for different deployment environments

## Features

- 🔐 **Secure JWT Validation**: Uses GitHub's official JWKs for token validation
- 🏢 **Repository-based Access Control**: Maps specific repositories to their secrets
- 🚀 **Zero-Config GitHub Actions Integration**: Automatically fetches tokens in CI/CD
- 🎯 **Multiple Output Formats**: JSON, Bash exports, environment variables, YAML
- 🔄 **Key Transformations**: Add prefixes and convert to uppercase for environment-specific deployments
- 🛡️ **Automatic Secret Masking**: Masks sensitive values in GitHub Actions logs
- ⚡ **High Performance**: Sub-100ms response times with efficient JWK caching
- 🐳 **Docker Ready**: Includes Docker deployment examples

## Quick Start

### 1. Install

```bash
# Download the latest release for your platform
curl -L https://github.com/patrickdappollonio/github-authorized-secrets/releases/latest/download/github-authorized-secrets-linux-x86_64.tar.gz | tar xz
chmod +x github-authorized-secrets
```

### 2. Create Configuration

Create a `config.toml` file:

```toml
[server]
host = "127.0.0.1"
port = 8080
jwt_cache_duration = 300

[validation]
required_claims = ["repository", "repository_owner"]
allowed_issuers = ["https://token.actions.githubusercontent.com"]
max_token_age = 300

# Repository secrets mapping (format: [owner.repository])
[github.octocat]
api_key = "your_api_key_here"
database_url = "postgresql://user:pass@localhost/db"
deployment_token = "ghp_xxxxxxxxxxxx"

[acme-corp.web-app]
deploy_key = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQAB..."
webhook_secret = "supersecret"
redis_url = "redis://redis:6379"
```

### 3. Start the Server

```bash
./github-authorized-secrets server --config config.toml
```

### 4. Use in GitHub Actions

```yaml
name: Deploy
on: [push]

permissions:
  id-token: write  # Required for OIDC token
  contents: read

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - name: Download secrets client
        run: |
          curl -L https://github.com/patrickdappollonio/github-authorized-secrets/releases/latest/download/github-authorized-secrets-linux-x86_64.tar.gz | tar xz
          chmod +x github-authorized-secrets

      - name: Load secrets
        run: |
          ./github-authorized-secrets pull --host secrets.example.com --format bash --prefix DEPLOY_ --uppercase >> $GITHUB_ENV

      - name: Deploy
        run: |
          echo "API Key: $DEPLOY_API_KEY"
          echo "Database: $DEPLOY_DATABASE_URL"
```

## Installation

### Binary Releases

Download pre-built binaries from the [releases page](https://github.com/patrickdappollonio/github-authorized-secrets/releases). There are binaries for Linux, macOS, and Windows.

### Docker

```bash
# Use stable v1 version (minor and patch changes shouldn't break anything)
docker pull ghcr.io/patrickdappollonio/github-authorized-secrets:v1

# Or use the latest version
docker pull ghcr.io/patrickdappollonio/github-authorized-secrets:latest
```

## Configuration

### Configuration File Format

The configuration uses TOML format with three main sections:

#### Server Configuration

```toml
[server]
host = "127.0.0.1"      # Server bind address
port = 8080             # Server port
jwt_cache_duration = 300 # JWK cache duration in seconds
```

#### Validation Rules (Optional)

```toml
[validation]
required_claims = ["repository", "repository_owner"]           # Required JWT claims
allowed_issuers = ["https://token.actions.githubusercontent.com"] # Allowed token issuers
max_token_age = 300     # Maximum token age in seconds
```

#### Repository Secrets

Map repositories to their secrets using the format `[owner.repository]`:

```toml
[github.octocat]
api_key = "secret_value"
database_url = "postgresql://user:pass@localhost/db"

[organization.private-repo]
deploy_key = """-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA...
-----END RSA PRIVATE KEY-----"""
```

## CLI Usage

### Server Commands

```bash
# Start server with default config
./github-authorized-secrets server

# Start server with custom config
./github-authorized-secrets server --config /path/to/config.toml
```

### Client Commands

#### Pull Secrets

```bash
# Basic usage (automatically detects GitHub Actions)
./github-authorized-secrets pull --host secrets.example.com

# With custom format
./github-authorized-secrets pull --host secrets.example.com --format json

# With key transformations
./github-authorized-secrets pull --host secrets.example.com --format bash --prefix PROD_ --uppercase

# Manual token (for testing outside GitHub Actions)
./github-authorized-secrets pull --host secrets.example.com --token "jwt_token_here"

# Custom audience
./github-authorized-secrets pull --host secrets.example.com --audience "my-service"
```

#### List Repositories

```bash
# List available repositories
./github-authorized-secrets list --host secrets.example.com
```

### Output Formats

#### Environment Variables (`--format env`)
```
API_KEY=secret123
DATABASE_URL=postgresql://localhost/db
```

#### Bash Exports (`--format bash`)
```bash
export API_KEY='secret123'
export DATABASE_URL='postgresql://localhost/db'
```

#### JSON (`--format json`)
```json
{
  "api_key": "secret123",
  "database_url": "postgresql://localhost/db"
}
```

#### YAML (`--format yaml`)
```yaml
api_key: secret123
database_url: postgresql://localhost/db
```

### Key Transformations

Transform secret keys for different environments:

```bash
# Add prefix and convert to uppercase
./github-authorized-secrets pull --host secrets.example.com --prefix PROD_ --uppercase
# Output: PROD_API_KEY=secret123

# Just add prefix
./github-authorized-secrets pull --host secrets.example.com --prefix staging_
# Output: staging_api_key=secret123

# Just uppercase
./github-authorized-secrets pull --host secrets.example.com --uppercase
# Output: API_KEY=secret123
```

## Local Testing

For development and testing purposes, GitHub Authorized Secrets provides a local testing mode that bypasses GitHub's JWT validation and allows you to create your own test tokens.

### Why Local Testing?

- **Development**: Test your configuration without needing actual GitHub Actions
- **CI/CD Testing**: Validate your setup in local environments
- **Integration Testing**: Create controlled test scenarios with custom JWT claims
- **Debugging**: Troubleshoot token validation and secret retrieval locally

### Setting Up Local Testing

#### 1. Start Server in Local Testing Mode

```bash
# Start with local testing enabled
./github-authorized-secrets server --config config.toml --local-testing

# Generate multiple key pairs for testing
./github-authorized-secrets server --config config.toml --local-testing --local-keys 2

# Override host/port for testing
./github-authorized-secrets server --config config.toml --local-testing --host 127.0.0.1 --port 9090
```

When local testing mode is enabled:
- Server generates RSA key pairs automatically
- JWKs (JSON Web Key Sets) are printed to console for reference
- A `/.well-known/jwks` endpoint serves the public keys
- **⚠️ WARNING messages** are displayed (never use in production!)

#### 2. Create Test JWT Tokens

Use the `sign` command to create valid JWT tokens for testing:

```bash
# Basic token creation
./github-authorized-secrets sign --repository "github/octocat"

# Full token with custom claims
./github-authorized-secrets sign \
  --repository "myorg/myrepo" \
  --workflow "Deploy to Production" \
  --actor "john-doe" \
  --ref "refs/heads/main" \
  --sha "abc123def456" \
  --audience "my-custom-audience"
```

The `sign` command outputs:
- **JWT Token**: Ready to use with API calls
- **Token Claims**: Human-readable claim details
- **JWKs JSON**: Public keys for server validation
- **Test Command**: curl example you can copy/paste

#### 3. Test the Complete Flow

Here's a complete local testing workflow:

```bash
# Terminal 1: Start server in local mode
./github-authorized-secrets server --config config.toml --local-testing

# Terminal 2: Create a test token and use it
# Create token for a repository you have configured
TOKEN=$(./github-authorized-secrets sign --repository "github/octocat" | grep -A1 "Generated JWT Token:" | tail -1)

# Test the health endpoint
curl http://localhost:8080/health

# Test JWKs endpoint
curl http://localhost:8080/.well-known/jwks

# Get secrets using the test token
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/secrets

# List repositories
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/secrets/repositories
```

### Configuration for Local Testing

You can also enable local testing via configuration or environment variables:

#### TOML Configuration
```toml
[server]
host = "127.0.0.1"
port = 8080
local_testing_mode = true
local_testing_num_keys = 1
```

#### Environment Variables
```bash
export LOCAL_TESTING_MODE=true
export SERVER_HOST=127.0.0.1
export SERVER_PORT=8080

./github-authorized-secrets server --config config.toml
```

### Local Testing Examples

#### Example 1: Test Different Repositories

```bash
# Create tokens for different repos
./github-authorized-secrets sign --repository "acme/frontend" --workflow "Deploy Frontend"
./github-authorized-secrets sign --repository "acme/backend" --workflow "Deploy API"
./github-authorized-secrets sign --repository "acme/mobile" --workflow "Build App"
```

#### Example 2: Test Token Expiration

Tokens expire after 10 minutes by default. Test token validation:

```bash
# Create a token
TOKEN=$(./github-authorized-secrets sign --repository "test/repo" | grep -A1 "Generated JWT Token:" | tail -1)

# Use it immediately (should work)
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/secrets

# Wait 11 minutes and try again (should fail with 401)
```

#### Example 3: Integration Testing Script

```bash
#!/bin/bash
set -e

echo "Starting local testing..."

# Start server in background
./github-authorized-secrets server --config test-config.toml --local-testing &
SERVER_PID=$!

# Wait for server to start
sleep 2

# Test various repositories
for repo in "github/octocat" "myorg/frontend" "myorg/backend"; do
    echo "Testing repository: $repo"

    TOKEN=$(./github-authorized-secrets sign --repository "$repo" | grep -A1 "Generated JWT Token:" | tail -1)

    if curl -f -H "Authorization: Bearer $TOKEN" http://localhost:8080/secrets > /dev/null; then
        echo "✅ $repo: Success"
    else
        echo "❌ $repo: Failed"
    fi
done

# Clean up
kill $SERVER_PID
echo "Local testing complete!"
```

### Security Warnings

🚨 **IMPORTANT**: Local testing mode should **NEVER** be used in production:

- Local testing bypasses GitHub's official JWT validation
- RSA keys are generated locally and are not secure for production use
- Warning messages are displayed when local testing is active
- The server will log warnings about local testing mode being enabled

**Always ensure local testing is disabled for production deployments.**

## API Reference

### Authentication

All API endpoints (except `/health`) require a valid GitHub Actions JWT token in the Authorization header:

```
Authorization: Bearer <github_actions_jwt_token>
```

### Endpoints

#### `GET /health`

Health check endpoint.

**Response:**
```json
{
  "status": "healthy",
  "service": "github-authorized-secrets",
  "version": "1.0.0"
}
```

#### `POST /secrets`

Retrieve secrets for the authenticated repository.

**Headers:**
- `Authorization: Bearer <jwt_token>`

**Response:**
```json
{
  "repository": "owner/repo",
  "secrets": {
    "api_key": "secret_value",
    "database_url": "postgresql://..."
  },
  "metadata": {
    "retrieved_at": "2024-01-01T12:00:00Z",
    "repository_owner": "owner"
  }
}
```

**Error Responses:**
- `401 Unauthorized`: Invalid or missing JWT token
- `404 Not Found`: Repository not configured
- `403 Forbidden`: Token validation failed

#### `GET /secrets/repositories`

List all available repositories.

**Headers:**
- `Authorization: Bearer <jwt_token>`

**Response:**
```json
{
  "repositories": [
    "owner/repo1",
    "owner/repo2",
    "org/project"
  ]
}
```

## GitHub Actions Integration

### Required Permissions

Your workflow must include these permissions:

```yaml
permissions:
  id-token: write    # Required for OIDC token
  contents: read     # Standard permission
```

### Usage Examples

#### Basic Secret Loading

```yaml
- name: Load secrets
  run: |
    curl -L https://github.com/patrickdappollonio/github-authorized-secrets/releases/latest/download/github-authorized-secrets-linux-x86_64.tar.gz | tar xz
    chmod +x github-authorized-secrets
    ./github-authorized-secrets pull --host secrets.example.com --format bash >> $GITHUB_ENV
  env:
    HOST: secrets.example.com
```

#### Environment-Specific Deployments

```yaml
- name: Load production secrets
  run: |
    ./github-authorized-secrets pull --host secrets.example.com --format bash --prefix PROD_ --uppercase >> $GITHUB_ENV

- name: Deploy to production
  run: |
    deploy-script --api-key="$PROD_API_KEY" --db-url="$PROD_DATABASE_URL"
```

#### Multiple Environments

```yaml
- name: Load secrets for staging
  if: github.ref == 'refs/heads/develop'
  run: |
    ./github-authorized-secrets pull --host secrets.example.com --audience staging --format env --prefix STAGING_ >> $GITHUB_ENV

- name: Load secrets for production
  if: github.ref == 'refs/heads/main'
  run: |
    ./github-authorized-secrets pull --host secrets.example.com --audience production --format env --prefix PROD_ >> $GITHUB_ENV
```

## Docker Deployment

### Production Deployment

```dockerfile
FROM ghcr.io/patrickdappollonio/github-authorized-secrets:latest

# Copy your configuration
COPY config.toml /config/config.toml

# Run as non-root user
USER 1000:1000

EXPOSE 8080

CMD ["github-authorized-secrets", "server", "--config", "/config/config.toml"]
```

## Security Considerations

### JWT Validation
- Uses GitHub's official JWKs for token validation
- Strict validation of token expiration and issuer
- Configurable token age limits
- Only accepts RS256 algorithm

### Secret Management
- Secrets are loaded from configuration at startup
- No secrets are logged or exposed in responses
- Automatic secret masking in GitHub Actions logs
- Repository-based access control

### Network Security
- Use HTTPS in production
- Configure appropriate CORS settings
- Implement rate limiting (recommended)
- Use secure configuration file permissions (600)

## Troubleshooting

### Common Issues

#### "Not running in GitHub Actions environment"
- **Cause**: CLI client can't find GitHub Actions environment variables
- **Solution**: Either run inside GitHub Actions or provide a manual token with `--token`

#### "Token validation failed"
- **Cause**: Invalid JWT token or expired token
- **Solution**: Check token validity and ensure proper GitHub Actions permissions

#### "Repository not found"
- **Cause**: Repository not configured in TOML file
- **Solution**: Add repository configuration in format `[owner.repository]`

#### "Connection refused"
- **Cause**: Server not running or wrong host/port
- **Solution**: Check server status and verify host/port configuration

### Debug Mode

Enable debug logging:

```bash
RUST_LOG=debug ./github-authorized-secrets server --config config.toml
```

### Testing Configuration

Test your configuration file:

```bash
# Test server startup
./github-authorized-secrets server --config config.toml

# Test client connection (requires running server)
./github-authorized-secrets list --host localhost:8080 --scheme http --token "test_token"
```

