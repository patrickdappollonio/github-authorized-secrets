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

## Installation

### Binary Releases

Download pre-built binaries from the [releases page](https://github.com/patrickdappollonio/github-authorized-secrets/releases). There are binaries for Linux, macOS, and Windows.

### Homebrew

Homebrew is available on macOS and Linux:

```bash
brew install patrickdappollonio/tap/github-authorized-secrets
```

### Docker

We provide Docker images for a full version and a major version tag. The major version tag is recommended for production use, and to get the latest updates without breaking changes:

```bash
# Use stable v1 version (minor and patch changes shouldn't break anything)
docker pull ghcr.io/patrickdappollonio/github-authorized-secrets:v1

# Or use the latest version
docker pull ghcr.io/patrickdappollonio/github-authorized-secrets:latest
```

## Quick Start

Launching `github-authorized-secrets` is quite simple, especially if you're not using local testing:

### 1. Create Configuration

Create a `config.toml` file:

```toml
[server]
host = "127.0.0.1"
port = 8080
jwt_cache_duration = 300

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

### 2. Start the Server

Launch the server with the configuration file you just created:

```bash
./github-authorized-secrets server --config config.toml
```

> [!NOTE]
> 💡 **Quick Testing**: Want to test locally without GitHub Actions? Add `--local-testing` to the command above and see the [Local Testing](#local-testing) section for a complete development workflow.

### 3. Use in GitHub Actions

Now you can use the `github-authorized-secrets` client to pull secrets into your GitHub Actions workflow.

Here's an example workflow that loads secrets for the `octocat/api` repository:

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
          ./github-authorized-secrets pull --format bash --prefix DEPLOY_ --uppercase >> $GITHUB_ENV
        env:
          HOST: secrets.example.com

      - name: Deploy
        run: |
          echo "API Key: $DEPLOY_API_KEY"
          echo "Database: $DEPLOY_DATABASE_URL"
```

Note here a few options have been used:

* The `HOST` environment variable is set to the host of the server.
* The `--format bash` flag is used to output the secrets in a format that can be used in a bash script.
* The `--prefix DEPLOY_` flag is used to prefix the secret keys with `DEPLOY_`.
* The `--uppercase` flag is used to convert the secret keys to uppercase.

## Configuration

The configuration uses TOML format with several sections:

### Server Configuration

```toml
[server]
host = "127.0.0.1"      # Server bind address
port = 8080             # Server port
jwt_cache_duration = 300 # JWK cache duration in seconds
```

### Validation Rules (Optional)

```toml
[validation]
required_claims = ["repository", "repository_owner"]           # Required JWT claims
allowed_issuers = ["https://token.actions.githubusercontent.com"] # Allowed token issuers
max_token_age = 300     # Maximum token age in seconds
```

### Repository Secrets

Map repositories to their secrets using the format `[owner.repository]`:

```toml
[github.octocat]
api_key = "secret_value"
database_url = "postgresql://user:pass@localhost/db"

[organization.private-repo]
deploy_key = """-----BEGIN RSA PRIVATE KEY-----
<redacted>
"""
```

### Security Configuration

GitHub Authorized Secrets provides comprehensive security configuration options to balance protection with usability. All security settings are optional and have sensible defaults that work well for scriptable tools.

Add a `[security]` section to your `config.toml` to customize security behavior:

```toml
[security]
# Core security settings
production_mode = false                   # Enable stricter security defaults
detailed_audit_logging = false            # Log detailed security events

# User agent restrictions
enable_user_agent_blocking = false        # Allow curl, wget, and other tools
blocked_user_agents = ["python-requests"] # List of blocked user agents (when enabled)

# Protocol and connection security
require_https = false                     # Require HTTPS (overrides production_mode)
allow_insecure_host = false               # Allow binding to 0.0.0.0 in production
allow_http_behind_proxy = false           # Allow HTTP when TLS terminated at load balancer

# Rate limiting
max_auth_failures_per_hour = 100          # Maximum failed authentications per hour
max_secret_access_per_minute = 60         # Maximum secret access attempts per minute

# Token validation
min_token_length = 100                    # Minimum JWT token length in characters

# Threat detection (can be disabled for testing)
enable_sql_injection_detection = true       # Detect SQL injection patterns in repo names
enable_path_traversal_detection = true      # Detect path traversal attempts in repo names
enable_suspicious_activity_detection = true # Enable general suspicious activity detection
enable_secure_memory = true                 # Use secure memory for secrets storage
```

> [!TIP]
> 💡 **Local testing disables security settings**:
> When using the `--local-testing` flag, security settings are automatically relaxed for development.
> See [Local Testing](#local-testing) for more details.

#### Security Settings Explained

**User Agent Blocking**
- `enable_user_agent_blocking` (default: `false`): When `false`, allows all user agents including curl, wget, and automation tools
- `blocked_user_agents` (default: `["python-requests"]`): List of user agent strings to block (case-insensitive substring matching)

**Protocol Security**
- `require_https` (default: depends on `production_mode`): When `true`, rejects all HTTP requests, requires HTTPS
- `allow_insecure_host` (default: `false`): Controls whether binding to `0.0.0.0` is allowed in production mode
- `allow_http_behind_proxy` (default: `false`): Allows HTTP backends in production when TLS is terminated at load balancer/proxy level

**Rate Limiting**
- `max_auth_failures_per_hour` (default: `100`): Maximum number of authentication failures allowed per hour
- `max_secret_access_per_minute` (default: `60`): Maximum number of secret access requests per minute

**Token Validation**
- `min_token_length` (default: `100`): Minimum length for JWT tokens in characters

**Threat Detection**
- `enable_sql_injection_detection` (default: `true`): Scans repository names for SQL injection patterns
- `enable_path_traversal_detection` (default: `true`): Detects path traversal attempts in repository names
- `enable_suspicious_activity_detection` (default: `true`): General suspicious activity monitoring
- `enable_secure_memory` (default: `true`): Uses secure memory allocation for storing secrets

#### Production vs Development Defaults

**Production Mode** (`production_mode = true`):
- Requires HTTPS by default
- Stricter validation rules
- Enhanced security logging
- Rejects insecure configurations

**Development Mode** (`production_mode = false`, default):
- Allows HTTP connections
- More permissive settings
- Suitable for local development
- User agent blocking disabled by default

#### Example Configurations

**Minimal Security Configuration** (for most users):
```toml
[server]
host = "127.0.0.1"
port = 8080
jwt_cache_duration = 300

[security]
# Explicitly allow curl, wget, and other automation tools
enable_user_agent_blocking = false

[github.myorg]
api_key = "your_secret_here"
```

**High Security Configuration** (for production):
```toml
[server]
host = "127.0.0.1"  # Don't bind to 0.0.0.0
port = 8443
enable_tls = true
tls_cert_path = "/path/to/cert.pem"
tls_key_path = "/path/to/key.pem"

[security]
production_mode = true
detailed_audit_logging = true
require_https = true
enable_user_agent_blocking = true
blocked_user_agents = ["curl", "wget", "python-requests", "postman"]
max_auth_failures_per_hour = 50
max_secret_access_per_minute = 30
min_token_length = 150
# All threat detection enabled (defaults)
```

**TLS Termination at Load Balancer** (common production pattern):
```toml
[server]
host = "127.0.0.1"
port = 8080        # HTTP backend, TLS terminated at load balancer
jwt_cache_duration = 300

[security]
production_mode = true
allow_http_behind_proxy = true  # Allow HTTP when TLS terminated upstream
require_https = false           # Don't require HTTPS at application level
detailed_audit_logging = true

[github.myorg]
api_key = "your_secret_here"
```

## Usage

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

### GitHub Actions Integration

#### Required Permissions

Your workflow must include these permissions:

```yaml
permissions:
  id-token: write    # Required for OIDC token
  contents: read     # Standard permission
```

#### Usage Examples

**Basic Secret Loading:**
```yaml
- name: Load secrets
  run: |
    curl -L https://github.com/patrickdappollonio/github-authorized-secrets/releases/latest/download/github-authorized-secrets-linux-x86_64.tar.gz | tar xz
    chmod +x github-authorized-secrets
    ./github-authorized-secrets pull --host secrets.example.com --format bash >> $GITHUB_ENV
  env:
    HOST: secrets.example.com
```

**Environment-Specific Deployments:**
```yaml
- name: Load production secrets
  run: |
    ./github-authorized-secrets pull --host secrets.example.com --format bash --prefix PROD_ --uppercase >> $GITHUB_ENV

- name: Deploy to production
  run: |
    deploy-script --api-key="$PROD_API_KEY" --db-url="$PROD_DATABASE_URL"
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

# Token creation for different repository
./github-authorized-secrets sign --repository "myorg/myrepo"
```

The `sign` command outputs:
- **JWT Token**: Ready to use with API calls
- **Token Claims**: Human-readable claim details
- **JWKs JSON**: Public keys for server validation
- **Test Command**: curl example you can copy/paste

For scripting, use the `--token-only` flag to output just the token:

```bash
# Get only the token (perfect for shell variables)
TOKEN=$(./github-authorized-secrets sign --repository "github/octocat" --token-only)
```

#### 3. Test the Complete Flow

Here's a complete local testing workflow:

```bash
# Terminal 1: Start server in local mode
./github-authorized-secrets server --config config.toml --local-testing

# Terminal 2: Use the improved CLI workflow
# The sign command now automatically fetches tokens from the running server!
TOKEN=$(./github-authorized-secrets sign --repository "github/octocat" --token-only)

# Test the health endpoint
curl http://localhost:8080/health

# Test JWKs endpoint (shows the server's public keys)
curl http://localhost:8080/.well-known/jwks

# Pull secrets using the CLI (recommended method)
./github-authorized-secrets pull --host localhost:8080 --scheme http --token "$TOKEN"

# Or use curl directly
curl -X POST -H "Authorization: Bearer $TOKEN" http://localhost:8080/secrets

# List repositories
./github-authorized-secrets list --host localhost:8080 --scheme http --token "$TOKEN"
```

#### Server-Integrated Token Generation

The `sign` command now automatically connects to your running local server to generate tokens using the server's actual keys:

```bash
# Start server
./github-authorized-secrets server --config config.toml --local-testing

# Generate token (automatically uses server's keys)
./github-authorized-secrets sign --repository "github/octocat" --token-only

# Use token immediately with pull command
./github-authorized-secrets pull --host localhost:8080 --scheme http --token "$(./github-authorized-secrets sign --repository 'github/octocat' --token-only)"
```

**Benefits of server-integrated token generation:**
- ✅ Tokens always match the server's current keys
- ✅ No key synchronization issues
- ✅ Consistent behavior between sign and server
- ✅ Better error handling and validation

#### Important: Use HTTP Scheme for Local Testing

Local testing servers run HTTP (not HTTPS) by default. Always specify `--scheme http`:

```bash
# ✅ Correct - uses HTTP for local testing
./github-authorized-secrets pull --host localhost:8080 --scheme http --token "$TOKEN"

# ❌ Wrong - defaults to HTTPS and will fail with TLS errors
./github-authorized-secrets pull --host localhost:8080 --token "$TOKEN"
```

The CLI now provides helpful error messages:
- **TLS/SSL errors**: "TLS/SSL error - you may be using HTTPS with an HTTP-only server. Try adding --scheme http"
- **401 Unauthorized**: "unauthorized - invalid or expired token"
- **Connection refused**: "connection refused - is the server running?"

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

#### Example 1: Your First Local Test

Let's start your development server and test it with a real repository:

```bash
./github-authorized-secrets server --config config.toml --local-testing
```

Great! Your server is now running on `localhost:8080` and has generated its own RSA keys for testing. You'll see some startup logs showing the server configuration. Keep this terminal open - the server needs to stay running.

Now open a new terminal. Let's check if the server is healthy:

```bash
curl http://localhost:8080/health
```

Perfect! You should see `{"status":"healthy"}`. This means your server is ready to handle requests.

Next, let's see what cryptographic keys your server generated:

```bash
curl http://localhost:8080/.well-known/jwks | jq
```

You'll see a JSON response with RSA public keys. These keys are what your server will use to verify JWT tokens. Notice the `kid` (key ID) field - this identifies which key signed a token.

Now let's generate your first test token. This command will connect to your running server and get a properly signed JWT:

```bash
./github-authorized-secrets sign --repository "github/octocat" --token-only
```

Copy that token! Your server just generated it using the same keys it will use to verify it. This eliminates the key mismatch problems you might have encountered before.

Now let's use that token to fetch secrets:

```bash
./github-authorized-secrets pull --host localhost:8080 --scheme http --token "paste-your-token-here"
```

You should see the secrets for the `github/octocat` repository from your configuration. Notice we use `--scheme http` because your local server runs HTTP, not HTTPS.

Want to test another repository? Just repeat the process:

```bash
./github-authorized-secrets sign --repository "myorg/frontend" --token-only
```

Then use that new token to pull secrets for the frontend repository. Each repository might have different secrets based on your configuration file.

#### Example 2: Exploring Output Formats

Assuming your server is still running from Example 1, let's explore how secrets can be formatted for different use cases.

First, get a fresh token:

```bash
./github-authorized-secrets sign --repository "github/octocat" --token-only
```

By default, secrets are displayed in a human-readable table format. But let's try JSON format, which is perfect for processing with other tools:

```bash
./github-authorized-secrets pull --host localhost:8080 --scheme http --token "your-token-here" --format json
```

Now you'll see the secrets as structured JSON. This is great for piping to `jq` or parsing in scripts.

For shell scripting, the environment variable format is more useful:

```bash
./github-authorized-secrets pull --host localhost:8080 --scheme http --token "your-token-here" --format env
```

This outputs `KEY=value` pairs that you can source directly in bash. Even better, you can get proper bash export statements:

```bash
./github-authorized-secrets pull --host localhost:8080 --scheme http --token "your-token-here" --format bash
```

Want to add a prefix to avoid name collisions? Try this:

```bash
./github-authorized-secrets pull --host localhost:8080 --scheme http --token "your-token-here" --format bash --prefix "DEPLOY_" --uppercase
```

Now all your secret names will be prefixed with `DEPLOY_` and converted to uppercase - perfect for deployment scripts!

#### Example 3: Understanding Error Messages

Let's explore the helpful error messages by making some common mistakes. Don't worry - these are intentional errors that help you understand what went wrong!

First, let's see what happens when you forget the `--scheme http` flag and try to use HTTPS with your HTTP server:

```bash
./github-authorized-secrets pull --host localhost:8080 --token "fake-token"
```

You'll see: `TLS/SSL error - you may be using HTTPS with an HTTP-only server. Try adding --scheme http`

This error message immediately tells you the problem and how to fix it. Much better than cryptic "record overflow" messages!

Now let's try using the right scheme but with an invalid token:

```bash
./github-authorized-secrets pull --host localhost:8080 --scheme http --token "fake-token"
```

You'll get: `unauthorized - invalid or expired token`

This clearly indicates your token is the problem, not your connection or configuration.

Finally, let's see what happens when the server isn't running. Stop your server (Ctrl+C in the server terminal), then try:

```bash
./github-authorized-secrets pull --host localhost:8080 --scheme http --token "fake-token"
```

Now you'll see: `connection refused - is the server running?`

The error messages guide you toward the solution instead of leaving you guessing. Start your server again to continue with the next example!

#### Example 4: Quick Verification Workflow

Need to quickly verify everything is working? Here's the fastest way to test your setup.

Start your server:

```bash
./github-authorized-secrets server --config config.toml --local-testing
```

In a new terminal, verify it's alive:

```bash
curl http://localhost:8080/health
```

You should see a healthy status. Now generate and use a token in one smooth workflow:

```bash
./github-authorized-secrets sign --repository "github/octocat" --token-only
```

Copy that token and immediately use it:

```bash
./github-authorized-secrets pull --host localhost:8080 --scheme http --token "<paste-token-here>"
```

Perfect! Your secrets should appear. Want to see which repositories you have access to?

```bash
./github-authorized-secrets list --host localhost:8080 --scheme http --token "<same-token-here>"
```

This gives you a complete overview of your configured repositories. The beauty of this workflow is that the `sign` command connects directly to your running server, so tokens are always compatible. No more key mismatch headaches!

### Security Warnings

🚨 **IMPORTANT**: Local testing mode should **NEVER** be used in production:

- Local testing bypasses GitHub's official JWT validation
- RSA keys are generated locally and are not secure for production use
- Warning messages are displayed when local testing is active
- The server will log warnings about local testing mode being enabled
- **The `/sign-token` endpoint is only available in local testing mode** and is automatically disabled in production

**Security Features:**
- ✅ **Router-level protection**: The `/sign-token` endpoint route is only registered when `--local-testing` is enabled
- ✅ **Handler-level validation**: Double-checks that local testing mode is active before signing tokens
- ✅ **Production safety**: Endpoint returns 404 in production mode (route doesn't exist)
- ✅ **Clear warnings**: Server logs prominent warnings when local testing is active

**Always ensure local testing is disabled for production deployments.**

## Deployment

### Docker Deployment

```dockerfile
FROM ghcr.io/patrickdappollonio/github-authorized-secrets:latest

# Copy your configuration
COPY config.toml /config/config.toml

# Run as non-root user
USER 1000:1000

EXPOSE 8080

CMD ["github-authorized-secrets", "server", "--config", "/config/config.toml"]
```

### Kubernetes Deployment

#### Configuration Secret

First, create a Kubernetes Secret containing your configuration file:

```bash
# Create the secret from your config.toml file
kubectl create secret generic github-authorized-secrets-config \
  --from-file=config.toml=./config.toml
```

#### Production Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: github-authorized-secrets
  namespace: default
spec:
  replicas: 2
  selector:
    matchLabels:
      app: github-authorized-secrets
  template:
    metadata:
      labels:
        app: github-authorized-secrets
    spec:
      containers:
      - name: github-authorized-secrets
        image: ghcr.io/patrickdappollonio/github-authorized-secrets:latest
        ports:
        - containerPort: 8080
          name: http
        args:
          - "server"
          - "--config"
          - "/config/config.toml"
        volumeMounts:
        - name: config-volume
          mountPath: /config
          readOnly: true
        resources:
          requests:
            cpu: 100m
            memory: 128Mi
          limits:
            cpu: 500m
            memory: 256Mi
        securityContext:
          runAsNonRoot: true
          runAsUser: 1000
          runAsGroup: 1000
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          capabilities:
            drop:
            - ALL
        livenessProbe:
          httpGet:
            path: /health
            port: http
          initialDelaySeconds: 10
          periodSeconds: 30
        readinessProbe:
          httpGet:
            path: /health
            port: http
          initialDelaySeconds: 5
          periodSeconds: 10
      volumes:
      - name: config-volume
        secret:
          secretName: github-authorized-secrets-config
```

#### Service

```yaml
apiVersion: v1
kind: Service
metadata:
  name: github-authorized-secrets
  namespace: default
spec:
  selector:
    app: github-authorized-secrets
  ports:
  - name: http
    port: 80
    targetPort: 8080
    protocol: TCP
  type: ClusterIP
```

#### Ingress (Optional)

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: github-authorized-secrets
  annotations:
    kubernetes.io/ingress.class: nginx
    cert-manager.io/cluster-issuer: letsencrypt-prod  # If using cert-manager
spec:
  tls:
  - hosts:
    - secrets.yourdomain.com
    secretName: github-authorized-secrets-tls
  rules:
  - host: secrets.yourdomain.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: github-authorized-secrets
            port:
              number: 80
```

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

## Security Considerations

### Core Security Features

#### JWT Validation
- Uses GitHub's official JWKs for token validation
- Strict validation of token expiration and issuer
- Configurable token age limits and minimum token length
- Only accepts RS256 algorithm
- Configurable validation rules and allowed issuers

#### Secret Management
- Secrets are loaded from configuration at startup
- No secrets are logged or exposed in responses
- Automatic secret masking in GitHub Actions logs
- Repository-based access control
- Optional secure memory allocation with automatic zeroing

#### Network Security
- Configurable HTTPS requirements
- Built-in rate limiting with customizable thresholds
- CORS settings for web browser compatibility
- User agent filtering (disabled by default for scriptability)
- Host binding restrictions in production mode

#### Threat Detection
- SQL injection pattern detection in repository names
- Path traversal attempt detection
- Suspicious activity monitoring and logging
- All detection features can be customized or disabled

### Best Practices

- **Use HTTPS in production**: Set `require_https = true` in your security configuration
- **Secure configuration files**: Set appropriate file permissions (600) on config.toml
- **Monitor security logs**: Enable `detailed_audit_logging = true` for production environments
- **Regular token rotation**: GitHub Actions tokens are short-lived, but monitor for unusual patterns
- **Network isolation**: Deploy behind a reverse proxy or API gateway when possible
- **Resource limits**: Configure appropriate rate limits based on your CI/CD load patterns

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

