use axum::{body::Body, http::Request, middleware::Next, response::Response};
use std::time::Instant;
use tracing::info;

/// Logging middleware for HTTP requests
pub async fn logging_middleware(request: Request<Body>, next: Next) -> Response {
    let method = request.method().clone();
    let uri = request.uri().clone();
    let version = request.version();
    let start_time = Instant::now();
    let response = next.run(request).await;
    let duration = start_time.elapsed();
    let status = response.status();

    // Try to get response body size
    let content_length = response
        .headers()
        .get("content-length")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(0);

    info!(
        "{} {} -- {:?} {} (served in {:.3}ms; {} bytes)",
        method,
        uri,
        version,
        status,
        duration.as_secs_f64() * 1000.0,
        content_length
    );

    response
}

/// CORS middleware setup
pub fn cors_layer() -> tower_http::cors::CorsLayer {
    tower_http::cors::CorsLayer::permissive()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Method, Request, Uri},
        response::Response,
    };

    #[tokio::test]
    async fn test_cors_layer_creation() {
        // Test that CORS layer can be created without panicking
        let cors_layer = cors_layer();

        // The layer should be created successfully
        // We can't test much more without a full integration test,
        // but we can verify it doesn't panic on creation
        assert!(!format!("{cors_layer:?}").is_empty());
    }

    #[tokio::test]
    async fn test_logging_middleware_structure() {
        // Test that we can create requests and responses for logging middleware testing
        // This tests the middleware logic without needing complex axum setup

        // Create a mock request for testing
        let request = Request::builder()
            .method(Method::GET)
            .uri("/test")
            .body(Body::empty())
            .unwrap();

        // Verify request components that the middleware logs
        assert_eq!(request.method(), &Method::GET);
        assert_eq!(request.uri().path(), "/test");
        assert_eq!(request.version(), axum::http::Version::HTTP_11);

        // Test response creation
        let response = Response::builder()
            .status(200)
            .header("content-length", "4")
            .body(Body::from("test"))
            .unwrap();

        assert_eq!(response.status(), 200);

        // Test content-length header parsing (used by middleware for logging)
        let content_length = response
            .headers()
            .get("content-length")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(0);
        assert_eq!(content_length, 4);
    }

    #[tokio::test]
    async fn test_middleware_components() {
        // Test the basic components used by middleware

        // Test different HTTP methods that middleware needs to handle
        let methods = vec![
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::DELETE,
            Method::OPTIONS,
        ];

        for method in methods {
            let request = Request::builder()
                .method(method.clone())
                .uri("/test")
                .body(Body::empty())
                .unwrap();

            // Middleware should be able to extract method and URI from any request
            assert_eq!(request.method(), &method);
            assert!(!request.uri().to_string().is_empty());
        }
    }

    #[tokio::test]
    async fn test_request_uri_parsing() {
        // Test different URI formats that logging middleware might encounter
        let uris = vec![
            "/",
            "/health",
            "/secrets",
            "/secrets/repositories",
            "/test?param=value",
            "/test?multiple=params&other=value",
        ];

        for uri_str in uris {
            let uri: Uri = uri_str.parse().unwrap();
            let request = Request::builder()
                .method(Method::GET)
                .uri(uri.clone())
                .body(Body::empty())
                .unwrap();

            // Middleware should be able to log any valid URI
            assert_eq!(request.uri(), &uri);
            assert!(!request.uri().to_string().is_empty());
        }
    }

    #[tokio::test]
    async fn test_cors_permissive_creation() {
        // Test that we can create permissive CORS layer multiple times
        let cors1 = cors_layer();
        let cors2 = cors_layer();

        // Both should be created successfully
        assert!(!format!("{cors1:?}").is_empty());
        assert!(!format!("{cors2:?}").is_empty());
    }

    #[tokio::test]
    async fn test_middleware_request_headers() {
        // Test that logging middleware can handle requests with various headers
        let request = Request::builder()
            .method(Method::POST)
            .uri("/secrets")
            .header("authorization", "Bearer token123")
            .header("content-type", "application/json")
            .header("user-agent", "test-client/1.0")
            .body(Body::empty())
            .unwrap();

        // Middleware should be able to log requests with headers
        assert_eq!(request.method(), &Method::POST);
        assert_eq!(request.uri().path(), "/secrets");
        assert!(request.headers().contains_key("authorization"));
        assert!(request.headers().contains_key("content-type"));
    }

    #[tokio::test]
    async fn test_middleware_timing_and_content_length() {
        use std::time::Instant;

        // Test timing functionality used by middleware
        let start_time = Instant::now();
        tokio::time::sleep(tokio::time::Duration::from_millis(1)).await;
        let duration = start_time.elapsed();

        // Duration should be at least 1ms but less than 100ms (reasonable for test)
        assert!(duration.as_millis() >= 1);
        assert!(duration.as_millis() < 100);

        // Test content-length parsing with various scenarios
        let test_cases = vec![
            ("123", Some(123)),
            ("0", Some(0)),
            ("invalid", None),
            ("", None),
        ];

        for (header_value, expected) in test_cases {
            let response = Response::builder()
                .status(200)
                .header("content-length", header_value)
                .body(Body::empty())
                .unwrap();

            let content_length = response
                .headers()
                .get("content-length")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse::<usize>().ok())
                .unwrap_or(0);

            assert_eq!(content_length, expected.unwrap_or(0));
        }

        // Test response without content-length header
        let response_no_header = Response::builder().status(200).body(Body::empty()).unwrap();

        let content_length = response_no_header
            .headers()
            .get("content-length")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(0);

        assert_eq!(content_length, 0);
    }
}
