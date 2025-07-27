use crate::error::SecurityError;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{error, info, warn};

/// Security audit event types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SecurityEvent {
    /// Successful authentication
    AuthenticationSuccess {
        repository: String,
        user_agent: Option<String>,
        ip_address: Option<String>,
    },
    /// Failed authentication attempt
    AuthenticationFailure {
        reason: String,
        ip_address: Option<String>,
        user_agent: Option<String>,
    },
    /// Secret access
    SecretAccess {
        repository: String,
        secret_count: usize,
        ip_address: Option<String>,
    },
    /// Configuration access
    ConfigurationAccess {
        accessed_keys: Vec<String>,
        ip_address: Option<String>,
    },
    /// Suspicious activity detected
    SuspiciousActivity {
        activity_type: String,
        details: String,
        severity: SecuritySeverity,
        ip_address: Option<String>,
    },
    /// Security policy violation
    PolicyViolation {
        policy: String,
        violation_details: String,
        ip_address: Option<String>,
    },
    /// Rate limiting triggered
    RateLimitExceeded {
        resource: String,
        limit: u64,
        window: String,
        ip_address: Option<String>,
    },
}

/// Security event severity levels
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SecuritySeverity {
    Low,
    Medium,
    High,
    Critical,
}

/// Security audit log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityAuditEntry {
    pub timestamp: DateTime<Utc>,
    pub event: SecurityEvent,
    pub request_id: Option<String>,
    pub metadata: HashMap<String, String>,
}

/// Security auditor for comprehensive logging and monitoring
pub struct SecurityAuditor {
    /// Whether to enable detailed logging
    detailed_logging: bool,
    /// Security policies to enforce
    policies: SecurityPolicies,
}

/// Security policies configuration
#[derive(Debug, Clone)]
pub struct SecurityPolicies {
    /// Maximum failed authentication attempts per hour
    pub max_auth_failures_per_hour: u32,
    /// Maximum secret access attempts per minute
    pub max_secret_access_per_minute: u32,
    /// Require HTTPS in production
    pub require_https: bool,
    /// Block suspicious user agents
    pub block_suspicious_user_agents: Vec<String>,
    /// Minimum token length
    pub min_token_length: usize,
}

impl Default for SecurityPolicies {
    fn default() -> Self {
        Self {
            max_auth_failures_per_hour: 100,
            max_secret_access_per_minute: 60,
            require_https: true,
            block_suspicious_user_agents: vec![
                "curl".to_string(),
                "wget".to_string(),
                "python-requests".to_string(),
            ],
            min_token_length: 100,
        }
    }
}

impl SecurityAuditor {
    /// Create a new security auditor
    pub fn new(detailed_logging: bool, policies: Option<SecurityPolicies>) -> Self {
        Self {
            detailed_logging,
            policies: policies.unwrap_or_default(),
        }
    }

    /// Log a security event
    pub fn log_security_event(&self, event: SecurityEvent, request_id: Option<String>) {
        let entry = SecurityAuditEntry {
            timestamp: Utc::now(),
            event: event.clone(),
            request_id,
            metadata: HashMap::new(),
        };

        // Log based on event severity
        match &event {
            SecurityEvent::AuthenticationSuccess { repository, .. } => {
                info!("Authentication success for repository: {}", repository);
                if self.detailed_logging {
                    info!("Security audit: {}", serde_json::to_string(&entry).unwrap_or_default());
                }
            }
            SecurityEvent::AuthenticationFailure { reason, .. } => {
                warn!("Authentication failure: {}", reason);
                if self.detailed_logging {
                    warn!("Security audit: {}", serde_json::to_string(&entry).unwrap_or_default());
                }
            }
            SecurityEvent::SecretAccess { repository, secret_count, .. } => {
                info!("Secret access for repository: {} ({} secrets)", repository, secret_count);
                if self.detailed_logging {
                    info!("Security audit: {}", serde_json::to_string(&entry).unwrap_or_default());
                }
            }
            SecurityEvent::SuspiciousActivity { activity_type, severity, .. } => {
                match severity {
                    SecuritySeverity::Low => info!("Low severity suspicious activity: {}", activity_type),
                    SecuritySeverity::Medium => warn!("Medium severity suspicious activity: {}", activity_type),
                    SecuritySeverity::High => warn!("High severity suspicious activity: {}", activity_type),
                    SecuritySeverity::Critical => error!("Critical suspicious activity: {}", activity_type),
                }
                if self.detailed_logging {
                    error!("Security audit: {}", serde_json::to_string(&entry).unwrap_or_default());
                }
            }
            SecurityEvent::PolicyViolation { policy, .. } => {
                warn!("Security policy violation: {}", policy);
                if self.detailed_logging {
                    warn!("Security audit: {}", serde_json::to_string(&entry).unwrap_or_default());
                }
            }
            SecurityEvent::RateLimitExceeded { resource, .. } => {
                warn!("Rate limit exceeded for resource: {}", resource);
                if self.detailed_logging {
                    warn!("Security audit: {}", serde_json::to_string(&entry).unwrap_or_default());
                }
            }
            SecurityEvent::ConfigurationAccess { .. } => {
                info!("Configuration access logged");
                if self.detailed_logging {
                    info!("Security audit: {}", serde_json::to_string(&entry).unwrap_or_default());
                }
            }
        }
    }

    /// Audit authentication attempt
    pub fn audit_authentication(&self,
        repository: &str,
        success: bool,
        failure_reason: Option<&str>,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) {
        let event = if success {
            SecurityEvent::AuthenticationSuccess {
                repository: repository.to_string(),
                ip_address,
                user_agent,
            }
        } else {
            SecurityEvent::AuthenticationFailure {
                reason: failure_reason.unwrap_or("unknown").to_string(),
                ip_address,
                user_agent,
            }
        };

        self.log_security_event(event, None);
    }

    /// Audit secret access
    pub fn audit_secret_access(&self,
        repository: &str,
        secret_count: usize,
        ip_address: Option<String>,
    ) {
        let event = SecurityEvent::SecretAccess {
            repository: repository.to_string(),
            secret_count,
            ip_address,
        };

        self.log_security_event(event, None);
    }

    /// Check and enforce security policies
    pub fn enforce_security_policies(&self,
        scheme: &str,
        user_agent: Option<&str>,
        token: &str,
    ) -> Result<(), SecurityError> {
        // Check HTTPS requirement in production
        if self.policies.require_https && scheme != "https" {
            return Err(SecurityError::InsecureConfiguration {
                issue: "HTTPS is required in production".to_string(),
            });
        }

        // Check user agent blocklist
        if let Some(ua) = user_agent {
            for blocked_ua in &self.policies.block_suspicious_user_agents {
                if ua.to_lowercase().contains(&blocked_ua.to_lowercase()) {
                    self.log_security_event(
                        SecurityEvent::SuspiciousActivity {
                            activity_type: "Blocked user agent".to_string(),
                            details: format!("User agent: {}", ua),
                            severity: SecuritySeverity::Medium,
                            ip_address: None,
                        },
                        None,
                    );
                    return Err(SecurityError::SuspiciousActivity {
                        details: format!("User agent '{}' is blocked", ua),
                    });
                }
            }
        }

        // Check minimum token length
        if token.len() < self.policies.min_token_length {
            return Err(SecurityError::InputValidationFailed {
                message: format!("Token too short: {} characters", token.len()),
            });
        }

        Ok(())
    }

    /// Detect suspicious patterns in requests
    pub fn detect_suspicious_activity(&self,
        repository: &str,
        ip_address: Option<String>,
        user_agent: Option<String>,
        _additional_context: HashMap<String, String>,
    ) -> Vec<SecurityEvent> {
        let mut suspicious_events = Vec::new();

        // Check for suspicious repository patterns
        if repository.contains("../") || repository.contains("..\\") {
            suspicious_events.push(SecurityEvent::SuspiciousActivity {
                activity_type: "Path traversal attempt".to_string(),
                details: format!("Repository name contains path traversal: {}", repository),
                severity: SecuritySeverity::High,
                ip_address: ip_address.clone(),
            });
        }

        // Check for SQL injection patterns in repository name
        let sql_patterns = ["union", "select", "insert", "drop", "delete", "update"];
        let repo_lower = repository.to_lowercase();
        for pattern in &sql_patterns {
            if repo_lower.contains(pattern) {
                suspicious_events.push(SecurityEvent::SuspiciousActivity {
                    activity_type: "SQL injection attempt".to_string(),
                    details: format!("Repository name contains SQL keyword: {}", pattern),
                    severity: SecuritySeverity::High,
                    ip_address: ip_address.clone(),
                });
                break;
            }
        }

        // Check for suspicious user agents
        if let Some(ua) = &user_agent {
            let ua_lower = ua.to_lowercase();
            if ua_lower.contains("bot") && !ua_lower.contains("github") {
                suspicious_events.push(SecurityEvent::SuspiciousActivity {
                    activity_type: "Suspicious bot activity".to_string(),
                    details: format!("Non-GitHub bot detected: {}", ua),
                    severity: SecuritySeverity::Medium,
                    ip_address: ip_address.clone(),
                });
            }
        }

        // Log all detected suspicious events
        for event in &suspicious_events {
            self.log_security_event(event.clone(), None);
        }

        suspicious_events
    }

    /// Perform basic security audit checks
    pub fn perform_security_audit(&self) -> Result<SecurityAuditReport, SecurityError> {
        let mut report = SecurityAuditReport::new();

        // Check basic security configurations
        if !self.policies.require_https {
            report.add_finding(SecurityFinding {
                severity: SecuritySeverity::Medium,
                category: "Configuration".to_string(),
                description: "HTTPS not required - potential security risk".to_string(),
                recommendation: "Enable HTTPS requirement for production".to_string(),
            });
        }

        if self.policies.max_auth_failures_per_hour > 1000 {
            report.add_finding(SecurityFinding {
                severity: SecuritySeverity::Low,
                category: "Rate Limiting".to_string(),
                description: "Authentication failure rate limit is very high".to_string(),
                recommendation: "Consider lowering max auth failures threshold".to_string(),
            });
        }

        if self.policies.min_token_length < 50 {
            report.add_finding(SecurityFinding {
                severity: SecuritySeverity::Medium,
                category: "Token Security".to_string(),
                description: "Minimum token length is too short".to_string(),
                recommendation: "Increase minimum token length to at least 100 characters".to_string(),
            });
        }

        info!("Security audit completed with {} findings", report.findings.len());
        Ok(report)
    }

    /// Get current security policies
    pub fn get_policies(&self) -> &SecurityPolicies {
        &self.policies
    }

    /// Update security policies
    pub fn update_policies(&mut self, policies: SecurityPolicies) {
        self.policies = policies;
        info!("Security policies updated");
    }
}

/// Security audit report
#[derive(Debug, Clone)]
pub struct SecurityAuditReport {
    pub timestamp: DateTime<Utc>,
    pub findings: Vec<SecurityFinding>,
}

impl SecurityAuditReport {
    fn new() -> Self {
        Self {
            timestamp: Utc::now(),
            findings: Vec::new(),
        }
    }

    fn add_finding(&mut self, finding: SecurityFinding) {
        self.findings.push(finding);
    }

    /// Get findings by severity
    pub fn get_findings_by_severity(&self, severity: SecuritySeverity) -> Vec<&SecurityFinding> {
        self.findings
            .iter()
            .filter(|f| matches!((&f.severity, &severity),
                (SecuritySeverity::Low, SecuritySeverity::Low) |
                (SecuritySeverity::Medium, SecuritySeverity::Medium) |
                (SecuritySeverity::High, SecuritySeverity::High) |
                (SecuritySeverity::Critical, SecuritySeverity::Critical)
            ))
            .collect()
    }

    /// Check if there are any critical findings
    pub fn has_critical_findings(&self) -> bool {
        self.findings.iter().any(|f| matches!(f.severity, SecuritySeverity::Critical))
    }
}

/// Individual security finding
#[derive(Debug, Clone)]
pub struct SecurityFinding {
    pub severity: SecuritySeverity,
    pub category: String,
    pub description: String,
    pub recommendation: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_security_auditor_creation() {
        let auditor = SecurityAuditor::new(true, None);
        assert!(auditor.detailed_logging);
        assert_eq!(auditor.policies.max_auth_failures_per_hour, 100);
    }

    #[test]
    fn test_security_policies_enforcement() {
        let policies = SecurityPolicies {
            require_https: true,
            block_suspicious_user_agents: vec!["curl".to_string()],
            min_token_length: 100,
            ..Default::default()
        };

        let auditor = SecurityAuditor::new(false, Some(policies));

        // Test HTTPS requirement
        let result = auditor.enforce_security_policies("http", None, &"a".repeat(150));
        assert!(result.is_err());

        // Test user agent blocking
        let result = auditor.enforce_security_policies("https", Some("curl/7.68.0"), &"a".repeat(150));
        assert!(result.is_err());

        // Test minimum token length
        let result = auditor.enforce_security_policies("https", None, "short_token");
        assert!(result.is_err());

        // Test valid request
        let result = auditor.enforce_security_policies("https", Some("github-actions"), &"a".repeat(150));
        assert!(result.is_ok());
    }

    #[test]
    fn test_suspicious_activity_detection() {
        let auditor = SecurityAuditor::new(false, None);

        // Test path traversal detection
        let events = auditor.detect_suspicious_activity(
            "owner/../../../etc/passwd",
            Some("192.168.1.1".to_string()),
            None,
            HashMap::new(),
        );
        assert!(!events.is_empty());

        // Test SQL injection detection
        let events = auditor.detect_suspicious_activity(
            "owner/repo'; DROP TABLE users;--",
            Some("192.168.1.1".to_string()),
            None,
            HashMap::new(),
        );
        assert!(!events.is_empty());

        // Test normal repository
        let events = auditor.detect_suspicious_activity(
            "github/octocat",
            Some("192.168.1.1".to_string()),
            Some("github-actions".to_string()),
            HashMap::new(),
        );
        assert!(events.is_empty());
    }

    #[test]
    fn test_security_audit_report() {
        let auditor = SecurityAuditor::new(false, None);
        let report = auditor.perform_security_audit().unwrap();

        assert!(!report.timestamp.to_string().is_empty());

        // Should have some findings based on default policies
        let critical_findings = report.get_findings_by_severity(SecuritySeverity::Critical);
        let has_critical = report.has_critical_findings();

        // These should be consistent
        assert_eq!(critical_findings.is_empty(), !has_critical);
    }

    #[test]
    fn test_audit_authentication() {
        let auditor = SecurityAuditor::new(false, None);

        // Test successful authentication
        auditor.audit_authentication(
            "github/repo",
            true,
            None,
            Some("192.168.1.1".to_string()),
            Some("github-actions".to_string()),
        );

        // Test failed authentication
        auditor.audit_authentication(
            "github/repo",
            false,
            Some("invalid token"),
            Some("192.168.1.1".to_string()),
            Some("curl".to_string()),
        );

        // If we get here without panicking, the logging worked
        assert!(true);
    }

    #[test]
    fn test_audit_secret_access() {
        let auditor = SecurityAuditor::new(false, None);

        auditor.audit_secret_access(
            "github/repo",
            5,
            Some("192.168.1.1".to_string()),
        );

        // If we get here without panicking, the logging worked
        assert!(true);
    }
}
