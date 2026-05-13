//! Scope validation — strict enforcement of authorized targets.

use ipnetwork::IpNetwork;
use regex::Regex;
use std::collections::HashSet;
use std::net::IpAddr;
use tracing::warn;

/// Validates targets against authorized scope definitions.
pub struct ScopeValidator {
    in_scope_domains: HashSet<String>,
    in_scope_wildcards: HashSet<String>,
    in_scope_ips: HashSet<IpAddr>,
    in_scope_cidrs: Vec<IpNetwork>,
    out_of_scope_domains: HashSet<String>,
    out_of_scope_wildcards: HashSet<String>,
}

impl ScopeValidator {
    pub fn new() -> Self {
        Self {
            in_scope_domains: HashSet::new(),
            in_scope_wildcards: HashSet::new(),
            in_scope_ips: HashSet::new(),
            in_scope_cidrs: Vec::new(),
            out_of_scope_domains: HashSet::new(),
            out_of_scope_wildcards: HashSet::new(),
        }
    }

    /// Add a scope entry.
    pub fn add_scope(&mut self, value: &str, in_scope: bool) {
        let value = value.trim().to_lowercase();
        let cleaned = Regex::new(r"^https?://").unwrap()
            .replace(&value, "")
            .split('/')
            .next()
            .unwrap_or("")
            .to_string();

        if cleaned.starts_with("*.") {
            let domain = cleaned[2..].to_string();
            if in_scope {
                self.in_scope_wildcards.insert(domain);
            } else {
                self.out_of_scope_wildcards.insert(domain);
            }
        } else if let Ok(ip) = cleaned.parse::<IpAddr>() {
            if in_scope {
                self.in_scope_ips.insert(ip);
            }
        } else if let Ok(cidr) = cleaned.parse::<IpNetwork>() {
            if in_scope {
                self.in_scope_cidrs.push(cidr);
            }
        } else {
            if in_scope {
                self.in_scope_domains.insert(cleaned);
            } else {
                self.out_of_scope_domains.insert(cleaned);
            }
        }
    }

    /// Check if a target is within the authorized scope.
    pub fn is_in_scope(&self, target: &str) -> bool {
        let target = target.trim().to_lowercase();
        let cleaned = Regex::new(r"^https?://").unwrap()
            .replace(&target, "")
            .split('/')
            .next()
            .unwrap_or("")
            .split(':')
            .next()
            .unwrap_or("")
            .to_string();

        // Check out-of-scope first (exclusions take priority)
        if self.out_of_scope_domains.contains(&cleaned) {
            warn!(target = %cleaned, "OUT OF SCOPE (explicit exclusion)");
            return false;
        }
        for wildcard in &self.out_of_scope_wildcards {
            if cleaned == *wildcard || cleaned.ends_with(&format!(".{}", wildcard)) {
                warn!(target = %cleaned, "OUT OF SCOPE (wildcard exclusion)");
                return false;
            }
        }

        // Check in-scope: exact domain
        if self.in_scope_domains.contains(&cleaned) {
            return true;
        }

        // Check in-scope: wildcard
        for wildcard in &self.in_scope_wildcards {
            if cleaned == *wildcard || cleaned.ends_with(&format!(".{}", wildcard)) {
                return true;
            }
        }

        // Check in-scope: IP
        if let Ok(ip) = cleaned.parse::<IpAddr>() {
            if self.in_scope_ips.contains(&ip) {
                return true;
            }
            for cidr in &self.in_scope_cidrs {
                if cidr.contains(ip) {
                    return true;
                }
            }
        }

        warn!(target = %cleaned, "OUT OF SCOPE");
        false
    }
}

impl Default for ScopeValidator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exact_domain_scope() {
        let mut v = ScopeValidator::new();
        v.add_scope("example.com", true);
        assert!(v.is_in_scope("example.com"));
        assert!(!v.is_in_scope("other.com"));
    }

    #[test]
    fn test_wildcard_scope() {
        let mut v = ScopeValidator::new();
        v.add_scope("*.example.com", true);
        assert!(v.is_in_scope("sub.example.com"));
        assert!(v.is_in_scope("deep.sub.example.com"));
        assert!(!v.is_in_scope("other.com"));
    }

    #[test]
    fn test_out_of_scope_exclusion() {
        let mut v = ScopeValidator::new();
        v.add_scope("*.example.com", true);
        v.add_scope("admin.example.com", false);
        assert!(v.is_in_scope("api.example.com"));
        assert!(!v.is_in_scope("admin.example.com"));
    }

    #[test]
    fn test_url_normalization() {
        let mut v = ScopeValidator::new();
        v.add_scope("https://example.com/path", true);
        assert!(v.is_in_scope("http://example.com/other"));
        assert!(v.is_in_scope("example.com"));
    }
}
