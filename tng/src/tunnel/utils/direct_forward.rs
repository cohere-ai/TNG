use anyhow::{Context, Result};

use crate::config::{DirectForwardRule, DirectForwardRules};

#[cfg(unix)]
use super::http_inspector::RequestInfo;

pub struct DirectForwardTrafficDetector {
    rule_matchers: Vec<RuleMatcher>,
}

impl DirectForwardTrafficDetector {
    pub fn new(rules: DirectForwardRules) -> Result<Self> {
        let rule_matchers = rules
            .0
            .iter()
            .map(RuleMatcher::new)
            .collect::<Result<Vec<_>>>()?;

        Ok(Self { rule_matchers })
    }

    pub fn matches_path(&self, path: &str) -> bool {
        self.rule_matchers
            .iter()
            .any(|m| m.http_path_regex.is_match(path))
    }

    /// Used by the egress side which inspects raw TCP streams and extracts
    /// request info (authority + path) before deciding whether to forward directly.
    #[cfg(unix)]
    pub fn should_forward_directly(&self, request_info: &RequestInfo) -> bool {
        match request_info {
            RequestInfo::Http1 { path, .. } | RequestInfo::Http2 { path, .. } => {
                self.matches_path(path)
            }
            RequestInfo::UnknownProtocol => false,
        }
    }
}

struct RuleMatcher {
    http_path_regex: regex::Regex,
}

impl RuleMatcher {
    fn new(rule: &DirectForwardRule) -> Result<Self> {
        let regex = &rule.http_path;

        Ok(Self {
            http_path_regex: regex::Regex::new(regex)
                .with_context(|| format!("Invalid regex: {regex}"))?,
        })
    }
}
