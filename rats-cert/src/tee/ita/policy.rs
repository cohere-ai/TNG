use crate::errors::*;

/// Trait for dynamically resolving ITA policy IDs.
///
/// Implementations may return static values or fetch them from a remote source
/// with caching.
#[async_trait::async_trait]
pub trait PolicyIdSource: Send + Sync {
    async fn get_policy_ids(&self) -> Result<Vec<String>>;
}

/// Returns a fixed set of policy IDs provided at construction time.
pub struct StaticPolicyIds(Vec<String>);

impl StaticPolicyIds {
    pub fn new(ids: Vec<String>) -> Self {
        Self(ids)
    }
}

#[async_trait::async_trait]
impl PolicyIdSource for StaticPolicyIds {
    async fn get_policy_ids(&self) -> Result<Vec<String>> {
        Ok(self.0.clone())
    }
}
