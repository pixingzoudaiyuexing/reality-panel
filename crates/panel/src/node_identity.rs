//! Node Reuse V1 concrete-node identity helpers.
//!
//! This type is intentionally narrower than the legacy Home-only node-id paths.
//! It defines only whether an existing node id is eligible for Node Reuse.
//! Parsing is exact: no trimming, case-folding, or Unicode normalization occurs.

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ReuseEligibleNodeId(String);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReuseEligibleNodeIdError {
    Empty,
    TooLong,
    InvalidCharacter,
}

impl ReuseEligibleNodeId {
    pub const MAX_LEN: usize = 128;

    pub fn parse(input: &str) -> Result<Self, ReuseEligibleNodeIdError> {
        if input.is_empty() {
            return Err(ReuseEligibleNodeIdError::Empty);
        }
        if input.len() > Self::MAX_LEN {
            return Err(ReuseEligibleNodeIdError::TooLong);
        }
        if !input
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        {
            return Err(ReuseEligibleNodeIdError::InvalidCharacter);
        }
        Ok(Self(input.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for ReuseEligibleNodeId {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reuse_eligible_node_id_accepts_exact_approved_grammar() {
        let values = [
            "0123456789abcdef0123456789abcdef",
            "AAA",
            "BBB",
            "my-fixed-id-12345",
            "node_01",
        ];
        for value in values {
            let parsed = ReuseEligibleNodeId::parse(value).unwrap();
            assert_eq!(parsed.as_str(), value);
        }

        let max = "a".repeat(ReuseEligibleNodeId::MAX_LEN);
        assert_eq!(
            ReuseEligibleNodeId::parse(&max).unwrap().as_str(),
            max.as_str()
        );
    }

    #[test]
    fn reuse_eligible_node_id_is_case_sensitive_and_never_normalizes() {
        let upper = ReuseEligibleNodeId::parse("AAA").unwrap();
        let lower = ReuseEligibleNodeId::parse("aaa").unwrap();
        assert_ne!(upper, lower);
        assert_eq!(upper.as_str(), "AAA");
        assert_eq!(lower.as_str(), "aaa");
        assert_eq!(
            ReuseEligibleNodeId::parse("my-node "),
            Err(ReuseEligibleNodeIdError::InvalidCharacter)
        );
    }

    #[test]
    fn reuse_eligible_node_id_rejects_whitespace_unicode_and_non_ascii() {
        for value in [
            " node",
            "node ",
            "my node",
            "my\tnode",
            "my\nnode",
            "node\u{00a0}",
            "node\u{3000}",
            "节点",
        ] {
            assert_eq!(
                ReuseEligibleNodeId::parse(value),
                Err(ReuseEligibleNodeIdError::InvalidCharacter),
                "{value:?}"
            );
        }
    }

    #[test]
    fn reuse_eligible_node_id_rejects_empty_and_overlong() {
        assert_eq!(
            ReuseEligibleNodeId::parse(""),
            Err(ReuseEligibleNodeIdError::Empty)
        );
        let overlong = "a".repeat(ReuseEligibleNodeId::MAX_LEN + 1);
        assert_eq!(
            ReuseEligibleNodeId::parse(&overlong),
            Err(ReuseEligibleNodeIdError::TooLong)
        );
    }
}
