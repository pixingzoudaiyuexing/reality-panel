//! Node Reuse V1 S2-A2A credential primitives.
//!
//! This module is intentionally inert: it can generate and verify credential
//! material for tests and future reviewed protocol code, but no HTTP, WebSocket,
//! bootstrap, or runtime path consumes it in S2-A2A.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::node_identity::ReuseEligibleNodeId;

#[allow(
    dead_code,
    reason = "S2-A2A inert secret wire format; issuance is a later reviewed task"
)]
pub const NODE_CREDENTIAL_SECRET_PREFIX: &str = "rpn1_";
pub const NODE_CREDENTIAL_SECRET_LEN: usize = 32;
pub const NODE_CREDENTIAL_VERIFIER_FORMAT: &str = "rp-node-sha256";
pub const NODE_CREDENTIAL_VERIFIER_VERSION: i64 = 1;
pub const NODE_CREDENTIAL_VERIFIER_DATA_LEN: usize = 32;
#[allow(
    dead_code,
    reason = "B2-02A keeps the delivery wire format inert until reviewed B2-02B API/helper"
)]
pub const NODE_CREDENTIAL_DELIVERY_NONCE_PREFIX: &str = "rpdn1_";
pub const NODE_CREDENTIAL_DELIVERY_NONCE_LEN: usize = 32;
pub const NODE_CREDENTIAL_DELIVERY_NONCE_VERIFIER_FORMAT: &str = "rp-node-delivery-nonce-sha256";
pub const NODE_CREDENTIAL_DELIVERY_NONCE_VERIFIER_VERSION: i64 = 1;
const NODE_CREDENTIAL_DOMAIN: &[u8] = b"relay-panel/node-credential/v1\0";
const NODE_CREDENTIAL_DELIVERY_NONCE_DOMAIN: &[u8] =
    b"relay-panel/node-credential-delivery-nonce/v1\0";

#[derive(Clone, PartialEq, Eq)]
pub struct NodeCredentialSecret([u8; NODE_CREDENTIAL_SECRET_LEN]);

impl std::fmt::Debug for NodeCredentialSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<redacted-node-credential>")
    }
}

#[allow(
    dead_code,
    reason = "S2-A2A inert secret parser; issuance is a later reviewed task"
)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeCredentialSecretParseError {
    InvalidPrefix,
    PaddingNotAllowed,
    InvalidEncoding,
    InvalidLength,
    NonCanonicalEncoding,
}

impl std::fmt::Display for NodeCredentialSecretParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            Self::InvalidPrefix => "invalid credential prefix",
            Self::PaddingNotAllowed => "credential padding is not allowed",
            Self::InvalidEncoding => "invalid credential encoding",
            Self::InvalidLength => "invalid credential length",
            Self::NonCanonicalEncoding => "non-canonical credential encoding",
        };
        f.write_str(message)
    }
}

impl std::error::Error for NodeCredentialSecretParseError {}

#[allow(
    dead_code,
    reason = "S2-A2A inert secret operations; issuance is a later reviewed task"
)]
impl NodeCredentialSecret {
    pub fn generate() -> Result<Self, getrandom::Error> {
        let mut bytes = [0_u8; NODE_CREDENTIAL_SECRET_LEN];
        getrandom::getrandom(&mut bytes)?;
        Ok(Self(bytes))
    }

    pub fn parse(input: &str) -> Result<Self, NodeCredentialSecretParseError> {
        let encoded = input
            .strip_prefix(NODE_CREDENTIAL_SECRET_PREFIX)
            .ok_or(NodeCredentialSecretParseError::InvalidPrefix)?;
        if encoded.contains('=') {
            return Err(NodeCredentialSecretParseError::PaddingNotAllowed);
        }

        let decoded = URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|_| NodeCredentialSecretParseError::InvalidEncoding)?;
        if decoded.len() != NODE_CREDENTIAL_SECRET_LEN {
            return Err(NodeCredentialSecretParseError::InvalidLength);
        }
        if URL_SAFE_NO_PAD.encode(&decoded) != encoded {
            return Err(NodeCredentialSecretParseError::NonCanonicalEncoding);
        }

        let mut bytes = [0_u8; NODE_CREDENTIAL_SECRET_LEN];
        bytes.copy_from_slice(&decoded);
        Ok(Self(bytes))
    }

    pub fn to_wire_value(&self) -> String {
        format!(
            "{}{}",
            NODE_CREDENTIAL_SECRET_PREFIX,
            URL_SAFE_NO_PAD.encode(self.0)
        )
    }

    fn as_bytes(&self) -> &[u8; NODE_CREDENTIAL_SECRET_LEN] {
        &self.0
    }

    #[cfg(test)]
    pub(crate) fn from_test_bytes(bytes: [u8; NODE_CREDENTIAL_SECRET_LEN]) -> Self {
        Self(bytes)
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct NodeCredentialVerifier {
    data: [u8; 32],
}

impl std::fmt::Debug for NodeCredentialVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeCredentialVerifier")
            .field("format", &NODE_CREDENTIAL_VERIFIER_FORMAT)
            .field("version", &NODE_CREDENTIAL_VERIFIER_VERSION)
            .field("data", &"<redacted-verifier>")
            .finish()
    }
}

impl NodeCredentialVerifier {
    pub fn derive(
        credential_id: &str,
        home_group_id: i64,
        node_id: &ReuseEligibleNodeId,
        secret: &NodeCredentialSecret,
    ) -> Self {
        let credential_id_bytes = credential_id.as_bytes();
        let node_id_bytes = node_id.as_str().as_bytes();

        let mut digest = Sha256::new();
        digest.update(NODE_CREDENTIAL_DOMAIN);
        digest.update((credential_id_bytes.len() as u64).to_be_bytes());
        digest.update(credential_id_bytes);
        digest.update(home_group_id.to_be_bytes());
        digest.update((node_id_bytes.len() as u64).to_be_bytes());
        digest.update(node_id_bytes);
        digest.update(secret.as_bytes());

        Self {
            data: digest.finalize().into(),
        }
    }

    pub fn format(&self) -> &'static str {
        NODE_CREDENTIAL_VERIFIER_FORMAT
    }

    pub fn version(&self) -> i64 {
        NODE_CREDENTIAL_VERIFIER_VERSION
    }

    pub fn data(&self) -> &[u8; 32] {
        &self.data
    }

    pub fn verify_data(&self, stored: &[u8]) -> bool {
        stored.len() == self.data.len() && bool::from(self.data.as_slice().ct_eq(stored))
    }
}

#[allow(
    dead_code,
    reason = "B2-02A validates the future PREPARE wire contract without exposing an HTTP route"
)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PresentedNodeCredentialVerifierParseError {
    UnsupportedFormat,
    UnsupportedVersion,
    PaddingNotAllowed,
    InvalidEncoding,
    InvalidLength,
    NonCanonicalEncoding,
}

impl std::fmt::Display for PresentedNodeCredentialVerifierParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            Self::UnsupportedFormat => "unsupported credential verifier format",
            Self::UnsupportedVersion => "unsupported credential verifier version",
            Self::PaddingNotAllowed => "credential verifier padding is not allowed",
            Self::InvalidEncoding => "invalid credential verifier encoding",
            Self::InvalidLength => "invalid credential verifier length",
            Self::NonCanonicalEncoding => "non-canonical credential verifier encoding",
        };
        f.write_str(message)
    }
}

impl std::error::Error for PresentedNodeCredentialVerifierParseError {}

/// An untrusted verifier submitted by the future B2-02B target helper.
///
/// This validates only the wire and algorithm contract. Possession is not
/// established until the Repository receives the raw permanent secret and
/// recomputes NodeCredentialVerifier inside the activation transaction.
#[derive(Clone, PartialEq, Eq)]
pub struct PresentedNodeCredentialVerifier([u8; NODE_CREDENTIAL_VERIFIER_DATA_LEN]);

impl std::fmt::Debug for PresentedNodeCredentialVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PresentedNodeCredentialVerifier")
            .field("format", &NODE_CREDENTIAL_VERIFIER_FORMAT)
            .field("version", &NODE_CREDENTIAL_VERIFIER_VERSION)
            .field("data", &"<redacted-untrusted-verifier>")
            .finish()
    }
}

#[allow(
    dead_code,
    reason = "B2-02A parser/wire helpers are consumed by reviewed B2-02B, not runtime yet"
)]
impl PresentedNodeCredentialVerifier {
    pub fn parse(
        format: &str,
        version: i64,
        encoded_data: &str,
    ) -> Result<Self, PresentedNodeCredentialVerifierParseError> {
        if format != NODE_CREDENTIAL_VERIFIER_FORMAT {
            return Err(PresentedNodeCredentialVerifierParseError::UnsupportedFormat);
        }
        if version != NODE_CREDENTIAL_VERIFIER_VERSION {
            return Err(PresentedNodeCredentialVerifierParseError::UnsupportedVersion);
        }
        if encoded_data.contains('=') {
            return Err(PresentedNodeCredentialVerifierParseError::PaddingNotAllowed);
        }
        let decoded = URL_SAFE_NO_PAD
            .decode(encoded_data)
            .map_err(|_| PresentedNodeCredentialVerifierParseError::InvalidEncoding)?;
        let parsed = Self::from_data(format, version, &decoded)?;
        if URL_SAFE_NO_PAD.encode(parsed.0) != encoded_data {
            return Err(PresentedNodeCredentialVerifierParseError::NonCanonicalEncoding);
        }
        Ok(parsed)
    }

    pub fn from_data(
        format: &str,
        version: i64,
        data: &[u8],
    ) -> Result<Self, PresentedNodeCredentialVerifierParseError> {
        if format != NODE_CREDENTIAL_VERIFIER_FORMAT {
            return Err(PresentedNodeCredentialVerifierParseError::UnsupportedFormat);
        }
        if version != NODE_CREDENTIAL_VERIFIER_VERSION {
            return Err(PresentedNodeCredentialVerifierParseError::UnsupportedVersion);
        }
        if data.len() != NODE_CREDENTIAL_VERIFIER_DATA_LEN {
            return Err(PresentedNodeCredentialVerifierParseError::InvalidLength);
        }
        let mut bytes = [0_u8; NODE_CREDENTIAL_VERIFIER_DATA_LEN];
        bytes.copy_from_slice(data);
        Ok(Self(bytes))
    }

    pub fn format(&self) -> &'static str {
        NODE_CREDENTIAL_VERIFIER_FORMAT
    }

    pub fn version(&self) -> i64 {
        NODE_CREDENTIAL_VERIFIER_VERSION
    }

    pub fn data(&self) -> &[u8; NODE_CREDENTIAL_VERIFIER_DATA_LEN] {
        &self.0
    }

    pub fn verify_data(&self, stored: &[u8]) -> bool {
        stored.len() == self.0.len() && bool::from(self.0.as_slice().ct_eq(stored))
    }

    pub fn to_wire_data(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.0)
    }

    pub fn matches_derived(&self, derived: &NodeCredentialVerifier) -> bool {
        bool::from(self.0.as_slice().ct_eq(derived.data().as_slice()))
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct NodeCredentialDeliveryNonce([u8; NODE_CREDENTIAL_DELIVERY_NONCE_LEN]);

impl std::fmt::Debug for NodeCredentialDeliveryNonce {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<redacted-node-credential-delivery-nonce>")
    }
}

#[allow(
    dead_code,
    reason = "B2-02A keeps delivery nonce generation/wire parsing inert until reviewed B2-02B"
)]
impl NodeCredentialDeliveryNonce {
    pub fn generate() -> Result<Self, getrandom::Error> {
        let mut bytes = [0_u8; NODE_CREDENTIAL_DELIVERY_NONCE_LEN];
        getrandom::getrandom(&mut bytes)?;
        Ok(Self(bytes))
    }

    pub fn parse(input: &str) -> Result<Self, NodeCredentialSecretParseError> {
        let encoded = input
            .strip_prefix(NODE_CREDENTIAL_DELIVERY_NONCE_PREFIX)
            .ok_or(NodeCredentialSecretParseError::InvalidPrefix)?;
        if encoded.contains('=') {
            return Err(NodeCredentialSecretParseError::PaddingNotAllowed);
        }
        let decoded = URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|_| NodeCredentialSecretParseError::InvalidEncoding)?;
        if decoded.len() != NODE_CREDENTIAL_DELIVERY_NONCE_LEN {
            return Err(NodeCredentialSecretParseError::InvalidLength);
        }
        if URL_SAFE_NO_PAD.encode(&decoded) != encoded {
            return Err(NodeCredentialSecretParseError::NonCanonicalEncoding);
        }
        let mut bytes = [0_u8; NODE_CREDENTIAL_DELIVERY_NONCE_LEN];
        bytes.copy_from_slice(&decoded);
        Ok(Self(bytes))
    }

    pub fn to_wire_value(&self) -> String {
        format!(
            "{}{}",
            NODE_CREDENTIAL_DELIVERY_NONCE_PREFIX,
            URL_SAFE_NO_PAD.encode(self.0)
        )
    }

    fn as_bytes(&self) -> &[u8; NODE_CREDENTIAL_DELIVERY_NONCE_LEN] {
        &self.0
    }

    #[cfg(test)]
    pub(crate) fn from_test_bytes(bytes: [u8; NODE_CREDENTIAL_DELIVERY_NONCE_LEN]) -> Self {
        Self(bytes)
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct NodeCredentialDeliveryNonceVerifier([u8; 32]);

impl std::fmt::Debug for NodeCredentialDeliveryNonceVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeCredentialDeliveryNonceVerifier")
            .field("format", &NODE_CREDENTIAL_DELIVERY_NONCE_VERIFIER_FORMAT)
            .field("version", &NODE_CREDENTIAL_DELIVERY_NONCE_VERIFIER_VERSION)
            .field("data", &"<redacted-verifier>")
            .finish()
    }
}

impl NodeCredentialDeliveryNonceVerifier {
    pub fn derive(
        claim_id: &str,
        home_group_id: i64,
        node_id: &ReuseEligibleNodeId,
        nonce: &NodeCredentialDeliveryNonce,
    ) -> Self {
        let claim_id_bytes = claim_id.as_bytes();
        let node_id_bytes = node_id.as_str().as_bytes();
        let mut digest = Sha256::new();
        digest.update(NODE_CREDENTIAL_DELIVERY_NONCE_DOMAIN);
        digest.update((claim_id_bytes.len() as u64).to_be_bytes());
        digest.update(claim_id_bytes);
        digest.update(home_group_id.to_be_bytes());
        digest.update((node_id_bytes.len() as u64).to_be_bytes());
        digest.update(node_id_bytes);
        digest.update(nonce.as_bytes());
        Self(digest.finalize().into())
    }

    pub fn format(&self) -> &'static str {
        NODE_CREDENTIAL_DELIVERY_NONCE_VERIFIER_FORMAT
    }

    pub fn version(&self) -> i64 {
        NODE_CREDENTIAL_DELIVERY_NONCE_VERIFIER_VERSION
    }

    pub fn data(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn verify_data(&self, stored: &[u8]) -> bool {
        stored.len() == self.0.len() && bool::from(self.0.as_slice().ct_eq(stored))
    }
}

#[allow(
    dead_code,
    reason = "S2-A2A inert verifier view; runtime authentication is a later reviewed task"
)]
pub struct StoredNodeCredentialVerifier<'a> {
    pub credential_id: &'a str,
    pub home_group_id: i64,
    pub node_id: &'a str,
    pub verifier_format: &'a str,
    pub verifier_version: i64,
    pub verifier_data: &'a [u8],
    pub activated_at: Option<&'a str>,
    pub revoked_at: Option<&'a str>,
}

impl std::fmt::Debug for StoredNodeCredentialVerifier<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StoredNodeCredentialVerifier")
            .field("credential_id", &self.credential_id)
            .field("home_group_id", &self.home_group_id)
            .field("node_id", &self.node_id)
            .field("verifier_format", &self.verifier_format)
            .field("verifier_version", &self.verifier_version)
            .field("verifier_data", &"<redacted-verifier>")
            .field("activated_at", &self.activated_at)
            .field("revoked_at", &self.revoked_at)
            .finish()
    }
}

#[allow(
    dead_code,
    reason = "S2-A2A inert credential foundation; runtime authentication is a later reviewed task"
)]
pub fn verify_active_node_credential(
    stored: &StoredNodeCredentialVerifier<'_>,
    presented_credential_id: &str,
    presented_home_group_id: i64,
    presented_node_id: &ReuseEligibleNodeId,
    secret: &NodeCredentialSecret,
) -> bool {
    if stored.credential_id != presented_credential_id
        || stored.home_group_id != presented_home_group_id
        || stored.node_id != presented_node_id.as_str()
        || stored.verifier_format != NODE_CREDENTIAL_VERIFIER_FORMAT
        || stored.verifier_version != NODE_CREDENTIAL_VERIFIER_VERSION
        || stored.verifier_data.len() != 32
        || stored.activated_at.is_none()
        || stored.revoked_at.is_some()
    {
        return false;
    }

    let expected = NodeCredentialVerifier::derive(
        presented_credential_id,
        presented_home_group_id,
        presented_node_id,
        secret,
    );
    bool::from(expected.data().as_slice().ct_eq(stored.verifier_data))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET_BYTES: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ];

    #[test]
    fn generated_secret_has_exact_length_and_canonical_wire_round_trip() {
        let secret = NodeCredentialSecret::generate().unwrap();
        let wire = secret.to_wire_value();
        assert!(wire.starts_with(NODE_CREDENTIAL_SECRET_PREFIX));
        assert!(!wire.contains('='));
        assert_eq!(NodeCredentialSecret::parse(&wire).unwrap(), secret);
    }

    #[test]
    fn secret_parser_rejects_invalid_prefix_padding_encoding_and_length() {
        assert_eq!(
            NodeCredentialSecret::parse("wrong_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
            Err(NodeCredentialSecretParseError::InvalidPrefix)
        );
        assert_eq!(
            NodeCredentialSecret::parse("rpn1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="),
            Err(NodeCredentialSecretParseError::PaddingNotAllowed)
        );
        assert_eq!(
            NodeCredentialSecret::parse("rpn1_***************************************"),
            Err(NodeCredentialSecretParseError::InvalidEncoding)
        );
        assert_eq!(
            NodeCredentialSecret::parse("rpn1_AQ"),
            Err(NodeCredentialSecretParseError::InvalidLength)
        );
    }

    #[test]
    fn secret_parser_rejects_noncanonical_base64url() {
        let canonical = URL_SAFE_NO_PAD.encode([0_u8; NODE_CREDENTIAL_SECRET_LEN]);
        assert_eq!(canonical.len(), 43);
        let mut noncanonical = canonical;
        noncanonical.pop();
        noncanonical.push('B');

        assert!(
            NodeCredentialSecret::parse(&format!("{NODE_CREDENTIAL_SECRET_PREFIX}{noncanonical}"))
                .is_err(),
            "non-zero trailing Base64URL pad bits must not be accepted"
        );
    }

    #[test]
    fn verifier_v1_matches_fixed_vector_and_binds_every_identity_field() {
        let secret = NodeCredentialSecret::from_test_bytes(SECRET_BYTES);
        let node_id = ReuseEligibleNodeId::parse("Node_A").unwrap();
        let verifier = NodeCredentialVerifier::derive("cred-vector-1", 42, &node_id, &secret);

        assert_eq!(verifier.format(), "rp-node-sha256");
        assert_eq!(verifier.version(), 1);
        assert_eq!(
            hex::encode(verifier.data()),
            "7d4834854628830a4b21ae03e77ad2977e202e0ac94d514c8732e160f9a06186"
        );

        assert_ne!(
            NodeCredentialVerifier::derive("cred-vector-2", 42, &node_id, &secret).data(),
            verifier.data()
        );
        assert_ne!(
            NodeCredentialVerifier::derive("cred-vector-1", 43, &node_id, &secret).data(),
            verifier.data()
        );
        assert_ne!(
            NodeCredentialVerifier::derive(
                "cred-vector-1",
                42,
                &ReuseEligibleNodeId::parse("Node_B").unwrap(),
                &secret,
            )
            .data(),
            verifier.data()
        );
    }

    #[test]
    fn delivery_nonce_wire_and_verifier_are_strict_bound_and_redacted() {
        let nonce = NodeCredentialDeliveryNonce::from_test_bytes(SECRET_BYTES);
        let wire = nonce.to_wire_value();
        assert!(wire.starts_with(NODE_CREDENTIAL_DELIVERY_NONCE_PREFIX));
        assert!(!wire.contains('='));
        assert_eq!(NodeCredentialDeliveryNonce::parse(&wire).unwrap(), nonce);
        assert!(NodeCredentialDeliveryNonce::parse(
            "rpcn1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        )
        .is_err());
        assert!(NodeCredentialDeliveryNonce::parse(&format!("{wire}=")).is_err());

        let node = ReuseEligibleNodeId::parse("Node_A").unwrap();
        let verifier = NodeCredentialDeliveryNonceVerifier::derive("claim-1", 42, &node, &nonce);
        assert_eq!(verifier.format(), "rp-node-delivery-nonce-sha256");
        assert_eq!(verifier.version(), 1);
        assert!(verifier.verify_data(verifier.data()));
        assert!(
            !NodeCredentialDeliveryNonceVerifier::derive("claim-2", 42, &node, &nonce)
                .verify_data(verifier.data())
        );
        assert!(
            !NodeCredentialDeliveryNonceVerifier::derive("claim-1", 43, &node, &nonce)
                .verify_data(verifier.data())
        );
        assert!(!NodeCredentialDeliveryNonceVerifier::derive(
            "claim-1",
            42,
            &ReuseEligibleNodeId::parse("Node_B").unwrap(),
            &nonce,
        )
        .verify_data(verifier.data()));
        assert!(!format!("{nonce:?}").contains(&URL_SAFE_NO_PAD.encode(SECRET_BYTES)));
        assert!(!format!("{verifier:?}").contains(&hex::encode(verifier.data())));
    }

    #[test]
    fn presented_verifier_requires_exact_v1_canonical_shape_and_stays_untrusted() {
        let secret = NodeCredentialSecret::from_test_bytes(SECRET_BYTES);
        let node = ReuseEligibleNodeId::parse("Node_A").unwrap();
        let derived = NodeCredentialVerifier::derive("cred-presented", 42, &node, &secret);
        let encoded = URL_SAFE_NO_PAD.encode(derived.data());
        let presented =
            PresentedNodeCredentialVerifier::parse("rp-node-sha256", 1, &encoded).unwrap();
        assert!(presented.matches_derived(&derived));
        assert_eq!(presented.to_wire_data(), encoded);
        assert!(PresentedNodeCredentialVerifier::parse("wrong", 1, &encoded).is_err());
        assert!(PresentedNodeCredentialVerifier::parse("rp-node-sha256", 2, &encoded).is_err());
        assert!(PresentedNodeCredentialVerifier::parse(
            "rp-node-sha256",
            1,
            &(encoded.clone() + "="),
        )
        .is_err());
        assert!(PresentedNodeCredentialVerifier::parse("rp-node-sha256", 1, "AQ").is_err());
        assert!(!format!("{presented:?}").contains(&hex::encode(derived.data())));
    }

    #[test]
    fn active_verifier_rejects_wrong_secret_metadata_identity_and_lifecycle() {
        let secret = NodeCredentialSecret::from_test_bytes(SECRET_BYTES);
        let wrong_secret = NodeCredentialSecret::from_test_bytes([0x55; 32]);
        let node_id = ReuseEligibleNodeId::parse("Node_A").unwrap();
        let verifier = NodeCredentialVerifier::derive("cred-1", 42, &node_id, &secret);

        let verify = |credential_id: &str,
                      home_group_id: i64,
                      node: &ReuseEligibleNodeId,
                      presented_secret: &NodeCredentialSecret,
                      format: &str,
                      version: i64,
                      data: &[u8],
                      activated: Option<&str>,
                      revoked: Option<&str>| {
            let stored = StoredNodeCredentialVerifier {
                credential_id: "cred-1",
                home_group_id: 42,
                node_id: "Node_A",
                verifier_format: format,
                verifier_version: version,
                verifier_data: data,
                activated_at: activated,
                revoked_at: revoked,
            };
            verify_active_node_credential(
                &stored,
                credential_id,
                home_group_id,
                node,
                presented_secret,
            )
        };

        assert!(verify(
            "cred-1",
            42,
            &node_id,
            &secret,
            verifier.format(),
            verifier.version(),
            verifier.data(),
            Some("2026-09-23 00:00:00"),
            None,
        ));
        assert!(!verify(
            "cred-1",
            42,
            &node_id,
            &wrong_secret,
            verifier.format(),
            verifier.version(),
            verifier.data(),
            Some("2026-09-23 00:00:00"),
            None,
        ));
        assert!(!verify(
            "cred-2",
            42,
            &node_id,
            &secret,
            verifier.format(),
            verifier.version(),
            verifier.data(),
            Some("2026-09-23 00:00:00"),
            None,
        ));
        assert!(!verify(
            "cred-1",
            43,
            &node_id,
            &secret,
            verifier.format(),
            verifier.version(),
            verifier.data(),
            Some("2026-09-23 00:00:00"),
            None,
        ));
        assert!(!verify(
            "cred-1",
            42,
            &ReuseEligibleNodeId::parse("Node_B").unwrap(),
            &secret,
            verifier.format(),
            verifier.version(),
            verifier.data(),
            Some("2026-09-23 00:00:00"),
            None,
        ));
        assert!(!verify(
            "cred-1",
            42,
            &node_id,
            &secret,
            "wrong-format",
            verifier.version(),
            verifier.data(),
            Some("2026-09-23 00:00:00"),
            None,
        ));
        assert!(!verify(
            "cred-1",
            42,
            &node_id,
            &secret,
            verifier.format(),
            99,
            verifier.data(),
            Some("2026-09-23 00:00:00"),
            None,
        ));
        assert!(!verify(
            "cred-1",
            42,
            &node_id,
            &secret,
            verifier.format(),
            verifier.version(),
            &[0_u8; 31],
            Some("2026-09-23 00:00:00"),
            None,
        ));
        assert!(!verify(
            "cred-1",
            42,
            &node_id,
            &secret,
            verifier.format(),
            verifier.version(),
            verifier.data(),
            None,
            None,
        ));
        assert!(!verify(
            "cred-1",
            42,
            &node_id,
            &secret,
            verifier.format(),
            verifier.version(),
            verifier.data(),
            Some("2026-09-23 00:00:00"),
            Some("2026-09-23 00:01:00"),
        ));
    }

    #[test]
    fn secret_and_verifier_debug_output_are_redacted() {
        let secret = NodeCredentialSecret::from_test_bytes(SECRET_BYTES);
        let verifier = NodeCredentialVerifier::derive(
            "cred-debug",
            1,
            &ReuseEligibleNodeId::parse("AAA").unwrap(),
            &secret,
        );
        let wire = secret.to_wire_value();

        let secret_debug = format!("{secret:?}");
        let verifier_debug = format!("{verifier:?}");
        assert!(secret_debug.contains("redacted"));
        assert!(!secret_debug.contains(&wire));
        assert!(verifier_debug.contains("redacted-verifier"));
        assert!(!verifier_debug.contains(&hex::encode(verifier.data())));
    }
}
