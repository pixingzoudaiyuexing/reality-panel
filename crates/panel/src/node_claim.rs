//! Node Reuse V1 S2-A2B1 one-time Concrete Node Claim primitives.
//!
//! This module is intentionally inert. It defines cryptographic material used by
//! the internal claim registry, but no HTTP, WebSocket, bootstrap, helper, or
//! runtime path issues or consumes a real Claim Secret in S2-A2B1.

#![allow(
    dead_code,
    reason = "S2-A2B1 is an intentionally inert reviewed claim foundation"
)]

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::node_identity::ReuseEligibleNodeId;

pub const NODE_CLAIM_SECRET_PREFIX: &str = "rpc1_";
pub const NODE_CLAIM_NONCE_PREFIX: &str = "rpcn1_";
pub const NODE_CLAIM_SECRET_LEN: usize = 32;
pub const NODE_CLAIM_NONCE_LEN: usize = 32;
pub const NODE_CLAIM_SECRET_VERIFIER_FORMAT: &str = "rp-node-claim-sha256";
pub const NODE_CLAIM_NONCE_VERIFIER_FORMAT: &str = "rp-node-claim-nonce-sha256";
pub const NODE_CLAIM_VERIFIER_VERSION: i64 = 1;
pub const NODE_CLAIM_MAX_TTL_SECS: i64 = 24 * 60 * 60;

const NODE_CLAIM_SECRET_DOMAIN: &[u8] = b"relay-panel/node-claim-secret/v1\0";
const NODE_CLAIM_NONCE_DOMAIN: &[u8] = b"relay-panel/node-claimant-nonce/v1\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeClaimWireParseError {
    InvalidPrefix,
    PaddingNotAllowed,
    InvalidEncoding,
    InvalidLength,
    NonCanonicalEncoding,
}

impl std::fmt::Display for NodeClaimWireParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            Self::InvalidPrefix => "invalid claim material prefix",
            Self::PaddingNotAllowed => "claim material padding is not allowed",
            Self::InvalidEncoding => "invalid claim material encoding",
            Self::InvalidLength => "invalid claim material length",
            Self::NonCanonicalEncoding => "non-canonical claim material encoding",
        };
        f.write_str(message)
    }
}

impl std::error::Error for NodeClaimWireParseError {}

fn parse_wire<const N: usize>(
    input: &str,
    prefix: &str,
) -> Result<[u8; N], NodeClaimWireParseError> {
    let encoded = input
        .strip_prefix(prefix)
        .ok_or(NodeClaimWireParseError::InvalidPrefix)?;
    if encoded.contains('=') {
        return Err(NodeClaimWireParseError::PaddingNotAllowed);
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| NodeClaimWireParseError::InvalidEncoding)?;
    if decoded.len() != N {
        return Err(NodeClaimWireParseError::InvalidLength);
    }
    if URL_SAFE_NO_PAD.encode(&decoded) != encoded {
        return Err(NodeClaimWireParseError::NonCanonicalEncoding);
    }
    let mut bytes = [0_u8; N];
    bytes.copy_from_slice(&decoded);
    Ok(bytes)
}

fn wire_value(prefix: &str, bytes: &[u8]) -> String {
    format!("{prefix}{}", URL_SAFE_NO_PAD.encode(bytes))
}

fn derive_bound_digest(
    domain: &[u8],
    claim_id: &str,
    home_group_id: i64,
    node_id: &ReuseEligibleNodeId,
    raw: &[u8],
) -> [u8; 32] {
    let claim_id_bytes = claim_id.as_bytes();
    let node_id_bytes = node_id.as_str().as_bytes();
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update((claim_id_bytes.len() as u64).to_be_bytes());
    digest.update(claim_id_bytes);
    digest.update(home_group_id.to_be_bytes());
    digest.update((node_id_bytes.len() as u64).to_be_bytes());
    digest.update(node_id_bytes);
    digest.update(raw);
    digest.finalize().into()
}

#[derive(Clone, PartialEq, Eq)]
pub struct NodeClaimSecret([u8; NODE_CLAIM_SECRET_LEN]);

impl std::fmt::Debug for NodeClaimSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<redacted-node-claim-secret>")
    }
}

impl NodeClaimSecret {
    pub fn generate() -> Result<Self, getrandom::Error> {
        let mut bytes = [0_u8; NODE_CLAIM_SECRET_LEN];
        getrandom::getrandom(&mut bytes)?;
        Ok(Self(bytes))
    }

    pub fn parse(input: &str) -> Result<Self, NodeClaimWireParseError> {
        Ok(Self(parse_wire(input, NODE_CLAIM_SECRET_PREFIX)?))
    }

    pub fn to_wire_value(&self) -> String {
        wire_value(NODE_CLAIM_SECRET_PREFIX, &self.0)
    }

    fn as_bytes(&self) -> &[u8; NODE_CLAIM_SECRET_LEN] {
        &self.0
    }

    #[cfg(test)]
    pub(crate) fn from_test_bytes(bytes: [u8; NODE_CLAIM_SECRET_LEN]) -> Self {
        Self(bytes)
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct NodeClaimantNonce([u8; NODE_CLAIM_NONCE_LEN]);

impl std::fmt::Debug for NodeClaimantNonce {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<redacted-node-claimant-nonce>")
    }
}

impl NodeClaimantNonce {
    pub fn generate() -> Result<Self, getrandom::Error> {
        let mut bytes = [0_u8; NODE_CLAIM_NONCE_LEN];
        getrandom::getrandom(&mut bytes)?;
        Ok(Self(bytes))
    }

    pub fn parse(input: &str) -> Result<Self, NodeClaimWireParseError> {
        Ok(Self(parse_wire(input, NODE_CLAIM_NONCE_PREFIX)?))
    }

    pub fn to_wire_value(&self) -> String {
        wire_value(NODE_CLAIM_NONCE_PREFIX, &self.0)
    }

    fn as_bytes(&self) -> &[u8; NODE_CLAIM_NONCE_LEN] {
        &self.0
    }

    #[cfg(test)]
    pub(crate) fn from_test_bytes(bytes: [u8; NODE_CLAIM_NONCE_LEN]) -> Self {
        Self(bytes)
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct NodeClaimSecretVerifier([u8; 32]);

impl std::fmt::Debug for NodeClaimSecretVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeClaimSecretVerifier")
            .field("format", &NODE_CLAIM_SECRET_VERIFIER_FORMAT)
            .field("version", &NODE_CLAIM_VERIFIER_VERSION)
            .field("data", &"<redacted-verifier>")
            .finish()
    }
}

impl NodeClaimSecretVerifier {
    pub fn derive(
        claim_id: &str,
        home_group_id: i64,
        node_id: &ReuseEligibleNodeId,
        secret: &NodeClaimSecret,
    ) -> Self {
        Self(derive_bound_digest(
            NODE_CLAIM_SECRET_DOMAIN,
            claim_id,
            home_group_id,
            node_id,
            secret.as_bytes(),
        ))
    }

    pub fn format(&self) -> &'static str {
        NODE_CLAIM_SECRET_VERIFIER_FORMAT
    }

    pub fn version(&self) -> i64 {
        NODE_CLAIM_VERIFIER_VERSION
    }

    pub fn data(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn verify_data(&self, stored: &[u8]) -> bool {
        stored.len() == self.0.len() && bool::from(self.0.as_slice().ct_eq(stored))
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct NodeClaimNonceVerifier([u8; 32]);

impl std::fmt::Debug for NodeClaimNonceVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeClaimNonceVerifier")
            .field("format", &NODE_CLAIM_NONCE_VERIFIER_FORMAT)
            .field("version", &NODE_CLAIM_VERIFIER_VERSION)
            .field("data", &"<redacted-verifier>")
            .finish()
    }
}

impl NodeClaimNonceVerifier {
    pub fn derive(
        claim_id: &str,
        home_group_id: i64,
        node_id: &ReuseEligibleNodeId,
        nonce: &NodeClaimantNonce,
    ) -> Self {
        Self(derive_bound_digest(
            NODE_CLAIM_NONCE_DOMAIN,
            claim_id,
            home_group_id,
            node_id,
            nonce.as_bytes(),
        ))
    }

    pub fn format(&self) -> &'static str {
        NODE_CLAIM_NONCE_VERIFIER_FORMAT
    }

    pub fn version(&self) -> i64 {
        NODE_CLAIM_VERIFIER_VERSION
    }

    pub fn data(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn verify_data(&self, stored: &[u8]) -> bool {
        stored.len() == self.0.len() && bool::from(self.0.as_slice().ct_eq(stored))
    }
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
    fn generated_claim_secret_and_nonce_are_canonical_and_distinct() {
        let secret = NodeClaimSecret::generate().unwrap();
        let nonce = NodeClaimantNonce::generate().unwrap();
        let secret_wire = secret.to_wire_value();
        let nonce_wire = nonce.to_wire_value();
        assert_eq!(NodeClaimSecret::parse(&secret_wire).unwrap(), secret);
        assert_eq!(NodeClaimantNonce::parse(&nonce_wire).unwrap(), nonce);
        assert!(!secret_wire.contains('='));
        assert!(!nonce_wire.contains('='));
        assert!(NodeClaimSecret::parse(&nonce_wire).is_err());
        assert!(NodeClaimantNonce::parse(&secret_wire).is_err());
        assert!(crate::node_credential::NodeCredentialSecret::parse(&secret_wire).is_err());
    }

    #[test]
    fn claim_wire_parser_rejects_padding_encoding_length_and_noncanonical_bits() {
        assert_eq!(
            NodeClaimSecret::parse("wrong_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
            Err(NodeClaimWireParseError::InvalidPrefix)
        );
        assert_eq!(
            NodeClaimSecret::parse("rpc1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="),
            Err(NodeClaimWireParseError::PaddingNotAllowed)
        );
        assert_eq!(
            NodeClaimSecret::parse("rpc1_***************************************"),
            Err(NodeClaimWireParseError::InvalidEncoding)
        );
        assert_eq!(
            NodeClaimSecret::parse("rpc1_AQ"),
            Err(NodeClaimWireParseError::InvalidLength)
        );
        let canonical = URL_SAFE_NO_PAD.encode([0_u8; NODE_CLAIM_SECRET_LEN]);
        let mut noncanonical = canonical;
        noncanonical.pop();
        noncanonical.push('B');
        assert!(
            NodeClaimSecret::parse(&format!("{NODE_CLAIM_SECRET_PREFIX}{noncanonical}")).is_err(),
            "non-zero trailing Base64URL pad bits must not be accepted"
        );
    }

    #[test]
    fn claim_verifiers_bind_identity_and_use_independent_domains() {
        let secret = NodeClaimSecret::from_test_bytes(SECRET_BYTES);
        let nonce = NodeClaimantNonce::from_test_bytes(SECRET_BYTES);
        let node = ReuseEligibleNodeId::parse("Node_A").unwrap();
        let secret_verifier = NodeClaimSecretVerifier::derive("claim-vector-1", 42, &node, &secret);
        let nonce_verifier = NodeClaimNonceVerifier::derive("claim-vector-1", 42, &node, &nonce);

        assert_eq!(secret_verifier.format(), "rp-node-claim-sha256");
        assert_eq!(nonce_verifier.format(), "rp-node-claim-nonce-sha256");
        assert_eq!(secret_verifier.version(), 1);
        assert_eq!(
            hex::encode(secret_verifier.data()),
            "f32683a230a58a1083458b6b2ab4aa8e3abaa3a6dc2da5d965561cc219ef57e5"
        );
        assert_eq!(
            hex::encode(nonce_verifier.data()),
            "a21cc8432153e96e774df72c6ba771d7f22a5f0a6985e54cbda98689e704681f"
        );
        assert_ne!(secret_verifier.data(), nonce_verifier.data());
        let credential_secret =
            crate::node_credential::NodeCredentialSecret::from_test_bytes(SECRET_BYTES);
        let credential_verifier = crate::node_credential::NodeCredentialVerifier::derive(
            "claim-vector-1",
            42,
            &node,
            &credential_secret,
        );
        assert_ne!(
            secret_verifier.data(),
            credential_verifier.data(),
            "Claim Secret and permanent Node Credential must use independent verifier domains"
        );
        assert_ne!(
            secret_verifier.data(),
            NodeClaimSecretVerifier::derive("claim-vector-2", 42, &node, &secret).data()
        );
        assert_ne!(
            secret_verifier.data(),
            NodeClaimSecretVerifier::derive("claim-vector-1", 43, &node, &secret).data()
        );
        assert_ne!(
            secret_verifier.data(),
            NodeClaimSecretVerifier::derive(
                "claim-vector-1",
                42,
                &ReuseEligibleNodeId::parse("Node_B").unwrap(),
                &secret,
            )
            .data()
        );
        assert!(secret_verifier.verify_data(secret_verifier.data()));
        assert!(!secret_verifier.verify_data(&[0_u8; 32]));
    }

    #[test]
    fn claim_material_debug_is_redacted() {
        let secret = NodeClaimSecret::from_test_bytes([0x41; 32]);
        let nonce = NodeClaimantNonce::from_test_bytes([0x42; 32]);
        let node = ReuseEligibleNodeId::parse("Node_A").unwrap();
        let secret_verifier = NodeClaimSecretVerifier::derive("claim-debug", 7, &node, &secret);
        let nonce_verifier = NodeClaimNonceVerifier::derive("claim-debug", 7, &node, &nonce);
        for debug in [
            format!("{secret:?}"),
            format!("{nonce:?}"),
            format!("{secret_verifier:?}"),
            format!("{nonce_verifier:?}"),
        ] {
            assert!(debug.contains("redacted"));
            assert!(!debug.contains(&secret.to_wire_value()));
            assert!(!debug.contains(&nonce.to_wire_value()));
            assert!(!debug.contains(&hex::encode(secret_verifier.data())));
            assert!(!debug.contains(&hex::encode(nonce_verifier.data())));
        }
    }
}
