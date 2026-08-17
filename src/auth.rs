//! Authentication — Klever wallet signing for API auth headers.
//!
//! Implements the auth header scheme from spec 4.2:
//!   X-Ogmara-Auth:      base64(Ed25519 signature)
//!   X-Ogmara-Address:   klv1... Klever address
//!   X-Ogmara-Timestamp: unix timestamp in milliseconds

use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha3::{Digest, Keccak256};

use crate::error::SdkError;

/// Klever message signing prefix (from kos-rs).
const KLEVER_MSG_PREFIX: &[u8] = b"\x17Klever Signed Message:\n";

/// The node identity an auth signature binds to (audit 2026-06-07
/// host-binding). Fetched once from `GET /api/v1/health` and cached by the
/// client; binding `{network, node_id}` defeats cross-node replay.
#[derive(Debug, Clone)]
pub struct NodeBinding {
    /// Klever network ("testnet" / "mainnet").
    pub network: String,
    /// Target node's Ogmara `node_id`.
    pub node_id: String,
}

/// Generate a random single-use nonce as a lowercase hex string (16 bytes).
/// Uses the OS CSPRNG (`OsRng`) — never a weak PRNG, so an attacker cannot
/// pre-compute nonces to defeat the verifier's replay cache.
pub fn random_nonce_hex() -> String {
    use rand::RngCore;
    let mut buf = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    hex::encode(buf)
}

/// A signer that can produce auth headers for authenticated API calls.
pub struct WalletSigner {
    signing_key: SigningKey,
    address: String,
}

impl WalletSigner {
    /// Create a signer from a raw Ed25519 private key (32 bytes).
    pub fn from_private_key(private_key: &[u8; 32]) -> Result<Self, SdkError> {
        let signing_key = SigningKey::from_bytes(private_key);
        let address = pubkey_to_address(&signing_key.verifying_key())?;
        Ok(Self {
            signing_key,
            address,
        })
    }

    /// Create a signer from a hex-encoded private key.
    pub fn from_hex(hex_key: &str) -> Result<Self, SdkError> {
        let bytes = hex::decode(hex_key)
            .map_err(|e| SdkError::InvalidKey(format!("invalid hex: {}", e)))?;
        if bytes.len() != 32 {
            return Err(SdkError::InvalidKey(format!(
                "expected 32 bytes, got {}",
                bytes.len()
            )));
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&bytes);
        Self::from_private_key(&key)
    }

    /// Get the signer's Klever address.
    pub fn address(&self) -> &str {
        &self.address
    }

    /// Get the signer's public key.
    pub fn public_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    /// Build auth headers for an API request.
    ///
    /// The signature is bound to the target node's `network` + `node_id`
    /// plus a fresh single-use `nonce` (audit 2026-06-07 host-binding), so
    /// a captured header is neither portable to another node nor replayable
    /// to this one.
    ///
    /// Returns `(auth_b64, address, timestamp_ms, nonce)`.
    pub fn sign_request(
        &self,
        network: &str,
        node_id: &str,
        method: &str,
        path: &str,
    ) -> (String, String, String, String) {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let nonce = random_nonce_hex();
        let auth_string = format!(
            "ogmara-auth:{}:{}:{}:{}:{}:{}",
            network, node_id, nonce, timestamp, method, path
        );
        let signature = sign_klever_message(&self.signing_key, auth_string.as_bytes());

        let auth_b64 = base64::engine::general_purpose::STANDARD
            .encode(signature.to_bytes());

        (auth_b64, self.address.clone(), timestamp.to_string(), nonce)
    }

    /// Sign an Ogmara protocol message (for envelope construction).
    ///
    /// Format (protocol v2, audit 2026-08-16 C1): `"ogmara-msg:" +
    /// network_len(1) + network + version(1) + msg_type(1) + msg_id(32) +
    /// timestamp(8) + payload`. `network` ("testnet"/"mainnet") binds the
    /// signature to a single Klever network — mirrors
    /// `signing::ogmara_signed_bytes` in the node (l2-node
    /// `crypto/signing.rs`) and `WalletSigner.signEnvelope` in sdk-js; all
    /// three must never drift apart.
    pub fn sign_envelope(
        &self,
        network: &str,
        version: u8,
        msg_type: u8,
        msg_id: &[u8; 32],
        timestamp: u64,
        payload: &[u8],
    ) -> Vec<u8> {
        let network_bytes = network.as_bytes();
        let mut signed_bytes = Vec::with_capacity(
            11 + 1 + network_bytes.len() + 1 + 1 + 32 + 8 + payload.len(),
        );
        signed_bytes.extend_from_slice(b"ogmara-msg:");
        signed_bytes.push(network_bytes.len() as u8);
        signed_bytes.extend_from_slice(network_bytes);
        signed_bytes.push(version);
        signed_bytes.push(msg_type);
        signed_bytes.extend_from_slice(msg_id);
        signed_bytes.extend_from_slice(&timestamp.to_be_bytes());
        signed_bytes.extend_from_slice(payload);

        let hash = keccak256(&signed_bytes);
        let signature = self.signing_key.sign(&hash);
        signature.to_bytes().to_vec()
    }

    /// Compute a message ID (protocol v2, audit 2026-08-16 C1):
    /// `Keccak-256(network_len(1) + network + author_pubkey + payload + timestamp)`.
    /// Mirrors `crypto::compute_msg_id` in the node and `computeMsgId` in
    /// sdk-js — must never drift apart.
    pub fn compute_msg_id(&self, network: &str, payload: &[u8], timestamp: u64) -> [u8; 32] {
        let network_bytes = network.as_bytes();
        let mut data = Vec::with_capacity(1 + network_bytes.len() + 32 + payload.len() + 8);
        data.push(network_bytes.len() as u8);
        data.extend_from_slice(network_bytes);
        data.extend_from_slice(self.signing_key.verifying_key().as_bytes());
        data.extend_from_slice(payload);
        data.extend_from_slice(&timestamp.to_be_bytes());
        keccak256(&data)
    }
}

/// Sign using Klever message format: prefix + length + message → Keccak-256 → Ed25519.
fn sign_klever_message(key: &SigningKey, message: &[u8]) -> Signature {
    let length_str = message.len().to_string();
    let mut data = Vec::with_capacity(KLEVER_MSG_PREFIX.len() + length_str.len() + message.len());
    data.extend_from_slice(KLEVER_MSG_PREFIX);
    data.extend_from_slice(length_str.as_bytes());
    data.extend_from_slice(message);
    let hash = keccak256(&data);
    key.sign(&hash)
}

/// Compute Keccak-256 hash.
fn keccak256(data: &[u8]) -> [u8; 32] {
    Keccak256::digest(data).into()
}

/// Derive a Klever address (klv1...) from an Ed25519 public key.
fn pubkey_to_address(pubkey: &VerifyingKey) -> Result<String, SdkError> {
    let hrp = bech32::Hrp::parse("klv").expect("valid hrp");
    bech32::encode::<bech32::Bech32>(hrp, pubkey.as_bytes())
        .map_err(|e| SdkError::InvalidKey(format!("bech32 error: {}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signer_from_random_key() {
        let key = SigningKey::generate(&mut rand::rngs::OsRng);
        let signer = WalletSigner::from_private_key(&key.to_bytes()).unwrap();
        assert!(signer.address().starts_with("klv1"));
    }

    #[test]
    fn test_sign_request_produces_valid_output() {
        let key = SigningKey::generate(&mut rand::rngs::OsRng);
        let signer = WalletSigner::from_private_key(&key.to_bytes()).unwrap();
        let (auth, addr, ts, nonce) =
            signer.sign_request("testnet", "node-abc", "GET", "/api/v1/health");
        assert!(!auth.is_empty());
        assert!(addr.starts_with("klv1"));
        assert!(ts.parse::<u64>().is_ok());
        // Host-binding nonce (audit 2026-06-07): 16 bytes → 32 hex chars.
        assert_eq!(nonce.len(), 32);
        assert!(nonce.bytes().all(|b| b.is_ascii_hexdigit()));
    }

    #[test]
    fn test_sign_request_nonce_is_fresh() {
        let key = SigningKey::generate(&mut rand::rngs::OsRng);
        let signer = WalletSigner::from_private_key(&key.to_bytes()).unwrap();
        let (_, _, _, n1) = signer.sign_request("testnet", "n", "GET", "/x");
        let (_, _, _, n2) = signer.sign_request("testnet", "n", "GET", "/x");
        assert_ne!(n1, n2);
    }

    #[test]
    fn test_compute_msg_id_deterministic() {
        let key = SigningKey::generate(&mut rand::rngs::OsRng);
        let signer = WalletSigner::from_private_key(&key.to_bytes()).unwrap();
        let id1 = signer.compute_msg_id("testnet", b"hello", 12345);
        let id2 = signer.compute_msg_id("testnet", b"hello", 12345);
        assert_eq!(id1, id2);
    }

    #[test]
    fn test_compute_msg_id_binds_to_network() {
        // C1 regression: same author/payload/timestamp must produce a
        // DIFFERENT msg_id per network — otherwise a testnet envelope's
        // msg_id would collide with its mainnet counterpart.
        let key = SigningKey::generate(&mut rand::rngs::OsRng);
        let signer = WalletSigner::from_private_key(&key.to_bytes()).unwrap();
        let testnet_id = signer.compute_msg_id("testnet", b"hello", 12345);
        let mainnet_id = signer.compute_msg_id("mainnet", b"hello", 12345);
        assert_ne!(testnet_id, mainnet_id);
    }

    #[test]
    fn test_sign_envelope() {
        let key = SigningKey::generate(&mut rand::rngs::OsRng);
        let signer = WalletSigner::from_private_key(&key.to_bytes()).unwrap();
        let sig = signer.sign_envelope("testnet", 2, 0x01, &[0u8; 32], 12345, b"payload");
        assert_eq!(sig.len(), 64);
    }
}
