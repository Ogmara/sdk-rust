//! Proof-of-Work solver for anti-spam challenges (audit 2026-06-07 W4).
//!
//! When a wallet is unknown to the node, the node rejects the request with an
//! HTTP 429 carrying a PoW challenge. The client must find a nonce such that
//! `SHA-256(prefix_ascii_bytes || nonce_le_u64)` has the required number of
//! leading zero bits, then POST the solution to `/api/v1/pow/verify`.
//!
//! The hashing and difficulty check are byte-for-byte identical to:
//! - the L2 node verifier (`l2-node/src/pow.rs::has_leading_zeros` /
//!   `verify_solution`: `Sha256(prefix.as_bytes() || nonce.to_le_bytes())`)
//! - the JS SDK (`sdk-js/src/pow.ts`: `sha256(prefix_utf8 || nonce_le_u64)`)
//!
//! A mismatch here would silently fail auth, so the encoding is locked:
//! the prefix is hashed as its ASCII/UTF-8 bytes (it is a hex string, but is
//! NOT hex-decoded), and the nonce is appended as 8 little-endian bytes.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::SdkError;

/// Client-side difficulty clamp (audit 2026-06-07 W4). The node default is 20
/// bits (~1M hashes, a few seconds). We refuse to attempt anything materially
/// harder so a hostile node can't force unbounded work on the client. 28 bits
/// is ~256x the default — a generous ceiling that still bounds worst-case work.
pub const MAX_POW_DIFFICULTY: u8 = 28;

/// A PoW challenge issued by the node (matches the node's `PowChallenge` and
/// the JS `PowChallenge`).
#[derive(Debug, Clone, Deserialize)]
pub struct PowChallenge {
    /// Unique challenge ID, echoed back in the solution.
    pub challenge_id: String,
    /// Hex-encoded prefix string. Hashed as its ASCII bytes (NOT hex-decoded).
    pub prefix: String,
    /// Required number of leading zero bits in the hash.
    pub difficulty: u8,
    /// When this challenge expires (Unix ms). Unused by the solver but part of
    /// the wire shape.
    #[serde(default)]
    pub expires_at: u64,
}

/// A PoW solution submitted back to the node (matches the node's `PowSolution`).
#[derive(Debug, Clone, Serialize)]
pub struct PowSolution {
    /// The challenge ID being solved.
    pub challenge_id: String,
    /// The wallet address the challenge was issued for.
    pub address: String,
    /// The nonce that satisfies the difficulty requirement.
    pub nonce: u64,
}

/// Check if a hash has at least `n` leading zero bits.
///
/// Identical to the node's `has_leading_zeros` and the JS `hasLeadingZeros`.
fn has_leading_zeros(hash: &[u8], n: u8) -> bool {
    let full_bytes = (n / 8) as usize;
    let remaining_bits = n % 8;

    if hash.len() < full_bytes {
        return false;
    }
    for byte in &hash[..full_bytes] {
        if *byte != 0 {
            return false;
        }
    }

    if remaining_bits > 0 {
        if hash.len() <= full_bytes {
            return false;
        }
        let mask = 0xFF_u8 << (8 - remaining_bits);
        if hash[full_bytes] & mask != 0 {
            return false;
        }
    }

    true
}

/// Solve a PoW challenge by finding a nonce that produces the required number
/// of leading zero bits in `SHA-256(prefix_bytes || nonce_le_u64)`.
///
/// Returns the winning nonce. Rejects challenges whose difficulty exceeds
/// [`MAX_POW_DIFFICULTY`] (audit 2026-06-07 W4) so a hostile node can't force
/// unbounded work. Also bounds the nonce search at `u32::MAX` iterations,
/// matching the JS solver's safety cap.
pub fn solve_challenge(challenge: &PowChallenge) -> Result<u64, SdkError> {
    if challenge.difficulty > MAX_POW_DIFFICULTY {
        return Err(SdkError::Protocol(format!(
            "PoW difficulty {} exceeds client max {} — refusing to solve",
            challenge.difficulty, MAX_POW_DIFFICULTY
        )));
    }

    // Pre-hash the constant prefix once, then clone the hasher per attempt so we
    // only re-feed the 8 nonce bytes. Cheaper than rebuilding the prefix state
    // for every nonce.
    let prefix_bytes = challenge.prefix.as_bytes();
    let mut base = Sha256::new();
    base.update(prefix_bytes);

    for nonce in 0u64..=u32::MAX as u64 {
        let mut hasher = base.clone();
        hasher.update(nonce.to_le_bytes());
        let hash = hasher.finalize();
        if has_leading_zeros(&hash, challenge.difficulty) {
            return Ok(nonce);
        }
    }

    Err(SdkError::Protocol(format!(
        "PoW solve exhausted nonce space (difficulty {} too high)",
        challenge.difficulty
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Solve a known low-difficulty challenge and verify the result the same
    /// way the node does. Difficulty 8 (one full zero byte) is found in a
    /// handful of hashes, keeping the test fast and deterministic.
    #[test]
    fn solves_low_difficulty_challenge() {
        let challenge = PowChallenge {
            challenge_id: "test-challenge".into(),
            // Mirror the node's prefix shape (a hex string, hashed as ASCII).
            prefix: "deadbeefdeadbeefdeadbeefdeadbeef".into(),
            difficulty: 8,
            expires_at: 0,
        };

        let nonce = solve_challenge(&challenge).expect("should solve difficulty 8");

        // Re-derive the hash exactly as the node verifier does and confirm it
        // satisfies the difficulty — this is the byte-for-byte cross-check.
        let mut hasher = Sha256::new();
        hasher.update(challenge.prefix.as_bytes());
        hasher.update(nonce.to_le_bytes());
        let hash = hasher.finalize();
        assert!(
            has_leading_zeros(&hash, challenge.difficulty),
            "winning hash {} must have {} leading zero bits",
            hex::encode(hash),
            challenge.difficulty
        );
    }

    #[test]
    fn rejects_difficulty_above_clamp() {
        let challenge = PowChallenge {
            challenge_id: "evil".into(),
            prefix: "00".into(),
            difficulty: MAX_POW_DIFFICULTY + 1,
            expires_at: 0,
        };
        let err = solve_challenge(&challenge).unwrap_err();
        assert!(matches!(err, SdkError::Protocol(_)));
    }

    #[test]
    fn leading_zeros_bit_granularity() {
        // 0x0F = 0000_1111 → exactly 4 leading zero bits.
        assert!(has_leading_zeros(&[0x0F], 4));
        assert!(!has_leading_zeros(&[0x0F], 5));
        // 0x00 0x80 = 8 leading zeros then a 1 bit → 8 ok, 9 not.
        assert!(has_leading_zeros(&[0x00, 0x80], 8));
        assert!(!has_leading_zeros(&[0x00, 0x80], 9));
    }
}
