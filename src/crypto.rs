//! E2E crypto core (P1, protocol §8). Shared symmetric content encryption + key
//! wrapping, mirrored **byte-for-byte** by sdk-js `crypto.ts` (the same RFC known-
//! answer tests and the same Ogmara wrap vector are asserted in both SDKs — any
//! drift breaks one suite).
//!
//! Primitives are audited RustCrypto crates, wrapped behind Ogmara-native names so
//! the rest of the SDK never couples to a specific crate API:
//! - **AEAD:** XChaCha20-Poly1305, 24-byte nonce (`chacha20poly1305`)
//! - **KDF:**  HKDF-SHA256 (`hkdf` + `sha2`)
//! - **DH:**   X25519, constant-time (`x25519-dalek`)
//!
//! Every function is deterministic given its inputs — randomness is injected by the
//! caller ([`wrap_key`] is the one convenience that draws fresh randomness) so the
//! cross-impl vectors reproduce exactly. This module is content-key plumbing only;
//! the channel/DM policy (epochs, fan-out, history) lives in higher layers.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::error::SdkError;

/// XChaCha20-Poly1305 nonce length (bytes). The 24-byte nonce is what makes random
/// nonces safe at message scale (vs. the 12-byte ChaCha20-Poly1305 birthday bound).
pub const AEAD_NONCE_LEN: usize = 24;
/// Symmetric key length (bytes) — content keys, channel keys, and wrapped keys.
pub const KEY_LEN: usize = 32;
/// Poly1305 tag length (bytes); appended to the ciphertext by [`aead_encrypt`].
pub const AEAD_TAG_LEN: usize = 16;

/// HKDF `info` label for the ECIES key-wrap KDF (domain separation). Bump the
/// version suffix if the wrap construction ever changes so old/new can't collide.
const KEYWRAP_INFO: &[u8] = b"ogmara-keywrap-v1";

/// Encrypt `plaintext` under `key` with XChaCha20-Poly1305. Returns
/// `ciphertext || tag` (the trailing 16 bytes are the Poly1305 tag). `aad` is
/// authenticated but NOT encrypted — pass the envelope binding (for content:
/// `channel_id || epoch || msg_id`; for a key wrap: the ephemeral pubkey) so a
/// ciphertext can't be spliced onto a different envelope.
///
/// The caller owns nonce uniqueness per `key`: never reuse a `(key, nonce)` pair.
pub fn aead_encrypt(
    key: &[u8; KEY_LEN],
    nonce: &[u8; AEAD_NONCE_LEN],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, SdkError> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .encrypt(XNonce::from_slice(nonce), Payload { msg: plaintext, aad })
        .map_err(|_| SdkError::Crypto("AEAD encryption failed".into()))
}

/// Decrypt `ciphertext` (`ct || tag`) produced by [`aead_encrypt`]. Returns
/// [`SdkError::Crypto`] on ANY authentication failure (wrong key, tampered bytes,
/// or wrong `aad`) — the error is deliberately indistinguishable across causes.
pub fn aead_decrypt(
    key: &[u8; KEY_LEN],
    nonce: &[u8; AEAD_NONCE_LEN],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, SdkError> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .decrypt(XNonce::from_slice(nonce), Payload { msg: ciphertext, aad })
        .map_err(|_| SdkError::Crypto("AEAD authentication failed".into()))
}

/// HKDF-SHA256 (RFC 5869): derive `len` bytes from `ikm` with `salt` + `info`.
pub fn hkdf_sha256(ikm: &[u8], salt: &[u8], info: &[u8], len: usize) -> Result<Vec<u8>, SdkError> {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut okm = vec![0u8; len];
    hk.expand(info, &mut okm)
        .map_err(|_| SdkError::Crypto("HKDF expand: invalid output length".into()))?;
    Ok(okm)
}

/// X25519 Diffie-Hellman. Rejects an all-zero (low-order point) shared secret,
/// matching sdk-js `getSharedSecret`. An error means a hostile/invalid peer key —
/// callers MUST treat it as fatal, never fall back to an unauthenticated path.
pub fn x25519_dh(private_key: &[u8; 32], peer_public: &[u8; 32]) -> Result<[u8; 32], SdkError> {
    let secret = StaticSecret::from(*private_key);
    let shared = secret.diffie_hellman(&PublicKey::from(*peer_public));
    let bytes = shared.to_bytes();
    // Non-secret-dependent all-zero check (low-order peer key → zero shared secret).
    if bytes.iter().fold(0u8, |acc, b| acc | b) == 0 {
        return Err(SdkError::Crypto(
            "X25519 all-zero shared secret (low-order peer key rejected)".into(),
        ));
    }
    Ok(bytes)
}

/// The X25519 public key (32 bytes) for a 32-byte secret.
pub fn x25519_public(private_key: &[u8; 32]) -> [u8; 32] {
    PublicKey::from(&StaticSecret::from(*private_key)).to_bytes()
}

/// A symmetric key wrapped to a recipient's device encryption public key (ECIES,
/// protocol §8.2). Carries the ephemeral pubkey + nonce needed to unwrap.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WrappedKey {
    /// Ephemeral X25519 public key (32 bytes).
    pub eph_pub: [u8; 32],
    /// AEAD nonce (24 bytes).
    pub nonce: [u8; AEAD_NONCE_LEN],
    /// Wrapped key bytes: `KEY_LEN + AEAD_TAG_LEN` = 48 bytes.
    pub wrapped: Vec<u8>,
}

/// Wrap a 32-byte symmetric key `k` for `recipient_pub` (a device enc pubkey) using
/// a **caller-supplied** ephemeral secret + nonce. Deterministic — used by the
/// cross-impl test vector; production code calls [`wrap_key`] (fresh randomness).
///
/// Construction (must stay identical to sdk-js `wrapKeyWith`):
/// `shared = X25519(eph_priv, recipient_pub)`,
/// `wk = HKDF-SHA256(ikm=shared, salt=context, info="ogmara-keywrap-v1", 32)`,
/// `wrapped = AEAD(wk, nonce, k, aad=eph_pub)`.
/// `context` domain-separates the KDF (e.g. `channel_id || epoch` or `conversation_id`).
pub fn wrap_key_with(
    k: &[u8; KEY_LEN],
    recipient_pub: &[u8; 32],
    context: &[u8],
    eph_priv: &[u8; 32],
    nonce: &[u8; AEAD_NONCE_LEN],
) -> Result<WrappedKey, SdkError> {
    let eph_pub = x25519_public(eph_priv);
    let shared = x25519_dh(eph_priv, recipient_pub)?;
    let wk = hkdf_sha256(&shared, context, KEYWRAP_INFO, KEY_LEN)?;
    let mut wk32 = [0u8; KEY_LEN];
    wk32.copy_from_slice(&wk);
    // Bind the wrap to its ephemeral pubkey so a wrapped blob can't be replayed
    // under a substituted eph_pub.
    let wrapped = aead_encrypt(&wk32, nonce, k, &eph_pub)?;
    wk32.fill(0);
    Ok(WrappedKey {
        eph_pub,
        nonce: *nonce,
        wrapped,
    })
}

/// Wrap `k` for `recipient_pub` with a fresh ephemeral keypair and random nonce
/// (production path). `context` domain-separates the KDF.
pub fn wrap_key(
    k: &[u8; KEY_LEN],
    recipient_pub: &[u8; 32],
    context: &[u8],
) -> Result<WrappedKey, SdkError> {
    let eph_priv = StaticSecret::random_from_rng(OsRng).to_bytes();
    let mut nonce = [0u8; AEAD_NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    wrap_key_with(k, recipient_pub, context, &eph_priv, &nonce)
}

/// Unwrap a [`WrappedKey`] using the recipient's device enc secret. The `context`
/// must match the one used at wrap time. Returns [`SdkError::Crypto`] on any
/// authentication failure.
pub fn unwrap_key(
    w: &WrappedKey,
    recipient_priv: &[u8; 32],
    context: &[u8],
) -> Result<[u8; KEY_LEN], SdkError> {
    let shared = x25519_dh(recipient_priv, &w.eph_pub)?;
    let wk = hkdf_sha256(&shared, context, KEYWRAP_INFO, KEY_LEN)?;
    let mut wk32 = [0u8; KEY_LEN];
    wk32.copy_from_slice(&wk);
    let pt = aead_decrypt(&wk32, &w.nonce, &w.wrapped, &w.eph_pub)?;
    wk32.fill(0);
    if pt.len() != KEY_LEN {
        return Err(SdkError::Crypto("unwrapped key has wrong length".into()));
    }
    let mut out = [0u8; KEY_LEN];
    out.copy_from_slice(&pt);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- HKDF-SHA256: RFC 5869 Test Case 1 (externally verifiable KAT) ---------
    #[test]
    fn hkdf_rfc5869_case1() {
        let ikm = [0x0bu8; 22];
        let salt: Vec<u8> = (0u8..=0x0c).collect(); // 00..0c (13 bytes)
        let info: Vec<u8> = (0xf0u8..=0xf9).collect(); // f0..f9 (10 bytes)
        let okm = hkdf_sha256(&ikm, &salt, &info, 42).unwrap();
        assert_eq!(
            hex::encode(okm),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        );
    }

    // --- AEAD XChaCha20-Poly1305: draft-irtf-cfrg-xchacha-03 A.3.1 KAT ---------
    #[test]
    fn aead_xchacha_draft_vector() {
        let key: [u8; 32] = core::array::from_fn(|i| 0x80 + i as u8); // 80..9f
        let nonce: [u8; 24] = core::array::from_fn(|i| 0x40 + i as u8); // 40..57
        let aad: [u8; 12] = [
            0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
        ];
        let pt = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let ct = aead_encrypt(&key, &nonce, pt, &aad).unwrap();
        // ciphertext (114) || tag (16) = 130 bytes
        assert_eq!(
            hex::encode(&ct),
            "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb\
             731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b452\
             2f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff9\
             21f9664c97637da9768812f615c68b13b52e\
             c0875924c1c7987947deafd8780acf49"
                .replace(['\n', ' '], "")
        );
        // Roundtrip + AAD binding.
        assert_eq!(aead_decrypt(&key, &nonce, &ct, &aad).unwrap(), pt);
        assert!(aead_decrypt(&key, &nonce, &ct, b"wrong aad").is_err());
    }

    // --- ECIES key wrap: roundtrip + deterministic Ogmara KAT (cross-impl) -----
    #[test]
    fn wrap_roundtrip() {
        let k: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_mul(3).wrapping_add(7));
        let recip_priv: [u8; 32] = core::array::from_fn(|i| (i + 1) as u8);
        let recip_pub = x25519_public(&recip_priv);
        let w = wrap_key(&k, &recip_pub, b"ctx").unwrap();
        assert_eq!(w.wrapped.len(), KEY_LEN + AEAD_TAG_LEN);
        assert_eq!(unwrap_key(&w, &recip_priv, b"ctx").unwrap(), k);
        // Wrong context fails (KDF domain separation).
        assert!(unwrap_key(&w, &recip_priv, b"other").is_err());
    }

    // Deterministic wrap KAT — identical literals asserted in sdk-js `crypto.test.ts`.
    // recipient priv = 0x01..0x20, ephemeral priv = 0x21..0x40, nonce = 0xa0..0xb7,
    // key = 0xff..0xe0 (descending), context = "ogmara-test-context".
    #[test]
    fn wrap_cross_impl_vector() {
        let k: [u8; 32] = core::array::from_fn(|i| 0xff - i as u8);
        let recip_priv: [u8; 32] = core::array::from_fn(|i| (i + 1) as u8);
        let recip_pub = x25519_public(&recip_priv);
        let eph_priv: [u8; 32] = core::array::from_fn(|i| 0x21 + i as u8);
        let nonce: [u8; 24] = core::array::from_fn(|i| 0xa0 + i as u8);

        let w = wrap_key_with(&k, &recip_pub, b"ogmara-test-context", &eph_priv, &nonce).unwrap();
        assert_eq!(
            hex::encode(w.eph_pub),
            "5869aff450549732cbaaed5e5df9b30a6da31cb0e5742bad5ad4a1a768f1a67b",
            "eph_pub drift vs sdk-js"
        );
        assert_eq!(
            hex::encode(&w.wrapped),
            "68697ad63cd9360b1fcbcd26fa499292df75de990f0467a6034617eeeb88eabe2002135f9016a8d20a157d7fcaf4ae6f",
            "wrapped key drift vs sdk-js"
        );
        // And it unwraps back to the original key.
        assert_eq!(unwrap_key(&w, &recip_priv, b"ogmara-test-context").unwrap(), k);
    }
}
