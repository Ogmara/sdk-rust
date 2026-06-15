//! Encrypted media (P5 / D6, protocol §8 + spec 04 §9).
//!
//! Files attached to encrypted DMs and channels are sealed with a fresh per-file
//! XChaCha20-Poly1305 key BEFORE upload. The per-file key never gets its own
//! envelope: it rides inside the message's already-encrypted content blob (a
//! [`MediaDescriptor`] in `content.media`), which is itself sealed under the
//! channel epoch key / DM conv key. The members who can read the message recover
//! every file key for free, and the node — holding no key — serves the ciphertext
//! blindly.
//!
//! Mirrors sdk-js `media.ts` byte-for-byte: the same `aad = "ogmara-media-v1"`
//! domain tag and the same fixed KAT are asserted in both SDKs.

use rand::rngs::OsRng;
use rand::RngCore;

use crate::crypto::{aead_decrypt, aead_encrypt, AEAD_NONCE_LEN, KEY_LEN};
use crate::error::SdkError;

/// AEAD associated data binding every encrypted media blob to its purpose.
/// Identical constant in sdk-js (`MEDIA_AAD`).
pub const MEDIA_AAD: &[u8] = b"ogmara-media-v1";

/// A decrypted attachment, carried INSIDE the message ciphertext (spec 04 §9.2).
/// The real MIME type and filename are hidden from the node; the on-wire
/// `Attachment` keeps only `{ cid, size_bytes }` + a generic MIME (§9.3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MediaDescriptor {
    /// CID of the ENCRYPTED blob on IPFS.
    pub cid: String,
    /// Plaintext byte size (UI hint; the blob on IPFS is ~16 bytes larger).
    pub size: u64,
    /// Real MIME type (e.g. `image/png`) — hidden from the node.
    pub mime: String,
    /// Original filename — hidden from the node.
    pub name: Option<String>,
    /// 32-byte per-file key.
    pub key: [u8; KEY_LEN],
    /// 24-byte nonce for the file content.
    pub nonce: [u8; AEAD_NONCE_LEN],
    /// CID of the encrypted thumbnail blob, if any.
    pub tcid: Option<String>,
    /// 24-byte nonce for the thumbnail (reuses [`MediaDescriptor::key`]).
    pub tnonce: Option<[u8; AEAD_NONCE_LEN]>,
}

/// Output of [`encrypt_file`]: upload `cipher`, keep `key`/`nonce` for the descriptor.
pub struct EncryptedFile {
    /// Ciphertext (`ct || tag`) — upload as an opaque blob (`encrypted=true`).
    pub cipher: Vec<u8>,
    /// 32-byte per-file key.
    pub key: [u8; KEY_LEN],
    /// 24-byte file nonce.
    pub nonce: [u8; AEAD_NONCE_LEN],
}

/// Generate a fresh 32-byte per-file key.
pub fn random_file_key() -> [u8; KEY_LEN] {
    let mut k = [0u8; KEY_LEN];
    OsRng.fill_bytes(&mut k);
    k
}

fn random_nonce() -> [u8; AEAD_NONCE_LEN] {
    let mut n = [0u8; AEAD_NONCE_LEN];
    OsRng.fill_bytes(&mut n);
    n
}

/// Encrypt file bytes with a fresh per-file key (spec 04 §9.1). Upload the returned
/// `cipher`; the `key`/`nonce` go into the [`MediaDescriptor`] inside the sealed
/// message content.
pub fn encrypt_file(plaintext: &[u8]) -> Result<EncryptedFile, SdkError> {
    let key = random_file_key();
    let nonce = random_nonce();
    let cipher = aead_encrypt(&key, &nonce, plaintext, MEDIA_AAD)?;
    Ok(EncryptedFile { cipher, key, nonce })
}

/// Encrypt a thumbnail under an existing file key (distinct nonce — never reuse a
/// `(key, nonce)` pair). Returns the ciphertext to upload and the nonce to record
/// in [`MediaDescriptor::tnonce`].
pub fn encrypt_thumbnail(
    plaintext: &[u8],
    file_key: &[u8; KEY_LEN],
) -> Result<(Vec<u8>, [u8; AEAD_NONCE_LEN]), SdkError> {
    let nonce = random_nonce();
    let cipher = aead_encrypt(file_key, &nonce, plaintext, MEDIA_AAD)?;
    Ok((cipher, nonce))
}

/// Decrypt an encrypted media (or thumbnail) blob. Returns [`SdkError::Crypto`] on
/// any authentication failure.
pub fn decrypt_media(
    cipher: &[u8],
    key: &[u8; KEY_LEN],
    nonce: &[u8; AEAD_NONCE_LEN],
) -> Result<Vec<u8>, SdkError> {
    aead_decrypt(key, nonce, cipher, MEDIA_AAD)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_roundtrip() {
        let plain: Vec<u8> = (0u8..200).collect();
        let ef = encrypt_file(&plain).unwrap();
        assert_eq!(ef.cipher.len(), plain.len() + 16); // + Poly1305 tag
        assert_eq!(decrypt_media(&ef.cipher, &ef.key, &ef.nonce).unwrap(), plain);
    }

    #[test]
    fn thumbnail_reuses_key_distinct_nonce() {
        let ef = encrypt_file(&[1u8; 50]).unwrap();
        let thumb = [7u8; 31];
        let (cipher, nonce) = encrypt_thumbnail(&thumb, &ef.key).unwrap();
        assert_ne!(nonce, ef.nonce);
        assert_eq!(decrypt_media(&cipher, &ef.key, &nonce).unwrap(), thumb);
    }

    #[test]
    fn wrong_key_fails() {
        let ef = encrypt_file(&[1u8; 32]).unwrap();
        assert!(decrypt_media(&ef.cipher, &random_file_key(), &ef.nonce).is_err());
    }

    /// Fixed cross-impl KAT — must equal sdk-js `media.test.ts`. file_key = 1..=32,
    /// nonce = 1..=24, plaintext = "ogmara", aad = MEDIA_AAD.
    #[test]
    fn media_kat_matches_sdk_js() {
        let mut key = [0u8; KEY_LEN];
        for (i, b) in key.iter_mut().enumerate() {
            *b = (i + 1) as u8;
        }
        let mut nonce = [0u8; AEAD_NONCE_LEN];
        for (i, b) in nonce.iter_mut().enumerate() {
            *b = (i + 1) as u8;
        }
        let cipher = aead_encrypt(&key, &nonce, b"ogmara", MEDIA_AAD).unwrap();
        assert_eq!(hex::encode(&cipher), "dabfaaef612395d76fade0ec7c7780daeee008e5d398");
    }
}
