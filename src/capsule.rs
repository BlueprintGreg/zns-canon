//! Sealed seed capsule: the seed's on-disk form.
//!
//! Format is unchanged from the pre-refactor inlined codec: postcard-serialised
//! `{ magic, fingerprint, nonce, ciphertext }`, magic = `b"ZNS_SEED"`, 24-byte
//! `XChaCha20Poly1305` nonce, AAD = `magic || fingerprint`, plaintext = the
//! 32-byte ZIP-32 seed. The sealing key is passed in by the caller —
//! derive it with [`crate::sealing::derive_sealing_key`] (production:
//! SNP hardware; `non-tee` builds: [`crate::sealing::dev_sealing_key`]) —
//! so this module is TEE-agnostic and the crypto is testable off-hardware.
//!
//! The decrypted payload is `seed || access_code_key`: the ZIP-32 seed for
//! the treasury, and the pre-sale access-code key the mint judges claims
//! with. One envelope, one sealing key, one unseal at boot.

use std::fs::File;
use std::io::Read;
use std::path::Path;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand::TryCryptoRng;
use secrecy::{ExposeSecret, Secret};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::Zeroize;
use zip32::fingerprint::SeedFingerprint;

use crate::sealing::SealingKey;

/// The capsule magic; the first 8 bytes of every ZNS seed capsule.
pub const MAGIC: [u8; 8] = *b"ZNS_SEED";

/// The `XChaCha20Poly1305` nonce length.
pub const NONCE_LEN: usize = 24;

/// The ZIP-32 seed length in bytes.
pub const SEED_LEN: usize = 32;

/// Poly1305 tag appended to the payload.
const TAG_LEN: usize = 16;

/// The access-code key rides inside the capsule beside the seed.
pub const ACCESS_CODE_KEY_LEN: usize = 32;

/// The decrypted capsule payload: `seed || access_code_key`.
pub const PAYLOAD_LEN: usize = SEED_LEN + ACCESS_CODE_KEY_LEN;

/// Ciphertext is the payload plus its tag.
pub const CIPHERTEXT_LEN: usize = PAYLOAD_LEN + TAG_LEN;

/// On-disk size: magic, fingerprint, nonce, ciphertext, and the two
/// postcard length bytes. A longer file is not a capsule.
pub const CAPSULE_LEN: usize = MAGIC.len() + 32 + 1 + NONCE_LEN + 1 + CIPHERTEXT_LEN;

/// The context string passed to [`crate::sealing::derive_sealing_key`] when
/// deriving the capsule AEAD key. A single well-known context today; extra
/// contexts are cheap to add.
pub const CAPSULE_KEY_CONTEXT: &[u8] = b"ZNS_SEED/capsule/v1";

/// Errors from capsule sealing, parsing, and unsealing.
#[derive(Debug, Error)]
pub enum CapsuleError {
    #[error("randomness source failed")]
    Rng,

    #[error("capsule magic mismatch (not a ZNS seed capsule)")]
    BadMagic,

    #[error("capsule nonce length {actual} != expected {expected}")]
    BadNonce { actual: usize, expected: usize },

    #[error("capsule length {actual} != expected {expected}")]
    BadLength { actual: usize, expected: usize },

    #[error("capsule ciphertext length {actual} != expected {expected}")]
    BadCiphertext { actual: usize, expected: usize },

    #[error("capsule file unreadable: {0}")]
    Read(#[from] std::io::Error),

    #[error("capsule parse failed: {0}")]
    Parse(String),

    #[error("capsule decryption failed (tampered ciphertext, wrong TEE, or wrong AAD)")]
    Decrypt,

    #[error("capsule sealing failed")]
    Seal,

    #[error("decrypted payload is not exactly {PAYLOAD_LEN} bytes")]
    BadSeedSize,

    #[error("capsule fingerprint does not match the seed it holds")]
    FingerprintMismatch,
}

/// The on-disk sealed seed envelope.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Capsule {
    pub magic: [u8; 8],
    pub fingerprint: [u8; 32],
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

/// The decrypted capsule contents. The seed drives the treasury; the
/// access-code key drives pre-sale claim judging.
pub struct SeedAndAccessCodeKey {
    pub seed: Secret<[u8; SEED_LEN]>,
    pub access_code_key: Secret<[u8; ACCESS_CODE_KEY_LEN]>,
}

/// Reads at most one byte past [`CAPSULE_LEN`]. A different length is
/// refused before the bytes are parsed.
pub fn read_capsule_file(path: impl AsRef<Path>) -> Result<Vec<u8>, CapsuleError> {
    let file = File::open(path)?;
    let mut limited = file.take((CAPSULE_LEN + 1) as u64);
    let mut buf = Vec::with_capacity(CAPSULE_LEN + 1);
    limited.read_to_end(&mut buf)?;
    if buf.len() != CAPSULE_LEN {
        return Err(CapsuleError::BadLength {
            actual: buf.len(),
            expected: CAPSULE_LEN,
        });
    }
    Ok(buf)
}

/// Deserialises a capsule from its on-disk bytes (postcard).
/// The blob and both variable fields must be the fixed lengths.
pub fn parse_capsule(blob: &[u8]) -> Result<Capsule, CapsuleError> {
    if blob.len() != CAPSULE_LEN {
        return Err(CapsuleError::BadLength {
            actual: blob.len(),
            expected: CAPSULE_LEN,
        });
    }
    let capsule: Capsule =
        postcard::from_bytes(blob).map_err(|e| CapsuleError::Parse(e.to_string()))?;
    fixed_fields(&capsule)?;
    Ok(capsule)
}

/// Nonce and ciphertext are fixed sizes. Checked before decryption.
fn fixed_fields(capsule: &Capsule) -> Result<(), CapsuleError> {
    if capsule.nonce.len() != NONCE_LEN {
        return Err(CapsuleError::BadNonce {
            actual: capsule.nonce.len(),
            expected: NONCE_LEN,
        });
    }
    if capsule.ciphertext.len() != CIPHERTEXT_LEN {
        return Err(CapsuleError::BadCiphertext {
            actual: capsule.ciphertext.len(),
            expected: CIPHERTEXT_LEN,
        });
    }
    Ok(())
}

/// Serialises a capsule to its on-disk bytes (postcard).
pub fn serialize_capsule(capsule: &Capsule) -> Result<Vec<u8>, CapsuleError> {
    postcard::to_allocvec(capsule).map_err(|e| CapsuleError::Parse(e.to_string()))
}

/// Seals the seed and the access-code key into a capsule under
/// `sealing_key`.
///
/// The capsule's fingerprint field is computed from the seed itself (so
/// `unseal_seed` can re-derive and cross-check) and is bound into the AEAD
/// as additional authenticated data; any tampering with either fails
/// decryption.
pub fn seal_seed<R>(
    sealing_key: &SealingKey,
    seed: &Secret<[u8; SEED_LEN]>,
    access_code_key: &Secret<[u8; ACCESS_CODE_KEY_LEN]>,
    rng: &mut R,
) -> Result<Capsule, CapsuleError>
where
    R: TryCryptoRng,
{
    let mut payload = [0u8; PAYLOAD_LEN];
    payload[..SEED_LEN].copy_from_slice(seed.expose_secret());
    payload[SEED_LEN..].copy_from_slice(access_code_key.expose_secret());
    let fingerprint = SeedFingerprint::from_seed(seed.expose_secret())
        .expect("ZIP-32 accepts 32-byte seeds")
        .to_bytes();

    let cipher =
        XChaCha20Poly1305::new_from_slice(sealing_key.expose()).expect("sealing key is 32 bytes");

    let mut nonce_bytes = [0u8; NONCE_LEN];
    rng.try_fill_bytes(&mut nonce_bytes)
        .map_err(|_| CapsuleError::Rng)?;

    let mut aad = Vec::with_capacity(MAGIC.len() + fingerprint.len());
    aad.extend_from_slice(&MAGIC);
    aad.extend_from_slice(&fingerprint);

    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce_bytes),
            Payload {
                msg: &payload,
                aad: &aad,
            },
        )
        .map_err(|_| CapsuleError::Seal);
    payload.zeroize();
    let ciphertext = ciphertext?;

    Ok(Capsule {
        magic: MAGIC,
        fingerprint,
        nonce: nonce_bytes.to_vec(),
        ciphertext,
    })
}

/// Unseals a capsule under `sealing_key` (the same key `seal_seed` used).
///
/// Verifies (in order): the magic, the nonce and ciphertext lengths,
/// the AEAD tag with AAD = `magic || fingerprint`, the decrypted payload
/// length, and the fingerprint the seed derives to. Both returned
/// [`Secret`]s wipe on drop.
pub fn unseal_seed(
    sealing_key: &SealingKey,
    capsule: &Capsule,
) -> Result<SeedAndAccessCodeKey, CapsuleError> {
    if capsule.magic != MAGIC {
        return Err(CapsuleError::BadMagic);
    }
    fixed_fields(capsule)?;

    let cipher =
        XChaCha20Poly1305::new_from_slice(sealing_key.expose()).expect("sealing key is 32 bytes");

    let mut aad = Vec::with_capacity(MAGIC.len() + capsule.fingerprint.len());
    aad.extend_from_slice(&capsule.magic);
    aad.extend_from_slice(&capsule.fingerprint);

    let plaintext = cipher.decrypt(
        XNonce::from_slice(&capsule.nonce),
        Payload {
            msg: &capsule.ciphertext,
            aad: &aad,
        },
    );
    let mut plaintext = plaintext.map_err(|_| CapsuleError::Decrypt)?;

    if plaintext.len() != PAYLOAD_LEN {
        plaintext.zeroize();
        return Err(CapsuleError::BadSeedSize);
    }
    let mut seed_bytes = [0u8; SEED_LEN];
    seed_bytes.copy_from_slice(&plaintext[..SEED_LEN]);
    let mut access_code_key = [0u8; ACCESS_CODE_KEY_LEN];
    access_code_key.copy_from_slice(&plaintext[SEED_LEN..]);
    plaintext.zeroize();

    // Cross-check: the capsule's declared fingerprint must match what the
    // seed derives to. AEAD-with-AAD already forces this — tampering with
    // the fingerprint changes the AAD, so decrypt would have failed — but
    // an explicit check makes the invariant visible at the callsite.
    let actual = SeedFingerprint::from_seed(&seed_bytes)
        .expect("ZIP-32 accepts 32-byte seeds")
        .to_bytes();
    if actual != capsule.fingerprint {
        seed_bytes.zeroize();
        return Err(CapsuleError::FingerprintMismatch);
    }

    Ok(SeedAndAccessCodeKey {
        seed: Secret::new(seed_bytes),
        access_code_key: Secret::new(access_code_key),
    })
}

/// The capsule hash: BLAKE2b-256 of the capsule's on-disk bytes — the
/// `capsule_hash` in attestation layouts, the genesis record, and the
/// custody manifest.
pub fn hash(capsule_bytes: &[u8]) -> [u8; 32] {
    crate::blake2b(capsule_bytes)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::SysRng;

    #[test]
    fn hash_is_blake2b_256_of_the_exact_bytes() {
        // BLAKE2b-256 of the empty input, from the BLAKE2 spec's known vectors.
        assert_eq!(
            hex::encode(hash(b"")),
            "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8"
        );
        // Hashing the parsed capsule and hashing the raw bytes must agree:
        // callers pass on-disk bytes, never a re-serialization.
        let key = crate::sealing::SealingKey::new([0x42; 32]);
        let blob =
            serialize_capsule(&seal_seed(&key, &a_seed(), &a_key(), &mut SysRng).expect("seal"))
                .expect("serialize");
        let parsed = parse_capsule(&blob).expect("parse");
        assert_eq!(
            hash(&blob),
            hash(&serialize_capsule(&parsed).expect("re-serialize"))
        );
    }

    fn a_seed() -> Secret<[u8; SEED_LEN]> {
        Secret::new([7u8; SEED_LEN])
    }

    fn a_key() -> Secret<[u8; ACCESS_CODE_KEY_LEN]> {
        Secret::new([0x33; ACCESS_CODE_KEY_LEN])
    }

    /// A fixed test key; capsule tests are sealed-envelope round-trips and
    /// do not depend on the TEE seam at all.
    fn fake_key() -> SealingKey {
        SealingKey::new([0x42; 32])
    }

    /// Round-trip: what seal_seed writes, unseal_seed reads back byte-for-byte.
    #[test]
    fn seal_unseal_roundtrip() {
        let key = fake_key();
        let seed = a_seed();
        let capsule = seal_seed(&key, &seed, &a_key(), &mut SysRng).expect("seal");
        let out = unseal_seed(&key, &capsule).expect("unseal");
        assert_eq!(out.seed.expose_secret(), seed.expose_secret());
        assert_eq!(out.access_code_key.expose_secret(), a_key().expose_secret());
    }

    /// A pre-access-code capsule (32-byte seed payload) fails the length
    /// check before any decryption: the payload size is the format version.
    #[test]
    fn a_legacy_seed_only_capsule_is_rejected() {
        let legacy_len = MAGIC.len() + 32 + 1 + NONCE_LEN + 1 + (32 + TAG_LEN);
        let blob = vec![0u8; legacy_len];
        assert!(matches!(
            parse_capsule(&blob),
            Err(CapsuleError::BadLength {
                actual: 114,
                expected: CAPSULE_LEN
            })
        ));
    }

    /// A capsule whose magic no longer says `ZNS_SEED` never even reaches
    /// AEAD — we fail fast with `BadMagic`.
    #[test]
    fn bad_magic_rejected() {
        let key = fake_key();
        let seed = a_seed();
        let mut capsule = seal_seed(&key, &seed, &a_key(), &mut SysRng).expect("seal");
        capsule.magic[0] ^= 0xFF;
        assert!(matches!(
            unseal_seed(&key, &capsule),
            Err(CapsuleError::BadMagic)
        ));
    }

    /// AEAD integrity: any ciphertext bit-flip fails the Poly1305 tag.
    #[test]
    fn flipped_ciphertext_rejected() {
        let key = fake_key();
        let seed = a_seed();
        let mut capsule = seal_seed(&key, &seed, &a_key(), &mut SysRng).expect("seal");
        capsule.ciphertext[0] ^= 0xFF;
        assert!(matches!(
            unseal_seed(&key, &capsule),
            Err(CapsuleError::Decrypt)
        ));
    }

    /// AAD binding: tampering with the fingerprint changes the AAD, so
    /// decrypt fails before the explicit fingerprint cross-check runs.
    #[test]
    fn tampered_fingerprint_rejected() {
        let key = fake_key();
        let seed = a_seed();
        let mut capsule = seal_seed(&key, &seed, &a_key(), &mut SysRng).expect("seal");
        capsule.fingerprint[0] ^= 0xFF;
        assert!(matches!(
            unseal_seed(&key, &capsule),
            Err(CapsuleError::Decrypt)
        ));
    }

    /// A capsule with a wrong-length nonce is rejected before the TEE is
    /// ever asked for a sealing key.
    #[test]
    fn bad_nonce_length_rejected() {
        let key = fake_key();
        let seed = a_seed();
        let mut capsule = seal_seed(&key, &seed, &a_key(), &mut SysRng).expect("seal");
        capsule.nonce.truncate(NONCE_LEN - 1);
        assert!(matches!(
            unseal_seed(&key, &capsule),
            Err(CapsuleError::BadNonce { .. })
        ));
    }

    /// postcard round-trip: on-disk bytes decode back to the same struct.
    #[test]
    fn on_disk_serialisation_roundtrip() {
        let key = fake_key();
        let seed = a_seed();
        let capsule = seal_seed(&key, &seed, &a_key(), &mut SysRng).expect("seal");
        let bytes = serialize_capsule(&capsule).expect("serialize");
        let parsed = parse_capsule(&bytes).expect("parse");
        assert_eq!(parsed, capsule);
        let out = unseal_seed(&key, &parsed).expect("unseal");
        assert_eq!(out.seed.expose_secret(), seed.expose_secret());
        assert_eq!(out.access_code_key.expose_secret(), a_key().expose_secret());
    }

    /// AEAD integrity: any nonce bit-flip fails the Poly1305 tag.
    #[test]
    fn flipped_nonce_rejected() {
        let key = fake_key();
        let seed = a_seed();
        let mut capsule = seal_seed(&key, &seed, &a_key(), &mut SysRng).expect("seal");
        capsule.nonce[0] ^= 0x01;
        assert!(matches!(
            unseal_seed(&key, &capsule),
            Err(CapsuleError::Decrypt)
        ));
    }

    /// Documented postcard layout: magic, fingerprint, then the nonce and
    /// ciphertext length prefixes.
    #[test]
    fn postcard_layout_matches_documented_fields() {
        let key = fake_key();
        let seed = a_seed();
        let capsule = seal_seed(&key, &seed, &a_key(), &mut SysRng).expect("seal");
        let bytes = serialize_capsule(&capsule).expect("serialize");
        assert_eq!(&bytes[0..8], b"ZNS_SEED");
        assert_eq!(&bytes[8..40], &capsule.fingerprint);
        assert_eq!(bytes[40], NONCE_LEN as u8);
        assert_eq!(bytes[41 + NONCE_LEN], CIPHERTEXT_LEN as u8);
    }

    /// Decrypt succeeds, then the explicit fingerprint check fails, when the
    /// AAD fingerprint and the seed disagree.
    #[test]
    fn fingerprint_mismatch_after_decrypt_is_rejected() {
        let key = fake_key();
        let seed = a_seed();
        let other = [0xABu8; 32];
        let cipher = XChaCha20Poly1305::new_from_slice(key.expose()).expect("32-byte key");
        let nonce = [0x22u8; NONCE_LEN];
        let mut aad = Vec::with_capacity(MAGIC.len() + other.len());
        aad.extend_from_slice(&MAGIC);
        aad.extend_from_slice(&other);
        let mut payload = [0u8; PAYLOAD_LEN];
        payload[..SEED_LEN].copy_from_slice(seed.expose_secret());
        let ciphertext = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &payload,
                    aad: &aad,
                },
            )
            .expect("encrypt");
        let capsule = Capsule {
            magic: MAGIC,
            fingerprint: other,
            nonce: nonce.to_vec(),
            ciphertext,
        };
        assert!(matches!(
            unseal_seed(&key, &capsule),
            Err(CapsuleError::FingerprintMismatch)
        ));
    }
}

#[cfg(test)]
mod bounds {
    use super::*;
    use std::io::Write;

    fn envelope() -> Capsule {
        Capsule {
            magic: MAGIC,
            fingerprint: [1u8; 32],
            nonce: vec![2u8; NONCE_LEN],
            ciphertext: vec![3u8; CIPHERTEXT_LEN],
        }
    }

    #[test]
    fn a_capsule_serialises_to_the_fixed_length() {
        let bytes = serialize_capsule(&envelope()).expect("serialize");
        assert_eq!(bytes.len(), CAPSULE_LEN);
        assert_eq!(parse_capsule(&bytes).expect("parse"), envelope());
    }

    #[test]
    fn parse_rejects_the_wrong_file_length() {
        let bytes = serialize_capsule(&envelope()).expect("serialize");
        assert!(matches!(
            parse_capsule(&bytes[..bytes.len() - 1]),
            Err(CapsuleError::BadLength { .. })
        ));
        let mut long = bytes.clone();
        long.push(0);
        assert!(matches!(
            parse_capsule(&long),
            Err(CapsuleError::BadLength { .. })
        ));
    }

    #[test]
    fn parse_rejects_a_short_ciphertext_inside_a_fixed_blob() {
        let mut bytes = serialize_capsule(&envelope()).expect("serialize");
        // Ciphertext length byte sits after magic, fingerprint, and nonce.
        let len_at = MAGIC.len() + 32 + 1 + NONCE_LEN;
        bytes[len_at] = (CIPHERTEXT_LEN - 1) as u8;
        assert!(matches!(
            parse_capsule(&bytes),
            Err(CapsuleError::BadCiphertext { .. })
        ));
    }

    #[test]
    fn read_rejects_an_oversized_file() {
        let path = std::env::temp_dir().join(format!("zns-capsule-bound-{}", std::process::id()));
        let mut file = std::fs::File::create(&path).expect("temp file");
        file.write_all(&[0u8; CAPSULE_LEN + 8]).expect("write");
        drop(file);
        assert!(matches!(
            read_capsule_file(&path),
            Err(CapsuleError::BadLength {
                actual: n,
                ..
            }) if n == CAPSULE_LEN + 1
        ));
        let _ = std::fs::remove_file(&path);
    }
}
