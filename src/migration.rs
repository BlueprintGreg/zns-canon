//! Protocol binding for handing a seed from one measured guest to the next.
//!
//! M2 builds a [`MigrationOffer`] and asks the TEE for an attestation whose
//! `report_data` is [`migration_report_data`]. M1 checks that report, the
//! upgrade manifest, and only then encrypts the unsealed seed to M2's
//! ephemeral key.
//!
//! A shared secret of all zeros is rejected. That is the contributory check
//! from RFC 7748, so a low-order target key does not wrap the seed.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand::TryCryptoRng;
use secrecy::{ExposeSecret, Secret};
use thiserror::Error;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

use crate::attestation::REPORT_DATA_LEN;
use crate::capsule::{SeedAndAccessCodeKey, ACCESS_CODE_KEY_LEN, PAYLOAD_LEN, SEED_LEN};

const AEAD_NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;
const TRANSFER_CIPHERTEXT_LEN: usize = PAYLOAD_LEN + TAG_LEN;

/// Domain separation for [`migration_report_data`].
pub const MIGRATION_DOMAIN: &[u8] = b"ZNS_MIGRATION_V1";

/// Domain separation for the wrap key and its AEAD associated data.
pub const WRAP_DOMAIN: &[u8] = b"ZNS_MIGRATION_WRAP_V1";

/// `sender_ephemeral_pubkey || aead_nonce || ciphertext`.
pub const TRANSFER_LEN: usize = 32 + AEAD_NONCE_LEN + TRANSFER_CIPHERTEXT_LEN;

/// What M2 commits to before M1 will release the seed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MigrationOffer {
    pub ephemeral_pubkey: [u8; 32],
    pub nonce: [u8; 32],
    pub manifest_hash: [u8; 32],
}

/// One-time X25519 key. `secret` is wiped when this value is dropped.
pub struct EphemeralKeypair {
    pub secret: Secret<[u8; 32]>,
    pub public: [u8; 32],
}

/// Ciphertext M1 writes for the attested M2 key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EncryptedSeedTransfer {
    pub sender_ephemeral_pubkey: [u8; 32],
    pub nonce: [u8; AEAD_NONCE_LEN],
    pub ciphertext: [u8; TRANSFER_CIPHERTEXT_LEN],
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum MigrationError {
    #[error("randomness source failed")]
    Rng,

    #[error("ephemeral public key is all zeros")]
    ZeroPublicKey,

    #[error("X25519 shared secret was not contributory")]
    NonContributory,

    #[error("ephemeral secret does not match the migration offer")]
    SecretOfferMismatch,

    #[error("seed encryption failed")]
    Seal,

    #[error("seed decryption failed")]
    Decrypt,
}

/// `BLAKE2b-512(b"ZNS_MIGRATION_V1" || ephemeral_pubkey || nonce || manifest_hash)`.
///
/// Pass the result to [`crate::sealing::get_attestation`].
pub fn migration_report_data(offer: &MigrationOffer) -> [u8; REPORT_DATA_LEN] {
    let mut input = Vec::with_capacity(MIGRATION_DOMAIN.len() + 32 + 32 + 32);
    input.extend_from_slice(MIGRATION_DOMAIN);
    input.extend_from_slice(&offer.ephemeral_pubkey);
    input.extend_from_slice(&offer.nonce);
    input.extend_from_slice(&offer.manifest_hash);
    crate::blake2b::<REPORT_DATA_LEN>(&input)
}

/// Generate the M2 X25519 ephemeral keypair for one migration attempt.
pub fn generate_ephemeral_keypair<R>(rng: &mut R) -> Result<EphemeralKeypair, MigrationError>
where
    R: TryCryptoRng,
{
    let mut bytes = [0u8; 32];
    if rng.try_fill_bytes(&mut bytes).is_err() {
        bytes.zeroize();
        return Err(MigrationError::Rng);
    }
    let secret = StaticSecret::from(bytes);
    bytes.zeroize();
    let public = PublicKey::from(&secret).to_bytes();
    let mut raw = secret.to_bytes();
    let stored = Secret::new(raw);
    raw.zeroize();
    drop(secret);
    Ok(EphemeralKeypair {
        secret: stored,
        public,
    })
}

/// Encrypt the capsule payload — the seed and the access-code key — to
/// M2's ephemeral public key.
///
/// The offer nonce and manifest hash are mixed into the wrap key and the
/// AEAD associated data, so this ciphertext opens only for this offer.
pub fn encrypt_seed<R>(
    payload: &SeedAndAccessCodeKey,
    offer: &MigrationOffer,
    rng: &mut R,
) -> Result<EncryptedSeedTransfer, MigrationError>
where
    R: TryCryptoRng,
{
    if offer.ephemeral_pubkey == [0u8; 32] {
        return Err(MigrationError::ZeroPublicKey);
    }
    let mut sender_bytes = [0u8; 32];
    if rng.try_fill_bytes(&mut sender_bytes).is_err() {
        sender_bytes.zeroize();
        return Err(MigrationError::Rng);
    }
    let sender = StaticSecret::from(sender_bytes);
    sender_bytes.zeroize();
    let sender_public = PublicKey::from(&sender).to_bytes();
    if sender_public == [0u8; 32] {
        return Err(MigrationError::ZeroPublicKey);
    }
    let target_public = PublicKey::from(offer.ephemeral_pubkey);
    let shared = sender.diffie_hellman(&target_public);
    let mut shared_bytes = *shared.as_bytes();
    drop(shared);
    drop(sender);
    if shared_bytes == [0u8; 32] {
        shared_bytes.zeroize();
        return Err(MigrationError::NonContributory);
    }

    let mut aead_nonce = [0u8; AEAD_NONCE_LEN];
    if rng.try_fill_bytes(&mut aead_nonce).is_err() {
        shared_bytes.zeroize();
        return Err(MigrationError::Rng);
    }
    let aad = wrap_aad(
        &sender_public,
        &offer.ephemeral_pubkey,
        &offer.nonce,
        &offer.manifest_hash,
    );
    let ciphertext = {
        let mut key = wrap_key(
            &shared_bytes,
            &sender_public,
            &offer.ephemeral_pubkey,
            &offer.nonce,
            &offer.manifest_hash,
        );
        shared_bytes.zeroize();
        let cipher = XChaCha20Poly1305::new_from_slice(&key).expect("wrap key is 32 bytes");
        let mut payload_bytes = [0u8; PAYLOAD_LEN];
        payload_bytes[..SEED_LEN].copy_from_slice(payload.seed.expose_secret());
        payload_bytes[SEED_LEN..].copy_from_slice(payload.access_code_key.expose_secret());
        let result = cipher.encrypt(
            XNonce::from_slice(&aead_nonce),
            Payload {
                msg: &payload_bytes,
                aad: &aad,
            },
        );
        payload_bytes.zeroize();
        key.zeroize();
        result.map_err(|_| MigrationError::Seal)?
    };
    if ciphertext.len() != TRANSFER_CIPHERTEXT_LEN {
        return Err(MigrationError::Seal);
    }
    let mut out = [0u8; TRANSFER_CIPHERTEXT_LEN];
    out.copy_from_slice(&ciphertext);
    Ok(EncryptedSeedTransfer {
        sender_ephemeral_pubkey: sender_public,
        nonce: aead_nonce,
        ciphertext: out,
    })
}

/// Decrypt a seed ciphertext with M2's ephemeral secret key.
///
/// The secret must be the private key for `offer.ephemeral_pubkey`. The
/// offer nonce and manifest hash must be the ones mixed into the wrap.
pub fn decrypt_seed(
    ephemeral_secret: &Secret<[u8; 32]>,
    offer: &MigrationOffer,
    transfer: &EncryptedSeedTransfer,
) -> Result<SeedAndAccessCodeKey, MigrationError> {
    if offer.ephemeral_pubkey == [0u8; 32] || transfer.sender_ephemeral_pubkey == [0u8; 32] {
        return Err(MigrationError::ZeroPublicKey);
    }
    let secret = StaticSecret::from(*ephemeral_secret.expose_secret());
    let derived_public = PublicKey::from(&secret).to_bytes();
    if !ct_eq(&derived_public, &offer.ephemeral_pubkey) {
        return Err(MigrationError::SecretOfferMismatch);
    }
    let sender_public = PublicKey::from(transfer.sender_ephemeral_pubkey);
    let shared = secret.diffie_hellman(&sender_public);
    let mut shared_bytes = *shared.as_bytes();
    drop(shared);
    drop(secret);
    if shared_bytes == [0u8; 32] {
        shared_bytes.zeroize();
        return Err(MigrationError::NonContributory);
    }

    let aad = wrap_aad(
        &transfer.sender_ephemeral_pubkey,
        &offer.ephemeral_pubkey,
        &offer.nonce,
        &offer.manifest_hash,
    );
    let mut plaintext = {
        let mut key = wrap_key(
            &shared_bytes,
            &transfer.sender_ephemeral_pubkey,
            &offer.ephemeral_pubkey,
            &offer.nonce,
            &offer.manifest_hash,
        );
        shared_bytes.zeroize();
        let cipher = XChaCha20Poly1305::new_from_slice(&key).expect("wrap key is 32 bytes");
        let result = cipher.decrypt(
            XNonce::from_slice(&transfer.nonce),
            Payload {
                msg: &transfer.ciphertext,
                aad: &aad,
            },
        );
        key.zeroize();
        result.map_err(|_| MigrationError::Decrypt)?
    };
    if plaintext.len() != PAYLOAD_LEN {
        plaintext.zeroize();
        return Err(MigrationError::Decrypt);
    }
    let mut seed = [0u8; SEED_LEN];
    seed.copy_from_slice(&plaintext[..SEED_LEN]);
    let mut access_code_key = [0u8; ACCESS_CODE_KEY_LEN];
    access_code_key.copy_from_slice(&plaintext[SEED_LEN..]);
    plaintext.zeroize();
    let opened = SeedAndAccessCodeKey {
        seed: Secret::new(seed),
        access_code_key: Secret::new(access_code_key),
    };
    seed.zeroize();
    access_code_key.zeroize();
    Ok(opened)
}

fn wrap_key(
    shared: &[u8; 32],
    sender_public: &[u8; 32],
    target_public: &[u8; 32],
    offer_nonce: &[u8; 32],
    manifest_hash: &[u8; 32],
) -> [u8; 32] {
    let mut input = Vec::with_capacity(WRAP_DOMAIN.len() + 32 * 5);
    input.extend_from_slice(WRAP_DOMAIN);
    input.extend_from_slice(shared);
    input.extend_from_slice(sender_public);
    input.extend_from_slice(target_public);
    input.extend_from_slice(offer_nonce);
    input.extend_from_slice(manifest_hash);
    let key = crate::blake2b::<32>(&input);
    input.zeroize();
    key
}

fn wrap_aad(
    sender_public: &[u8; 32],
    target_public: &[u8; 32],
    offer_nonce: &[u8; 32],
    manifest_hash: &[u8; 32],
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(WRAP_DOMAIN.len() + 32 * 4);
    aad.extend_from_slice(WRAP_DOMAIN);
    aad.extend_from_slice(sender_public);
    aad.extend_from_slice(target_public);
    aad.extend_from_slice(offer_nonce);
    aad.extend_from_slice(manifest_hash);
    aad
}

fn ct_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut diff = 0u8;
    for (a, b) in left.iter().zip(right.iter()) {
        diff |= a ^ b;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    fn rng() -> StdRng {
        StdRng::seed_from_u64(11)
    }

    fn a_key() -> Secret<[u8; ACCESS_CODE_KEY_LEN]> {
        Secret::new([0x33; ACCESS_CODE_KEY_LEN])
    }

    fn payload() -> SeedAndAccessCodeKey {
        SeedAndAccessCodeKey {
            seed: seed(),
            access_code_key: a_key(),
        }
    }

    fn seed() -> Secret<[u8; SEED_LEN]> {
        let mut bytes = [0u8; SEED_LEN];
        for (i, byte) in bytes.iter_mut().enumerate() {
            *byte = i as u8;
        }
        Secret::new(bytes)
    }

    #[test]
    fn report_data_binds_each_offer_field() {
        let offer = MigrationOffer {
            ephemeral_pubkey: [0x44; 32],
            nonce: [0x55; 32],
            manifest_hash: [0x66; 32],
        };
        let bound = migration_report_data(&offer);

        let mut other_key = offer;
        other_key.ephemeral_pubkey[0] ^= 0x01;
        let mut other_nonce = offer;
        other_nonce.nonce[0] ^= 0x01;
        let mut other_manifest = offer;
        other_manifest.manifest_hash[0] ^= 0x01;

        assert_ne!(migration_report_data(&other_key), bound);
        assert_ne!(migration_report_data(&other_nonce), bound);
        assert_ne!(migration_report_data(&other_manifest), bound);
    }

    #[test]
    fn wrap_roundtrip_and_offer_binding() {
        let mut rng = rng();
        let keypair = generate_ephemeral_keypair(&mut rng).unwrap();
        let offer = MigrationOffer {
            ephemeral_pubkey: keypair.public,
            nonce: [0x44; 32],
            manifest_hash: [0x66; 32],
        };
        let transfer = encrypt_seed(&payload(), &offer, &mut rng).unwrap();
        let mut encoded = [0u8; TRANSFER_LEN];
        encoded[..32].copy_from_slice(&transfer.sender_ephemeral_pubkey);
        encoded[32..32 + AEAD_NONCE_LEN].copy_from_slice(&transfer.nonce);
        encoded[32 + AEAD_NONCE_LEN..].copy_from_slice(&transfer.ciphertext);
        assert!(
            !encoded
                .windows(SEED_LEN)
                .any(|window| window == seed().expose_secret()),
            "seed bytes must not appear in the transfer"
        );

        let opened = decrypt_seed(&keypair.secret, &offer, &transfer).unwrap();
        assert_eq!(opened.seed.expose_secret(), seed().expose_secret());
        assert_eq!(
            opened.access_code_key.expose_secret(),
            a_key().expose_secret()
        );

        let mut other_nonce = offer;
        other_nonce.nonce[0] ^= 1;
        assert!(matches!(
            decrypt_seed(&keypair.secret, &other_nonce, &transfer),
            Err(MigrationError::Decrypt)
        ));
        let mut other_manifest = offer;
        other_manifest.manifest_hash[0] ^= 1;
        assert!(matches!(
            decrypt_seed(&keypair.secret, &other_manifest, &transfer),
            Err(MigrationError::Decrypt)
        ));

        let mut tampered = transfer;
        tampered.ciphertext[0] ^= 1;
        assert!(matches!(
            decrypt_seed(&keypair.secret, &offer, &tampered),
            Err(MigrationError::Decrypt)
        ));

        let other = generate_ephemeral_keypair(&mut rng).unwrap();
        assert!(matches!(
            decrypt_seed(&other.secret, &offer, &transfer),
            Err(MigrationError::SecretOfferMismatch)
        ));
    }

    #[test]
    fn all_zero_target_key_is_rejected() {
        let mut rng = rng();
        let offer = MigrationOffer {
            ephemeral_pubkey: [0u8; 32],
            nonce: [1u8; 32],
            manifest_hash: [2u8; 32],
        };
        let error = encrypt_seed(&payload(), &offer, &mut rng).unwrap_err();
        assert_eq!(error, MigrationError::ZeroPublicKey);
    }

    #[test]
    fn low_order_target_key_is_not_contributory() {
        let mut rng = rng();
        // u-coordinate 1 is a low-order X25519 point.
        let mut public = [0u8; 32];
        public[0] = 1;
        let offer = MigrationOffer {
            ephemeral_pubkey: public,
            nonce: [1u8; 32],
            manifest_hash: [2u8; 32],
        };
        let error = encrypt_seed(&payload(), &offer, &mut rng).unwrap_err();
        assert_eq!(error, MigrationError::NonContributory);
    }
}
