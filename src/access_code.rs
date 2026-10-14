//! The access-code key: seed-derived, agreed with the issuer.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

/// Mirrors zns-keygen's `SCALAR_DOMAIN`.
pub const SCALAR_DOMAIN: &[u8] = b"ZNS/access-code/x25519/v1";

/// Mirrors zns-keygen's `ISSUER_PUBKEY`.
pub const ISSUER_PUBLIC_KEY: [u8; 32] = [
    0xfb, 0xd1, 0x2e, 0xed, 0x08, 0xb8, 0xc1, 0xe3, 0x43, 0xab, 0x4b, 0x98, 0x22, 0x82, 0x1d, 0x51,
    0x13, 0xb0, 0xe3, 0xa7, 0x11, 0x00, 0x1d, 0x81, 0xed, 0xb8, 0xd5, 0xcf, 0xa3, 0x4e, 0xab, 0x52,
];

/// The purpose-key domain shared with the mint and zns-keygen.
pub const PURPOSE: &[u8] = b"access-code-v1";

type HmacSha256 = Hmac<Sha256>;

/// The seed-derived X25519 scalar.
pub fn seed_scalar(seed: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    let mut mac = HmacSha256::new_from_slice(seed).expect("HMAC-SHA256 accepts any key length");
    mac.update(SCALAR_DOMAIN);
    let out = mac.finalize().into_bytes();
    let mut scalar = Zeroizing::new([0u8; 32]);
    scalar.copy_from_slice(&out);
    scalar
}

/// The purpose key of an issuer shared secret: `HMAC-SHA256(shared, PURPOSE)`.
pub fn purpose(shared: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    let mut mac = HmacSha256::new_from_slice(shared).expect("HMAC-SHA256 accepts any key length");
    mac.update(PURPOSE);
    let out = mac.finalize().into_bytes();
    let mut digest = Zeroizing::new([0u8; 32]);
    digest.copy_from_slice(&out);
    digest
}

/// What the mint judges codes with, straight from the seed:
/// `purpose(ECDH(seed_scalar(seed), ISSUER_PUBLIC_KEY))`.
pub fn purpose_key(seed: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    let scalar = seed_scalar(seed);
    let shared = StaticSecret::from(*scalar).diffie_hellman(&PublicKey::from(ISSUER_PUBLIC_KEY));
    assert!(
        shared.was_contributory(),
        "the issuer public key is not a contributory X25519 point"
    );
    purpose(&shared.to_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// zns-keygen pins these vectors; a mismatch means the repos diverged.
    #[test]
    fn scalar_and_public_match_keygens_vectors() {
        let seed = [0x11u8; 32];
        let scalar = seed_scalar(&seed);
        assert_eq!(
            *scalar,
            [
                0xcf, 0x57, 0x84, 0xab, 0xd3, 0x8e, 0x10, 0xd8, 0xde, 0x32, 0xaa, 0x90, 0x52, 0x5d,
                0x15, 0xf4, 0xf5, 0x53, 0x84, 0xdf, 0xa5, 0xe1, 0x07, 0xe3, 0xf1, 0xcc, 0x26, 0x5f,
                0xc3, 0x72, 0x50, 0x9e,
            ]
        );
        let public = PublicKey::from(&StaticSecret::from(*scalar));
        assert_eq!(
            public.to_bytes(),
            [
                0x2a, 0x65, 0x82, 0xc9, 0x96, 0x4d, 0x89, 0x08, 0xf1, 0x55, 0x74, 0x12, 0xe8, 0xb8,
                0xed, 0xd2, 0x7e, 0x94, 0xd2, 0x51, 0x26, 0xf2, 0x35, 0xc8, 0x4f, 0xbf, 0x01, 0xb1,
                0xa8, 0x87, 0x94, 0x25,
            ]
        );
    }

    #[test]
    fn purpose_matches_the_mint_vector() {
        let shared: [u8; 32] = core::array::from_fn(|i| i as u8);
        assert_eq!(
            *purpose(&shared),
            [
                0x5e, 0x2d, 0xb6, 0x04, 0x0c, 0xd3, 0x2d, 0x24, 0x86, 0x67, 0x5a, 0x3b, 0x3d, 0x60,
                0xb9, 0xd4, 0xd9, 0x6e, 0x9c, 0x8d, 0x4a, 0x5f, 0x86, 0x2e, 0x0d, 0xfd, 0x7b, 0xd6,
                0xa3, 0xf5, 0x7b, 0x91,
            ]
        );
    }
}
