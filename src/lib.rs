//! Shared ZNS custody cryptography.
//!
//! [`capsule`] seals the ZIP-32 seed. [`sealing`] is the TEE seam that
//! derives the sealing key and requests a report. [`attestation`] verifies
//! a SEV-SNP report against a pinned AMD ARK.
//!
//! [`genesis`], [`upgrade`], and [`migration`] are the canonical statements
//! for a finished ceremony and for moving that seed to a new measurement.
//! [`regtest`] writes the dev `keys/` dir for regtest fixtures.
//! Ceremony and migration orchestration stay outside this crate.

#[cfg(all(feature = "non-tee", not(debug_assertions)))]
compile_error!(
    "the non-tee feature is a development escape hatch (public sealing keys, no attestation) and must not be enabled in release/production builds"
);

pub mod access_code;
pub mod attestation;
pub mod capsule;
pub mod genesis;
pub mod migration;
#[cfg(feature = "non-tee")]
pub mod regtest;
pub mod sealing;
pub mod upgrade;

use blake2b_simd::Params as Blake2bParams;

/// BLAKE2b truncated to `N` bytes — the one hashing primitive in this
/// crate. Domain separation stays at the call sites that define layouts.
pub(crate) fn blake2b<const N: usize>(input: &[u8]) -> [u8; N] {
    let digest = Blake2bParams::new().hash_length(N).hash(input);
    let mut out = [0u8; N];
    out.copy_from_slice(digest.as_bytes());
    out
}
