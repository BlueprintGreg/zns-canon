//! Dev keys for regtest fixtures: the all-zero seed and the two files
//! boot reads.

use secrecy::Secret;
use std::path::Path;
use zip32::fingerprint::SeedFingerprint;

use crate::capsule::{self, CAPSULE_KEY_CONTEXT};
use crate::sealing::dev_sealing_key;

/// 32 zero bytes. Every dev key derives from it.
pub const DEV_SEED: [u8; 32] = [0u8; 32];

/// The seed's ZIP-32 fingerprint.
pub fn dev_seed_fingerprint() -> SeedFingerprint {
    SeedFingerprint::from_seed(&DEV_SEED).expect("32 bytes is a valid seed")
}

/// Writes the dev `keys/` dir: `zns_seed.capsule` + `zns_mint.conf`.
/// `birthday` is the height the ceremony anchor was mined at — pass the
/// ceremony tip, boot cross-checks it.
pub fn write_dev_keys(dir: impl AsRef<Path>, birthday: u32) -> std::io::Result<()> {
    let dir = dir.as_ref();
    std::fs::create_dir_all(dir)?;

    let key = dev_sealing_key(CAPSULE_KEY_CONTEXT);
    let sealed = capsule::seal_seed(&key, &Secret::new(DEV_SEED), &mut rand::rngs::SysRng)
        .map_err(std::io::Error::other)?;
    let blob = capsule::serialize_capsule(&sealed).expect("a fresh capsule serializes");
    std::fs::write(dir.join("zns_seed.capsule"), blob)?;

    // Three fixed lines, formatted by hand; boot parses them with `toml`.
    // Display form, not hex: boot's `FromStr` is bech32.
    let conf = format!(
        "network = \"regtest\"\n\
         expected_seed_fingerprint = \"{}\"\n\
         birthday = {birthday}\n",
        dev_seed_fingerprint(),
    );
    std::fs::write(dir.join("zns_mint.conf"), conf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;

    #[test]
    fn writes_what_boot_reads() {
        let dir = std::env::temp_dir().join(format!("zns-canon-regtest-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        write_dev_keys(&dir, 100).expect("write dev keys");

        let blob = std::fs::read(dir.join("zns_seed.capsule")).expect("capsule file");
        let capsule = capsule::parse_capsule(&blob).expect("capsule parses");
        assert_eq!(capsule.fingerprint, dev_seed_fingerprint().to_bytes());
        let seed = capsule::unseal_seed(&dev_sealing_key(CAPSULE_KEY_CONTEXT), &capsule)
            .expect("dev capsule unseals");
        assert_eq!(seed.expose_secret(), &DEV_SEED);

        // Display form on both sides, so a hex-encoded fingerprint fails here.
        let conf = std::fs::read_to_string(dir.join("zns_mint.conf")).expect("conf file");
        let expected = format!(
            "network = \"regtest\"\nexpected_seed_fingerprint = \"{}\"\nbirthday = 100\n",
            dev_seed_fingerprint()
        );
        assert_eq!(conf, expected);

        std::fs::remove_dir_all(&dir).ok();
    }
}
