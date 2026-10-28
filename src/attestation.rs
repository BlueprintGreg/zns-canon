//! SEV-SNP attestation: request, parse, and self-verify.
//!
//! This module isolates all interaction with the AMD PSP (Platform Security
//! Processor) into one place so that the genesis ceremony stays a linear
//! script and the attestation logic is independently testable and auditable.
//!
//! Flow:
//!   1. `capsule::hash()` — BLAKE2b-256 of the capsule's on-disk bytes.
//!   2. `request()` — compute the 64-byte `report_data` that binds the
//!      attestation to this specific capsule (BLAKE2b-512 of
//!      fingerprint ‖ capsule hash), then call the PSP via `/dev/sev-guest`
//!      for a normal SNP report. That report is the VCEK-signed evidence.
//!   3. Fetch the public VCEK and ASK from AMD's Key Distribution Service.
//!      The ARK in that response is not the trust anchor.
//!   4. `verify_vcek_report()` — require the VCEK to name the report chip
//!      and reported TCB, the ASK to chain to a pinned AMD
//!      ARK, and the VCEK signature to cover the report.
//!      `Attestation::verify_report_data()` then checks `report_data` and
//!      that the measurement is not zero. Both run before the attestation
//!      report is written to disk. `verify()` and `stored()` check the
//!      signature again before a report already on disk is used, and return
//!      an error instead of panicking. The VCEK and the product cert chain
//!      are saved under `/state/kds` after they pass those checks. A later
//!      report for the same chip and reported TCB reuses them and does not
//!      call AMD KDS.

use sev::certs::snp::ca::Chain as CaChain;
use sev::certs::snp::{builtin, Certificate, Chain, Verifiable};
use sev::firmware::guest::AttestationReport;
#[cfg(target_os = "linux")]
use sev::firmware::guest::Firmware;
use sev::firmware::host::TcbVersion;
use sev::parser::ByteParser;
use sev::Generation;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use thiserror::Error;

use zip32::fingerprint::SeedFingerprint;

const FINGERPRINT_LEN: usize = 32;

/// Length of the SEV-SNP `report_data` field, and of the BLAKE2b-512 digest
/// this module writes there.
pub const REPORT_DATA_LEN: usize = 64;

/// A stored attestation report failed verification.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum AttestationError {
    #[error("parse SEV-SNP attestation report: {0}")]
    Parse(String),

    #[error("{0}")]
    Endorsement(String),

    #[error("{0}")]
    Signature(String),

    #[error("attestation report_data mismatch")]
    ReportData,

    #[error("attestation measurement is all zeros")]
    ZeroMeasurement,

    #[error("attestation guest policy is {0:#x}")]
    LaunchPolicy(u64),

    #[error("attestation reported SNP TCB {snp:#x} is below the {product} minimum {minimum:#x}")]
    LowTcb {
        product: String,
        snp: u8,
        minimum: u8,
    },

    #[error("SEV-SNP attestation verification requires a Linux SNP guest")]
    Unavailable,
}

/// This guest launches at `0x30000`: SMT is allowed, and debug and a migration
/// agent are not. The host cannot read guest memory. A capsule sealed under
/// this policy does not open under another one.
pub const LAUNCH_POLICY: u64 = 0x30000;

/// Minimum `reported_tcb.snp` from AMD-SB-3034 ("TCB Value for SEV Attestation").
/// Siena uses the Genoa value. The bulletin does not publish a floor for the
/// other TCB components.
fn min_reported_snp(product: &str) -> Result<u8, String> {
    match product {
        "Milan" => Ok(0x1D),
        "Genoa" => Ok(0x1C),
        "Turin" => Ok(0x05),
        other => Err(format!("no SNP TCB floor for {other}")),
    }
}

/// Parsed attestation report with the fields zns-keygen needs.
///
/// `report_bytes` is the raw 1184-byte report exactly as the PSP signed it.
/// The other fields are extracted from the parsed report for convenience
/// and for the custody manifest.
pub struct Attestation {
    /// Raw attestation report bytes (signed by the PSP, written to disk as-is).
    pub report_bytes: Vec<u8>,
    /// VM launch measurement. Commits to the measured guest launch state
    /// (48 bytes, hex in manifest). It is not itself a hash of the `zns-keygen` binary.
    pub measurement: [u8; 48],
    /// Guest policy value (u64, hex in manifest).
    pub guest_policy: u64,
    /// Platform TCB at report time (components formatted for the manifest).
    pub tcb_version: String,
    /// The report_data we supplied (kept for the sanity check).
    ///
    /// Unused on non-Linux, where `request` refuses to run.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub report_data: [u8; REPORT_DATA_LEN],
}

impl Attestation {
    /// Check that the report embeds the `report_data` we requested and that
    /// the launch measurement is not all zeros.
    ///
    /// This is not the AMD signature check. Call `verify_vcek_report` for that.
    ///
    /// Called only on Linux, where a real PSP report is available.
    /// [`request`] still treats a failure here as fatal. [`stored`] returns it.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub fn verify_report_data(&self) -> Result<(), AttestationError> {
        let report = AttestationReport::from_bytes(&self.report_bytes)
            .map_err(|error| AttestationError::Parse(error.to_string()))?;
        if report.report_data != self.report_data {
            return Err(AttestationError::ReportData);
        }
        if report.measurement.iter().all(|byte| *byte == 0) {
            return Err(AttestationError::ZeroMeasurement);
        }
        Ok(())
    }
}

/// The capsule attestation layout:
/// `report_data = BLAKE2b-512(seed_fingerprint ‖ BLAKE2b-256(capsule_bytes))`.
/// Binding the report to this pair is what stops one ceremony's attestation
/// being reused for a different capsule.
fn report_data(fingerprint: &SeedFingerprint, capsule_hash: &[u8; 32]) -> [u8; REPORT_DATA_LEN] {
    let mut input = Vec::with_capacity(FINGERPRINT_LEN + 32);
    input.extend_from_slice(&fingerprint.to_bytes());
    input.extend_from_slice(capsule_hash);

    crate::blake2b(&input)
}

/// Request a SEV-SNP attestation binding this capsule to this seed
/// fingerprint. Callers pass the capsule's on-disk bytes; the report layout
/// is computed here.
pub fn request(capsule_bytes: &[u8], expected_fingerprint: &SeedFingerprint) -> Attestation {
    request_report_data(&report_data(
        expected_fingerprint,
        &crate::capsule::hash(capsule_bytes),
    ))
}

/// Ask the PSP for a report and verify it end-to-end: launch policy, reported
/// SNP TCB, VCEK signature, pinned ARK chain, requested `report_data`,
/// non-zero measurement.
fn request_report_data(requested_report_data: &[u8; REPORT_DATA_LEN]) -> Attestation {
    #[cfg(not(target_os = "linux"))]
    {
        // No counterfeit attestations: off the enclave there is no
        // attestation, dev mode included.
        let _ = requested_report_data;
        panic!("FATAL: SEV-SNP attestation requires a Linux SNP guest");
    }
    #[cfg(target_os = "linux")]
    {
        let mut firmware = Firmware::open().expect("FATAL: open /dev/sev-guest");
        let report_bytes = firmware
            .get_report(None, Some(*requested_report_data), None)
            .expect("FATAL: request SEV-SNP attestation report");
        let report = AttestationReport::from_bytes(&report_bytes)
            .expect("FATAL: parse SEV-SNP attestation report");
        require_launch(&report).unwrap_or_else(|error| panic!("FATAL: {error}"));
        let (ask, vcek) =
            fetch_endorsement(&report).unwrap_or_else(|error| panic!("FATAL: {error}"));
        verify_vcek_report(&report, &ask, &vcek)
            .expect("FATAL: attestation signature verification");

        let attestation = attestation_from_report(report_bytes, &report, *requested_report_data);
        attestation
            .verify_report_data()
            .unwrap_or_else(|error| panic!("FATAL: {error}"));
        attestation
    }
}

/// Verify a stored report against the capsule it claims to attest: the
/// report must embed the capsule layout's `report_data`, carry a valid VCEK
/// signature, and chain to a pinned AMD ARK. Delegates to [`stored`].
pub fn verify(
    capsule_bytes: &[u8],
    expected_fingerprint: &SeedFingerprint,
    report_bytes: Vec<u8>,
) -> Result<Attestation, AttestationError> {
    stored(
        report_bytes,
        &report_data(expected_fingerprint, &crate::capsule::hash(capsule_bytes)),
    )
}

/// Verify a stored report whose expected `report_data` the caller composed.
///
/// Capsule attestations should use [`verify`], which derives the expected
/// `report_data` itself. This is the general form for callers whose report
/// layout is their own (migration hand-off flows).
///
/// The VCEK and the product cert chain are cached under `/state/kds` after
/// they pass the signature checks. The report is still checked on every call.
pub fn stored(
    report_bytes: Vec<u8>,
    expected_report_data: &[u8; REPORT_DATA_LEN],
) -> Result<Attestation, AttestationError> {
    #[cfg(target_os = "linux")]
    {
        let report = AttestationReport::from_bytes(&report_bytes)
            .map_err(|error| AttestationError::Parse(error.to_string()))?;
        require_launch(&report)?;
        let (ask, vcek) = fetch_endorsement(&report).map_err(AttestationError::Endorsement)?;
        verify_vcek_report(&report, &ask, &vcek).map_err(AttestationError::Signature)?;
        let attestation = attestation_from_report(report_bytes, &report, *expected_report_data);
        attestation.verify_report_data()?;
        Ok(attestation)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = report_bytes;
        let _ = expected_report_data;
        Err(AttestationError::Unavailable)
    }
}

#[cfg(target_os = "linux")]
fn attestation_from_report(
    report_bytes: Vec<u8>,
    report: &AttestationReport,
    report_data: [u8; REPORT_DATA_LEN],
) -> Attestation {
    let tcb = report.current_tcb;
    Attestation {
        report_bytes,
        measurement: report.measurement,
        guest_policy: report.policy.into(),
        tcb_version: format!(
            "bootloader={} tee={} snp={} microcode={}",
            tcb.bootloader, tcb.tee, tcb.snp, tcb.microcode
        ),
        report_data,
    }
}

/// Verify that `report` was signed by `vcek`, and that `ask` chains to a pinned AMD ARK.
///
/// `ask` and `vcek` are public certificates obtained from AMD KDS. The ARK
/// served beside the ASK is not trusted by itself: the ASK must verify under
/// the Milan, Genoa, or Turin ARK built into the `sev` crate.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub fn verify_vcek_report(
    report: &AttestationReport,
    ask: &Certificate,
    vcek: &Certificate,
) -> Result<(), String> {
    vcek_signing_key(report)?;
    vcek_matches_report(report, vcek)?;
    let chain = chain_under_pinned_ark(ask.clone(), vcek.clone())?;
    (&chain, report)
        .verify()
        .map_err(|e| format!("VCEK signature verification failed: {e}"))?;
    Ok(())
}

/// Refuse a debug launch and firmware below the pinned SNP TCB.
///
/// Called from [`request`] and [`stored`] after the report parses and before
/// AMD is contacted. Signature verification follows when these admission checks succeed.
pub fn require_launch(report: &AttestationReport) -> Result<(), AttestationError> {
    let policy = u64::from(report.policy);
    if policy != LAUNCH_POLICY {
        return Err(AttestationError::LaunchPolicy(policy));
    }
    let product = kds_product(report).map_err(AttestationError::Endorsement)?;
    let minimum = min_reported_snp(product).map_err(AttestationError::Endorsement)?;
    if report.reported_tcb.snp < minimum {
        return Err(AttestationError::LowTcb {
            product: product.to_string(),
            snp: report.reported_tcb.snp,
            minimum,
        });
    }
    Ok(())
}

fn vcek_signing_key(report: &AttestationReport) -> Result<(), String> {
    if report.key_info.mask_chip_key() {
        return Err("attestation report signature is masked".into());
    }
    if report.key_info.signing_key() != 0 {
        return Err("attestation report was not signed by the VCEK".into());
    }
    if report.chip_id.iter().all(|byte| *byte == 0) {
        return Err("attestation report chip id is zero".into());
    }
    Ok(())
}

/// AMD VCEK certificate extensions (VCEK certificate specification, chapter 3).
const OID_BL_SPL: &str = "1.3.6.1.4.1.3704.1.3.1";
const OID_TEE_SPL: &str = "1.3.6.1.4.1.3704.1.3.2";
const OID_SNP_SPL: &str = "1.3.6.1.4.1.3704.1.3.3";
const OID_UCODE_SPL: &str = "1.3.6.1.4.1.3704.1.3.8";
const OID_FMC_SPL: &str = "1.3.6.1.4.1.3704.1.3.9";
const OID_HW_ID: &str = "1.3.6.1.4.1.3704.1.4";

/// Require the VCEK to be the one AMD issued for this report's chip and
/// reported TCB.
///
/// The signature check alone does not show this: any genuine VCEK verifies
/// a report its own key signed. A VCEK can come from the `/state/kds` cache,
/// which the host can write, so a cached certificate for an older TCB would
/// otherwise stand in for the TCB the report claims.
fn vcek_matches_report(report: &AttestationReport, vcek: &Certificate) -> Result<(), String> {
    let cert = x509_cert::Certificate::from(vcek.clone());
    let extensions = cert.tbs_certificate.extensions.unwrap_or_default();
    let extension = |oid: &str| {
        extensions
            .iter()
            .find(|ext| ext.extn_id.to_string() == oid)
            .map(|ext| ext.extn_value.as_bytes())
    };

    let tcb = &report.reported_tcb;
    let spls = [
        ("blSPL", OID_BL_SPL, Some(tcb.bootloader)),
        ("teeSPL", OID_TEE_SPL, Some(tcb.tee)),
        ("snpSPL", OID_SNP_SPL, Some(tcb.snp)),
        ("ucodeSPL", OID_UCODE_SPL, Some(tcb.microcode)),
        ("fmcSPL", OID_FMC_SPL, tcb.fmc),
    ];
    for (name, oid, reported) in spls {
        let certified = extension(oid).map(spl_value).transpose()?;
        if certified != reported {
            return Err(format!(
                "VCEK {name} {certified:?} does not match the reported TCB {reported:?}"
            ));
        }
    }

    let hw_id = extension(OID_HW_ID).ok_or("VCEK has no hwID extension")?;
    if !hw_id_encodings(hw_id).any(|id| names_chip(id, &report.chip_id)) {
        return Err("VCEK hwID does not match the report chip id".into());
    }
    Ok(())
}

/// The hwID extension: a DER OCTET STRING, or the raw bytes in older VCEKs.
///
/// A raw id can also parse as DER, so a leading `0x04` does not decide the
/// encoding. Both readings are offered, and the caller keeps the one that
/// names the report's chip.
fn hw_id_encodings(bytes: &[u8]) -> impl Iterator<Item = &[u8]> {
    use x509_cert::der::asn1::OctetStringRef;
    use x509_cert::der::Decode;
    let der = OctetStringRef::from_der(bytes)
        .ok()
        .map(|octets| octets.as_bytes());
    der.into_iter().chain(std::iter::once(bytes))
}

/// A shorter hwID names the leading bytes of the chip id; the rest of the
/// reported id must then be zero.
fn names_chip(hw_id: &[u8], chip_id: &[u8; 64]) -> bool {
    chip_id
        .split_at_checked(hw_id.len())
        .is_some_and(|(named, rest)| named == hw_id && rest.iter().all(|byte| *byte == 0))
}

/// An SPL extension: a DER INTEGER that fits in one byte.
fn spl_value(bytes: &[u8]) -> Result<u8, String> {
    use x509_cert::der::Decode;
    u8::from_der(bytes).map_err(|error| format!("VCEK SPL extension: {error}"))
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn chain_under_pinned_ark(ask: Certificate, vcek: Certificate) -> Result<Chain, String> {
    let roots = [
        builtin::milan::ark(),
        builtin::genoa::ark(),
        builtin::turin::ark(),
    ];
    for root in roots {
        let ark = root.map_err(|e| format!("pinned AMD ARK: {e}"))?;
        let chain = Chain {
            ca: CaChain {
                ark,
                ask: ask.clone(),
            },
            vek: vcek.clone(),
        };
        if chain.verify().is_ok() {
            return Ok(chain);
        }
    }
    Err("ASK is not signed by a pinned AMD ARK (Milan, Genoa, or Turin)".into())
}

const KDS_ORIGIN: &str = "https://kdsintf.amd.com/vcek/v1";

/// Guest state disk. Mint, keygen, and migrate all verify through `stored`
/// and would otherwise download the same VCEK until AMD answers 429.
const KDS_CACHE_DIR: &str = "/state/kds";

/// AMD KDS product name for the CPUID family and model in an SNP report.
///
/// Siena and Bergamo use the Genoa key hierarchy. Venice has no pinned ARK here.
fn kds_product_name(family: u8, model: u8) -> Result<&'static str, String> {
    match Generation::try_from((family, model)) {
        Ok(Generation::Milan) => Ok("Milan"),
        Ok(Generation::Genoa) => Ok("Genoa"),
        Ok(Generation::Turin) => Ok("Turin"),
        Ok(generation) => Err(format!("no pinned AMD ARK for {}", generation.titlecase())),
        Err(error) => Err(format!(
            "attestation CPU family {family:#x} model {model:#x}: {error}"
        )),
    }
}

fn kds_product(report: &AttestationReport) -> Result<&'static str, String> {
    let family = report
        .cpuid_fam_id
        .ok_or("attestation report has no CPU family")?;
    let model = report
        .cpuid_mod_id
        .ok_or("attestation report has no CPU model")?;
    kds_product_name(family, model)
}

/// VCEK URL for the reported TCB. That is the TCB the VCEK was derived from.
fn vcek_url(product: &str, chip_id: &[u8; 64], tcb: &TcbVersion) -> String {
    let mut url = format!(
        "{KDS_ORIGIN}/{product}/{}?blSPL={}&teeSPL={}&snpSPL={}&ucodeSPL={}",
        hex::encode(chip_id),
        tcb.bootloader,
        tcb.tee,
        tcb.snp,
        tcb.microcode
    );
    if let Some(fmc) = tcb.fmc {
        url.push_str(&format!("&fmcSPL={fmc}"));
    }
    url
}

fn cert_chain_url(product: &str) -> String {
    format!("{KDS_ORIGIN}/{product}/cert_chain")
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn fetch_endorsement(report: &AttestationReport) -> Result<(Certificate, Certificate), String> {
    fetch_endorsement_cached(report, Path::new(KDS_CACHE_DIR), https_get)
}

/// Load a cached VCEK and cert chain, or download them.
///
/// A hit still runs `ask_from_kds_chain` and `verify_vcek_report` against this
/// report. Saved bytes that fail those checks are ignored and downloaded.
/// Files are written only after the checks succeed. A missing directory or a
/// failed write leaves a successful verification in place.
fn fetch_endorsement_cached(
    report: &AttestationReport,
    cache_dir: &Path,
    get: impl Fn(&str) -> Result<Vec<u8>, String>,
) -> Result<(Certificate, Certificate), String> {
    vcek_signing_key(report)?;
    let product = kds_product(report)?;
    let vcek_path = vcek_cache_path(cache_dir, product, &report.chip_id, &report.reported_tcb);
    let chain_path = chain_cache_path(cache_dir, product);

    if let (Ok(vcek_bytes), Ok(chain_bytes)) =
        (std::fs::read(&vcek_path), std::fs::read(&chain_path))
    {
        match endorsement_from_bytes(report, &vcek_bytes, &chain_bytes) {
            Ok(endorsement) => {
                tracing::info!(product, "using cached AMD KDS certificates");
                return Ok(endorsement);
            }
            Err(error) => {
                tracing::info!(%error, "cached AMD KDS certificates were rejected");
            }
        }
    }

    tracing::info!(product, "fetching VCEK and ASK from AMD KDS");
    let vcek_bytes = get(&vcek_url(product, &report.chip_id, &report.reported_tcb))?;
    let chain_bytes = get(&cert_chain_url(product))?;
    let endorsement = endorsement_from_bytes(report, &vcek_bytes, &chain_bytes)?;
    write_kds_cache(&vcek_path, &vcek_bytes, &chain_path, &chain_bytes);
    Ok(endorsement)
}

fn endorsement_from_bytes(
    report: &AttestationReport,
    vcek_bytes: &[u8],
    chain_bytes: &[u8],
) -> Result<(Certificate, Certificate), String> {
    let vcek = Certificate::from_der(vcek_bytes)
        .or_else(|_| Certificate::from_pem(vcek_bytes))
        .map_err(|error| format!("AMD KDS VCEK: {error}"))?;
    let chain_certs = pem_certificates(chain_bytes)?;
    let ask = ask_from_kds_chain(&chain_certs, &vcek)?;
    verify_vcek_report(report, &ask, &vcek)?;
    Ok((ask, vcek))
}

/// VCEK file name: product, chip id, and the reported TCB fields in `vcek_url`.
fn vcek_cache_path(
    cache_dir: &Path,
    product: &str,
    chip_id: &[u8; 64],
    tcb: &TcbVersion,
) -> PathBuf {
    let mut name = format!(
        "{product}-{}-bl{}-tee{}-snp{}-ucode{}",
        hex::encode(chip_id),
        tcb.bootloader,
        tcb.tee,
        tcb.snp,
        tcb.microcode
    );
    if let Some(fmc) = tcb.fmc {
        name.push_str(&format!("-fmc{fmc}"));
    }
    name.push_str(".vcek");
    cache_dir.join(name)
}

fn chain_cache_path(cache_dir: &Path, product: &str) -> PathBuf {
    cache_dir.join(format!("{product}-cert_chain.pem"))
}

/// Create `/state/kds` if needed. A failure here does not undo a verification
/// that already holds good certificates.
///
/// Each file is written to a temporary name in the same directory, flushed,
/// and renamed over the destination. A crash or a concurrent reader never
/// sees a truncated VCEK or cert chain.
fn write_kds_cache(vcek_path: &Path, vcek_bytes: &[u8], chain_path: &Path, chain_bytes: &[u8]) {
    if let Some(cache_dir) = vcek_path.parent() {
        if let Err(error) = std::fs::create_dir_all(cache_dir) {
            tracing::warn!(%error, "AMD KDS cache directory was not created");
            return;
        }
    }
    if let Err(error) = replace_cache_file(vcek_path, vcek_bytes) {
        tracing::warn!(%error, "AMD KDS VCEK was not cached");
    }
    if let Err(error) = replace_cache_file(chain_path, chain_bytes) {
        tracing::warn!(%error, "AMD KDS cert chain was not cached");
    }
}

fn replace_cache_file(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let tmp = cache_temp_path(path).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "AMD KDS cache path has no file name",
        )
    })?;
    if let Err(error) = write_cache_temp(&tmp, bytes) {
        let _ = std::fs::remove_file(&tmp);
        return Err(error);
    }
    if let Err(error) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(error);
    }
    Ok(())
}

fn write_cache_temp(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut file = std::fs::File::create(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn cache_temp_path(dest: &Path) -> Option<PathBuf> {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let dir = dest.parent()?;
    let name = dest.file_name()?.to_string_lossy();
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    Some(dir.join(format!(".{name}.{}.{seq}.tmp", std::process::id())))
}

/// The cert-chain bundle holds the ASK and the KDS ARK. Return the ASK that
/// chains to a pinned ARK and signs this VCEK.
fn ask_from_kds_chain(
    chain_certs: &[Certificate],
    vcek: &Certificate,
) -> Result<Certificate, String> {
    let mut chain_error = String::from("AMD KDS cert chain contained no ASK");
    for ask in chain_certs {
        match chain_under_pinned_ark(ask.clone(), vcek.clone()) {
            Ok(_) => return Ok(ask.clone()),
            Err(error) => chain_error = error,
        }
    }
    Err(chain_error)
}

fn pem_certificates(bundle: &[u8]) -> Result<Vec<Certificate>, String> {
    let text =
        std::str::from_utf8(bundle).map_err(|_| "AMD KDS cert chain is not UTF-8".to_string())?;
    let mut certificates = Vec::new();
    for block in text.split("-----END CERTIFICATE-----") {
        let Some(start) = block.find("-----BEGIN CERTIFICATE-----") else {
            continue;
        };
        let pem = format!("{}-----END CERTIFICATE-----\n", &block[start..]);
        let certificate = Certificate::from_pem(pem.as_bytes())
            .map_err(|error| format!("AMD KDS certificate: {error}"))?;
        certificates.push(certificate);
    }
    if certificates.is_empty() {
        return Err("AMD KDS cert chain contained no certificates".into());
    }
    Ok(certificates)
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn https_get(url: &str) -> Result<Vec<u8>, String> {
    let response = ureq::get(url)
        .timeout(std::time::Duration::from_secs(30))
        .call()
        .map_err(|error| format!("AMD KDS request failed: {error}"))?;
    let mut body = Vec::new();
    response
        .into_reader()
        .take(1024 * 1024)
        .read_to_end(&mut body)
        .map_err(|error| format!("AMD KDS response: {error}"))?;
    if body.is_empty() {
        return Err("AMD KDS response was empty".into());
    }
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    const MILAN_VCEK_DER: &[u8] = include_bytes!("testdata/vcek_milan.der");
    const MILAN_REPORT_HEX: &[u8] = include_bytes!("testdata/report_milan.hex");

    fn milan_report() -> AttestationReport {
        let bytes = hex::decode(MILAN_REPORT_HEX).unwrap();
        AttestationReport::from_bytes(&bytes).unwrap()
    }

    fn milan_ask_and_vcek() -> (Certificate, Certificate) {
        let ask = builtin::milan::ask().unwrap();
        let vcek = Certificate::from_der(MILAN_VCEK_DER).unwrap();
        (ask, vcek)
    }

    #[test]
    fn milan_vcek_report_verifies() {
        let (ask, vcek) = milan_ask_and_vcek();
        verify_vcek_report(&milan_report(), &ask, &vcek).unwrap();
    }

    #[test]
    fn the_milan_vcek_names_its_reports_chip_and_tcb() {
        let (_, vcek) = milan_ask_and_vcek();
        vcek_matches_report(&milan_report(), &vcek).unwrap();
    }

    #[test]
    fn a_vcek_for_another_tcb_is_rejected() {
        let (ask, vcek) = milan_ask_and_vcek();
        type Mutation = (&'static str, fn(&mut TcbVersion));
        let mutations: [Mutation; 5] = [
            ("blSPL", |tcb| {
                tcb.bootloader = tcb.bootloader.wrapping_add(1)
            }),
            ("teeSPL", |tcb| tcb.tee = tcb.tee.wrapping_add(1)),
            ("snpSPL", |tcb| tcb.snp = tcb.snp.wrapping_add(1)),
            ("ucodeSPL", |tcb| {
                tcb.microcode = tcb.microcode.wrapping_add(1)
            }),
            ("fmcSPL", |tcb| tcb.fmc = Some(1)),
        ];
        for (name, mutate) in mutations {
            let mut report = milan_report();
            mutate(&mut report.reported_tcb);
            let error = verify_vcek_report(&report, &ask, &vcek).unwrap_err();
            assert!(error.contains(name), "{name}: {error}");
        }
    }

    #[test]
    fn a_vcek_for_another_chip_is_rejected() {
        let (ask, vcek) = milan_ask_and_vcek();
        let mut report = milan_report();
        report.chip_id[0] ^= 0x01;
        let error = verify_vcek_report(&report, &ask, &vcek).unwrap_err();
        assert!(error.contains("hwID"), "{error}");
    }

    /// A raw hwID can also parse as a DER OCTET STRING. `04 3e` followed by
    /// 62 bytes is both a raw 64-byte id and a valid 62-byte DER value, so
    /// the leading `0x04` must not pick the encoding.
    #[test]
    fn a_raw_hw_id_that_also_parses_as_der_still_names_its_chip() {
        let mut chip_id = [0u8; 64];
        chip_id[0] = 0x04;
        chip_id[1] = 0x3e;
        for (i, byte) in chip_id[2..].iter_mut().enumerate() {
            *byte = i as u8 + 1;
        }
        assert!(hw_id_encodings(&chip_id).any(|id| names_chip(id, &chip_id)));

        let mut der = vec![0x04, 0x40];
        der.extend_from_slice(&chip_id);
        assert!(hw_id_encodings(&der).any(|id| names_chip(id, &chip_id)));

        let mut other = chip_id;
        other[63] ^= 0x01;
        assert!(!hw_id_encodings(&chip_id).any(|id| names_chip(id, &other)));
        assert!(!hw_id_encodings(&der).any(|id| names_chip(id, &other)));
    }

    /// The cache file name is not evidence. A genuine VCEK saved under the
    /// name of another TCB is refused, from the cache and from KDS alike.
    #[test]
    fn a_cached_vcek_saved_under_another_tcb_is_refused() {
        let dir = temp_kds_dir("planted");
        std::fs::create_dir_all(&dir).unwrap();
        let mut claimed = milan_report_for_kds();
        claimed.reported_tcb.snp = claimed.reported_tcb.snp.wrapping_add(1);
        let vcek_path = vcek_cache_path(&dir, "Milan", &claimed.chip_id, &claimed.reported_tcb);
        std::fs::write(&vcek_path, MILAN_VCEK_DER).unwrap();
        std::fs::write(chain_cache_path(&dir, "Milan"), milan_kds_chain()).unwrap();

        let probe = KdsProbe::new();
        let error = fetch_endorsement_cached(&claimed, &dir, |url| probe.get(url)).unwrap_err();
        assert!(error.contains("snpSPL"), "{error}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn modified_report_fails_vcek_signature() {
        let (ask, vcek) = milan_ask_and_vcek();
        let mut bytes = hex::decode(MILAN_REPORT_HEX).unwrap();
        bytes[21] ^= 0x80;
        let report = AttestationReport::from_bytes(&bytes).unwrap();
        assert!(verify_vcek_report(&report, &ask, &vcek).is_err());
    }

    #[test]
    fn vlek_signing_key_is_rejected() {
        let (ask, vcek) = milan_ask_and_vcek();
        let mut report = milan_report();
        report.key_info = sev::firmware::guest::KeyInfo::from(1 << 2);
        let error = verify_vcek_report(&report, &ask, &vcek).unwrap_err();
        assert!(error.contains("VCEK"), "{error}");
    }

    #[test]
    fn masked_signature_is_rejected() {
        let (ask, vcek) = milan_ask_and_vcek();
        let mut report = milan_report();
        report.key_info = sev::firmware::guest::KeyInfo::from(1 << 1);
        let error = verify_vcek_report(&report, &ask, &vcek).unwrap_err();
        assert!(error.contains("masked"), "{error}");
    }

    #[test]
    fn ask_from_another_generation_is_rejected() {
        let vcek = Certificate::from_der(MILAN_VCEK_DER).unwrap();
        let ask = builtin::turin::ask().unwrap();
        assert!(verify_vcek_report(&milan_report(), &ask, &vcek).is_err());
    }

    #[test]
    fn kds_chain_selects_the_ask_when_the_ark_comes_first() {
        let (ask, vcek) = milan_ask_and_vcek();
        let ark = builtin::milan::ark().unwrap();
        let bundle = [ark.to_pem().unwrap(), ask.to_pem().unwrap()].concat();
        let certificates = pem_certificates(&bundle).unwrap();
        assert_eq!(certificates.len(), 2);
        let selected = ask_from_kds_chain(&certificates, &vcek).unwrap();
        verify_vcek_report(&milan_report(), &selected, &vcek).unwrap();
    }

    #[test]
    fn kds_product_names_match_the_pinned_roots() {
        assert_eq!(kds_product_name(0x19, 0x01).unwrap(), "Milan");
        assert_eq!(kds_product_name(0x19, 0x11).unwrap(), "Genoa");
        // EPYC 8024P (Siena) is in the Genoa key hierarchy.
        assert_eq!(kds_product_name(0x19, 0xA0).unwrap(), "Genoa");
        assert_eq!(kds_product_name(0x1A, 0x00).unwrap(), "Turin");
        assert!(kds_product_name(0x1A, 0x50).is_err());
    }

    #[test]
    fn stored_rejects_bytes_that_are_not_a_report() {
        let Err(error) = stored(b"not-a-report".to_vec(), &[0; REPORT_DATA_LEN]) else {
            panic!("stored accepted bytes that are not a report");
        };
        #[cfg(target_os = "linux")]
        assert!(matches!(error, AttestationError::Parse(_)), "{error}");
        #[cfg(not(target_os = "linux"))]
        assert_eq!(error, AttestationError::Unavailable);
    }

    #[test]
    fn report_data_mismatch_is_an_error() {
        let bytes = hex::decode(MILAN_REPORT_HEX).unwrap();
        let report = AttestationReport::from_bytes(&bytes).unwrap();
        let attestation = Attestation {
            report_bytes: bytes,
            measurement: report.measurement,
            guest_policy: report.policy.into(),
            tcb_version: String::new(),
            report_data: [0; REPORT_DATA_LEN],
        };
        assert_eq!(
            attestation.verify_report_data().unwrap_err(),
            AttestationError::ReportData
        );
    }

    #[test]
    fn zero_measurement_is_an_error() {
        // SNP ABI: report_data is 64 bytes at 0x50, measurement is 48 bytes at 0x90.
        const MEASUREMENT_OFFSET: usize = 0x90;
        const MEASUREMENT_LEN: usize = 48;
        let mut bytes = hex::decode(MILAN_REPORT_HEX).unwrap();
        let report = AttestationReport::from_bytes(&bytes).unwrap();
        assert_eq!(
            &bytes[MEASUREMENT_OFFSET..MEASUREMENT_OFFSET + MEASUREMENT_LEN],
            &report.measurement
        );
        assert!(report.measurement.iter().any(|byte| *byte != 0));
        bytes[MEASUREMENT_OFFSET..MEASUREMENT_OFFSET + MEASUREMENT_LEN].fill(0);
        let report = AttestationReport::from_bytes(&bytes).unwrap();
        let attestation = Attestation {
            report_bytes: bytes,
            measurement: report.measurement,
            guest_policy: report.policy.into(),
            tcb_version: String::new(),
            report_data: report.report_data,
        };
        assert_eq!(
            attestation.verify_report_data().unwrap_err(),
            AttestationError::ZeroMeasurement
        );
    }

    fn report_at(policy: u64, family: u8, model: u8, snp: u8) -> AttestationReport {
        use sev::firmware::guest::GuestPolicy;
        let mut report = milan_report();
        report.policy = GuestPolicy::from(policy);
        report.cpuid_fam_id = Some(family);
        report.cpuid_mod_id = Some(model);
        report.reported_tcb.snp = snp;
        report
    }

    #[test]
    fn a_debug_launch_is_refused() {
        let debug = LAUNCH_POLICY | (1 << 19);
        let report = report_at(debug, 0x19, 0xA0, 0x1C);
        assert_eq!(
            require_launch(&report).unwrap_err(),
            AttestationError::LaunchPolicy(debug)
        );
    }

    #[test]
    fn a_migration_agent_launch_is_refused() {
        let migrate = LAUNCH_POLICY | (1 << 18);
        let report = report_at(migrate, 0x19, 0xA0, 0x1C);
        assert_eq!(
            require_launch(&report).unwrap_err(),
            AttestationError::LaunchPolicy(migrate)
        );
    }

    #[test]
    fn siena_firmware_below_the_snp_floor_is_refused() {
        let report = report_at(LAUNCH_POLICY, 0x19, 0xA0, 0x1B);
        assert_eq!(
            require_launch(&report).unwrap_err(),
            AttestationError::LowTcb {
                product: "Genoa".to_string(),
                snp: 0x1B,
                minimum: 0x1C,
            }
        );
    }

    #[test]
    fn the_pinned_policy_and_snp_floor_are_accepted() {
        require_launch(&report_at(LAUNCH_POLICY, 0x19, 0xA0, 0x1C)).unwrap();
        require_launch(&report_at(LAUNCH_POLICY, 0x19, 0x01, 0x1D)).unwrap();
        require_launch(&report_at(LAUNCH_POLICY, 0x1A, 0x00, 0x05)).unwrap();
        assert!(require_launch(&report_at(LAUNCH_POLICY, 0x19, 0x01, 0x1C)).is_err());
        assert!(require_launch(&report_at(LAUNCH_POLICY, 0x1A, 0x00, 0x04)).is_err());
    }

    #[test]
    fn vcek_url_uses_the_reported_tcb_and_chip_id() {
        let chip_id = [0xAB; 64];
        let tcb = TcbVersion {
            fmc: None,
            bootloader: 1,
            tee: 2,
            snp: 3,
            microcode: 4,
        };
        let url = vcek_url("Genoa", &chip_id, &tcb);
        assert_eq!(
            url,
            format!(
                "https://kdsintf.amd.com/vcek/v1/Genoa/{}?blSPL=1&teeSPL=2&snpSPL=3&ucodeSPL=4",
                hex::encode(chip_id)
            )
        );
        assert_eq!(
            cert_chain_url("Genoa"),
            "https://kdsintf.amd.com/vcek/v1/Genoa/cert_chain"
        );

        let turin = TcbVersion {
            fmc: Some(7),
            ..tcb
        };
        assert!(vcek_url("Turin", &chip_id, &turin).ends_with("&fmcSPL=7"));
    }

    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    /// Version 2 reports omit CPUID. Product selection still needs a family
    /// and model, and those fields are not part of the signed encoding.
    fn milan_report_for_kds() -> AttestationReport {
        let mut report = milan_report();
        report.cpuid_fam_id = Some(0x19);
        report.cpuid_mod_id = Some(0x01);
        report
    }

    fn milan_kds_chain() -> Vec<u8> {
        let ark = builtin::milan::ark().unwrap();
        let ask = builtin::milan::ask().unwrap();
        [ark.to_pem().unwrap(), ask.to_pem().unwrap()].concat()
    }

    struct KdsProbe {
        calls: AtomicUsize,
        urls: Mutex<Vec<String>>,
    }

    impl KdsProbe {
        fn new() -> Self {
            Self {
                calls: AtomicUsize::new(0),
                urls: Mutex::new(Vec::new()),
            }
        }

        fn get(&self, url: &str) -> Result<Vec<u8>, String> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.urls.lock().unwrap().push(url.to_string());
            if url.contains("/cert_chain") {
                Ok(milan_kds_chain())
            } else {
                Ok(MILAN_VCEK_DER.to_vec())
            }
        }

        fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }

    fn temp_kds_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("zns-canon-kds-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn a_second_report_with_the_same_chip_and_tcb_does_not_call_kds() {
        let dir = temp_kds_dir("reuse");
        let probe = KdsProbe::new();
        let report = milan_report_for_kds();
        fetch_endorsement_cached(&report, &dir, |url| probe.get(url)).unwrap();
        assert_eq!(probe.calls(), 2);

        let mut other = report;
        other.cpuid_step = Some(9);
        assert_eq!(other.chip_id, report.chip_id);
        assert_eq!(other.reported_tcb, report.reported_tcb);
        fetch_endorsement_cached(&other, &dir, |url| probe.get(url)).unwrap();
        assert_eq!(probe.calls(), 2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_different_spl_or_chip_id_calls_kds() {
        let dir = temp_kds_dir("miss");
        let probe = KdsProbe::new();
        let report = milan_report_for_kds();
        fetch_endorsement_cached(&report, &dir, |url| probe.get(url)).unwrap();
        let after_first = probe.calls();

        let mut other_spl = report;
        other_spl.reported_tcb.snp = other_spl.reported_tcb.snp.wrapping_add(1);
        let spl_error = fetch_endorsement_cached(&other_spl, &dir, |url| probe.get(url));
        assert!(spl_error.is_err(), "a mutated TCB is a different VCEK");
        assert!(probe.calls() > after_first);
        let spl = format!("snpSPL={}", other_spl.reported_tcb.snp);
        assert!(probe
            .urls
            .lock()
            .unwrap()
            .iter()
            .any(|url| url.contains(&spl)));

        let after_spl = probe.calls();
        let mut other_chip = report;
        other_chip.chip_id[0] ^= 0xff;
        let chip_error = fetch_endorsement_cached(&other_chip, &dir, |url| probe.get(url));
        assert!(chip_error.is_err(), "a mutated chip id is a different VCEK");
        assert!(probe.calls() > after_spl);
        let chip = hex::encode(other_chip.chip_id);
        assert!(probe
            .urls
            .lock()
            .unwrap()
            .iter()
            .any(|url| url.contains(&chip)));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_cached_chain_that_fails_the_pinned_ark_is_fetched() {
        let dir = temp_kds_dir("bad-ark");
        std::fs::create_dir_all(&dir).unwrap();
        let report = milan_report_for_kds();
        let chain_path = chain_cache_path(&dir, "Milan");
        let vcek_path = vcek_cache_path(&dir, "Milan", &report.chip_id, &report.reported_tcb);
        std::fs::write(
            &chain_path,
            builtin::turin::ask().unwrap().to_pem().unwrap(),
        )
        .unwrap();
        std::fs::write(&vcek_path, MILAN_VCEK_DER).unwrap();

        let probe = KdsProbe::new();
        fetch_endorsement_cached(&report, &dir, |url| probe.get(url)).unwrap();
        assert_eq!(probe.calls(), 2);
        assert_eq!(std::fs::read(&chain_path).unwrap(), milan_kds_chain());

        fetch_endorsement_cached(&report, &dir, |url| probe.get(url)).unwrap();
        assert_eq!(probe.calls(), 2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_failed_cache_write_still_returns_the_certificates() {
        let dir = temp_kds_dir("write");
        std::fs::create_dir_all(&dir).unwrap();
        let blocker = dir.join("not-a-directory");
        std::fs::write(&blocker, b"x").unwrap();
        let probe = KdsProbe::new();
        fetch_endorsement_cached(&milan_report_for_kds(), &blocker.join("kds"), |url| {
            probe.get(url)
        })
        .unwrap();
        assert_eq!(probe.calls(), 2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_cache_replace_does_not_leave_a_temporary_file() {
        let dir = temp_kds_dir("atomic");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("Milan-cert_chain.pem");
        std::fs::write(&path, b"old-chain").unwrap();
        replace_cache_file(&path, b"new-chain").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"new-chain");
        let names: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(
            names,
            vec![std::ffi::OsString::from("Milan-cert_chain.pem")]
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_failed_replace_leaves_the_cached_chain_intact() {
        let dir = temp_kds_dir("atomic-fail");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("Milan-cert_chain.pem");
        std::fs::write(&path, b"old-chain").unwrap();
        let mut perms = std::fs::metadata(&dir).unwrap().permissions();
        perms.set_readonly(true);
        std::fs::set_permissions(&dir, perms).unwrap();

        let error = replace_cache_file(&path, b"new-chain").unwrap_err();
        assert_eq!(std::fs::read(&path).unwrap(), b"old-chain", "{error}");

        let mut perms = std::fs::metadata(&dir).unwrap().permissions();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            perms.set_mode(0o755);
        }
        std::fs::set_permissions(&dir, perms).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }
}
