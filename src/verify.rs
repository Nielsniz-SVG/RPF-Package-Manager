//! Package signature policy.
//!
//! `pgp` knows how to check one signature; this module decides *which* keys are
//! trusted and *what* happens when a package is unsigned or signed by a key we
//! do not have.
//!
//! Policy, matching dnf where it matters and being stricter where it is safe:
//!
//! * A repository with `gpgcheck=1` must have its packages verified. If a key
//!   is missing the package is refused, not waved through.
//! * A signature that is present but invalid always refuses the package, even
//!   from a `gpgcheck=0` repository: a corrupted signature is evidence of
//!   tampering, not of a relaxed configuration.
//! * `gpgcheck=0` packages install with a warning, because that is what the
//!   administrator asked for.
//! * Local `.rpm` files are verified when their signing key is available, and
//!   install with a warning otherwise (dnf's `localpkg_gpgcheck=0` default).

use std::path::{Path, PathBuf};

use crate::config::{Config, Repo};
use crate::pgp::Keyring;
use crate::rpm::{Rpm, SignatureOutcome};
use crate::{fetch, Error, Result};

/// What we concluded about a package.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// At least one signature verified, none were invalid.
    Signed { key_ids: Vec<String> },
    /// No signature at all.
    Unsigned,
    /// Signed, but none of the keys we have match.
    UnknownKey { key_ids: Vec<String> },
    /// A signature is present and does not verify.
    Invalid { reasons: Vec<String> },
    /// The algorithm is not supported yet (EdDSA, ECDSA).
    Unsupported { reason: String },
}

impl Verdict {
    pub fn describe(&self) -> String {
        match self {
            Verdict::Signed { key_ids } => {
                let mut ids = key_ids.clone();
                ids.dedup();
                format!("signed by key {}", ids.join(", "))
            }
            Verdict::Unsigned => "not signed".to_string(),
            Verdict::UnknownKey { key_ids } => {
                if key_ids.is_empty() {
                    "signed by a key that is not in the keyring".to_string()
                } else {
                    format!("signed by unknown key {}", key_ids.join(", "))
                }
            }
            Verdict::Invalid { reasons } => format!("signature invalid: {}", reasons.join("; ")),
            Verdict::Unsupported { reason } => reason.clone(),
        }
    }

    pub fn is_trusted(&self) -> bool {
        matches!(self, Verdict::Signed { .. })
    }
}

/// Check one package file against a keyring.
pub fn check_package(path: &Path, keyring: &Keyring) -> Result<Verdict> {
    let rpm = Rpm::open(path)?;
    check_rpm(&rpm, keyring)
}

pub fn check_rpm(rpm: &Rpm, keyring: &Keyring) -> Result<Verdict> {
    let outcomes = rpm.verify_signatures(keyring)?;
    if outcomes.is_empty() {
        return Ok(Verdict::Unsigned);
    }

    let mut key_ids = Vec::new();
    let mut reasons = Vec::new();
    let mut unsupported = None;
    for outcome in &outcomes {
        match outcome {
            SignatureOutcome::Verified { key_id, .. } => key_ids.push(key_id.clone()),
            SignatureOutcome::NoKey { key_id, .. } => {
                if let Some(id) = key_id {
                    key_ids.push(id.clone());
                }
            }
            SignatureOutcome::Invalid { reason, .. } => reasons.push(reason.clone()),
        }
    }
    if let Some(reason) = outcomes.iter().find_map(|o| match o {
        SignatureOutcome::Invalid { reason, .. } if reason.contains("cannot verify yet") => {
            Some(reason.clone())
        }
        _ => None,
    }) {
        unsupported = Some(reason);
    }

    if !reasons.is_empty() {
        // Signature errors about unsupported algorithms are not tampering.
        if reasons.len() == 1 && unsupported.is_some() {
            return Ok(Verdict::Unsupported {
                reason: unsupported.unwrap(),
            });
        }
        return Ok(Verdict::Invalid { reasons });
    }
    if key_ids.is_empty() {
        return Ok(Verdict::UnknownKey {
            key_ids: Vec::new(),
        });
    }
    if outcomes.iter().any(|o| o.is_verified()) {
        return Ok(Verdict::Signed { key_ids });
    }
    Ok(Verdict::UnknownKey { key_ids })
}

/// Verify a detached signature over arbitrary data (used for `repomd.xml`).
///
/// When the signature names an issuer we check that key only; otherwise every
/// key in the ring is tried, which is what rpm does for keyless issuers.
pub fn verify_detached(keyring: &Keyring, signature: &[u8], data: &[u8]) -> Result<()> {
    if keyring.is_empty() {
        return Err(Error::new("no trusted keys available"));
    }
    let sig = crate::pgp::parse_signature_bytes(signature)?;
    if let Some(key) = keyring.find(sig.issuer) {
        return crate::pgp::verify(key, &sig, data);
    }
    let mut last = None;
    for key in &keyring.keys {
        match crate::pgp::verify(key, &sig, data) {
            Ok(()) => return Ok(()),
            Err(e) => last = Some(e),
        }
    }
    Err(last.unwrap_or_else(|| Error::new("signature did not match any trusted key")))
}

/// Enforce `repo_gpgcheck`: verify `repodata/repomd.xml` against the
/// repository's keys before any of it is trusted.
pub fn verify_repomd(
    config: &Config,
    repo: &Repo,
    bases: &[String],
    repomd: &[u8],
) -> Result<()> {
    let signature = fetch::fetch_bytes_from_mirrors(bases, "repodata/repomd.xml.asc")
        .map_err(|e| {
            Error::new(format!(
                "repository '{}' has repo_gpgcheck=1 but repomd.xml.asc is unavailable: {}",
                repo.id, e
            ))
        })?
        .1;

    let keyring = keys_for_repo(config, repo).map_err(|e| {
        Error::new(format!(
            "repository '{}' has repo_gpgcheck=1 but its keys are unavailable: {}",
            repo.id, e
        ))
    })?;

    verify_detached(&keyring, &signature, repomd).map_err(|e| {
        Error::new(format!(
            "repository '{}' metadata signature is invalid: {}",
            repo.id, e
        ))
    })
}

/// Keyring built from every enabled repository's `gpgkey=` entries.
pub fn keyring_for_repos(config: &Config, repos: &[&Repo]) -> Result<Keyring> {
    let mut ring = Keyring::new();
    let mut problems = Vec::new();
    for repo in repos {
        match keys_for_repo(config, repo) {
            Ok(extra) => ring.add_keys(extra.keys),
            Err(e) => problems.push(format!("{}: {}", repo.id, e)),
        }
    }
    if ring.is_empty() && !problems.is_empty() {
        return Err(Error::new(format!(
            "no usable repository keys: {}",
            problems.join("; ")
        )));
    }
    Ok(ring)
}

/// Fetch (and cache) one repository's keys.
pub fn keys_for_repo(config: &Config, repo: &Repo) -> Result<Keyring> {
    let dir = config.conf.cachedir.join("keys");
    std::fs::create_dir_all(&dir)
        .map_err(|e| Error::new(format!("{}: {}", dir.display(), e)))?;

    let mut ring = Keyring::new();
    for (index, url) in repo.gpgkeys.iter().enumerate() {
        let cache_path = dir.join(format!("{}-{}.key", sanitise(&repo.id), index));
        let bytes = if cache_path.exists() {
            std::fs::read(&cache_path)
                .map_err(|e| Error::new(format!("{}: {}", cache_path.display(), e)))?
        } else {
            let fetched = fetch::fetch_bytes(url)
                .map_err(|e| Error::new(format!("cannot fetch key {}: {}", url, e)))?;
            let _ = std::fs::write(&cache_path, &fetched);
            fetched
        };
        ring.add_keys(parse_key_material(&bytes)?);
    }
    Ok(ring)
}

/// Parse either ASCII-armoured or binary key material.
pub fn parse_key_material(bytes: &[u8]) -> Result<Vec<crate::pgp::PublicKey>> {
    if bytes.starts_with(b"-----BEGIN") {
        let text = String::from_utf8_lossy(bytes);
        return crate::pgp::parse_public_keys(&text);
    }
    crate::pgp::parse_public_key_packets(bytes)
}

/// Load key files given by `--key`.
pub fn keyring_from_files(paths: &[PathBuf]) -> Result<Keyring> {
    let mut ring = Keyring::new();
    for path in paths {
        let bytes = std::fs::read(path)
            .map_err(|e| Error::new(format!("{}: {}", path.display(), e)))?;
        ring.add_keys(parse_key_material(&bytes)?);
    }
    Ok(ring)
}

fn sanitise(id: &str) -> String {
    let cleaned: String = id
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' { c } else { '_' })
        .collect();
    if cleaned.is_empty() {
        "_".to_string()
    } else {
        cleaned
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(name: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(name)
    }

    #[test]
    fn verifies_a_known_signed_package() {
        let ring = keyring_from_files(&[fixture("keys/rpm.org-rsa-2048-test.pub")]).unwrap();
        let verdict = check_package(&fixture("rpmsig-hello-rsa.rpm"), &ring).unwrap();
        assert!(verdict.is_trusted(), "{}", verdict.describe());
        assert!(verdict.describe().contains("signed by key"));
    }

    #[test]
    fn reports_unknown_key() {
        let ring = keyring_from_files(&[fixture("keys/rpm-testkey-v4-rsa4096.asc")]).unwrap();
        let verdict = check_package(&fixture("rpmsig-hello-rsa.rpm"), &ring).unwrap();
        assert!(!verdict.is_trusted());
        assert!(
            verdict.describe().contains("unknown key"),
            "{}",
            verdict.describe()
        );
    }

    #[test]
    fn reports_unsigned_package() {
        let ring = Keyring::new();
        let verdict = check_package(&fixture("basic-gzip.rpm"), &ring).unwrap();
        assert_eq!(verdict, Verdict::Unsigned);
        assert!(!verdict.is_trusted());
    }

    #[test]
    fn rejects_a_tampered_package() {
        let ring = keyring_from_files(&[fixture("keys/rpm.org-rsa-2048-test.pub")]).unwrap();
        let data = std::fs::read(fixture("rpmsig-hello-rsa.rpm")).unwrap();
        let rpm = Rpm::parse(data.clone()).unwrap();
        let mut broken = data;
        let offset = rpm.main_header_offset + 40;
        broken[offset] ^= 0xff;
        let rpm = Rpm::parse(broken).unwrap();
        let verdict = check_rpm(&rpm, &ring).unwrap();
        assert!(!verdict.is_trusted());
        assert!(
            matches!(verdict, Verdict::Invalid { .. }),
            "{}",
            verdict.describe()
        );
    }

    #[test]
    fn parses_binary_and_armored_keys() {
        let armored = std::fs::read(fixture("keys/rpm.org-rsa-2048-test.pub")).unwrap();
        assert_eq!(parse_key_material(&armored).unwrap().len(), 2);

        let raw = crate::pgp::dearmor(std::str::from_utf8(&armored).unwrap()).unwrap();
        assert_eq!(parse_key_material(&raw).unwrap().len(), 2);
    }
}
