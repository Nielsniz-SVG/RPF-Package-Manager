//! EdDSA (Ed25519) and ECDSA (NIST P-256) signature verification, using
//! packages signed by rpm-build itself and the matching public keys.

mod common;

use common::*;
use std::path::{Path, PathBuf};

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

fn key(name: &str) -> PathBuf {
    fixture(&format!("keys/{}", name))
}

fn check_signature(package: &Path, key: &Path) -> std::process::Output {
    let fx = RepoFixture::new("curves");
    fx.rpf(&[
        "check-signature",
        "--key",
        key.to_str().unwrap(),
        package.to_str().unwrap(),
    ])
}

#[test]
fn verifies_an_ed25519_signed_package() {
    let out = check_signature(&fixture("rpmsig-eddsa.rpm"), &key("rpm-testkey-v4-ed25519.asc"));
    assert_success(&out, "check-signature ed25519");
    let text = text(&out);
    assert!(text.contains("OK"), "{}", text);
    assert!(
        text.contains("522E846427933839"),
        "key id should be reported: {}",
        text
    );
}

#[test]
fn verifies_an_ecdsa_signed_package() {
    let out = check_signature(
        &fixture("rpmsig-ecdsa.rpm"),
        &key("rpm-testkey-v4-ecdsa-nistp256.asc"),
    );
    assert_success(&out, "check-signature ecdsa");
    let text = text(&out);
    assert!(text.contains("OK"), "{}", text);
    assert!(
        text.contains("105C3DB6D139A931"),
        "key id should be reported: {}",
        text
    );
}

/// Flipping a byte in the package header must be caught by both curves.
#[test]
fn a_tampered_header_fails_eddsa_and_ecdsa() {
    for (package, key_name) in [
        ("rpmsig-eddsa.rpm", "rpm-testkey-v4-ed25519.asc"),
        ("rpmsig-ecdsa.rpm", "rpm-testkey-v4-ecdsa-nistp256.asc"),
    ] {
        let fx = RepoFixture::new("curves-tamper");
        let mut bytes = std::fs::read(fixture(package)).unwrap();

        // Ask the parser where the main header starts instead of duplicating
        // the lead/signature-header/padding arithmetic here.
        let rpm = rpf::rpm::Rpm::open(&fixture(package)).expect("fixture parses");
        let target = rpm.main_header_offset + 64;
        bytes[target] ^= 0xff;

        let path = fx.path("tampered.rpm");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, &bytes).unwrap();

        let out = check_signature(&path, &key(key_name));
        assert!(
            !out.status.success(),
            "{} with a tampered header must not verify:\n{}",
            package,
            text(&out)
        );
        assert!(
            !text(&out).contains("OK"),
            "{} reported OK after tampering:\n{}",
            package,
            text(&out)
        );
    }
}

#[test]
fn a_package_signed_by_another_curve_does_not_verify() {
    // The EdDSA package carries an issuer key id, so the ecdsa key is simply
    // the wrong one: the check must fail rather than fall back.
    let out = check_signature(
        &fixture("rpmsig-eddsa.rpm"),
        &key("rpm-testkey-v4-ecdsa-nistp256.asc"),
    );
    assert!(!out.status.success(), "wrong key must not verify");
}
