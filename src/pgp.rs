//! OpenPGP: just enough to verify RPM package signatures.
//!
//! This is deliberately a *verifier only*. It parses ASCII-armoured public
//! keys, detached v4 signatures, and checks RSA signatures with PKCS#1 v1.5
//! padding. It never generates keys, never signs, and never decrypts.
//!
//! ## What is verified
//!
//! For a v4 detached signature the hashed data is
//!
//! ```text
//! digest = H( document
//!           || 0x04 || type || pubkey_algo || hash_algo
//!           || BE16(len(hashed subpackets)) || hashed subpackets
//!           || 0x04 || 0xff || BE32(6 + len(hashed subpackets)) )
//! ```
//!
//! The final four-byte count covers only the part of the hashed data that came
//! from the signature packet itself (RFC 4880 §5.2.4), *not* the document.
//! This is easy to get wrong and was confirmed against real RPMs signed by rpm
//! itself: see `tests/fixtures/rpmsig-hello-rsa.rpm`.
//!
//! ## What is not verified
//!
//! * RSA (algorithms 1/2/3), EdDSA (22, Ed25519) and ECDSA (19, NIST P-256)
//!   are verified. Other curves (NIST P-384/P-521, Brainpool) are rejected
//!   with a clear error rather than silently accepted.
//! * Key expiry, revocation and trust levels are not checked: a key that is
//!   present in the configured keyring is trusted, exactly like `rpm --import`
//!   followed by `gpgcheck=1`.

use crate::bigint;
use crate::digest::{self, Sha256, Sha512};
use crate::{Error, Result};

/// Algorithms we can verify.
pub const ALGO_RSA: u8 = 1;
pub const ALGO_RSA_ENCRYPT: u8 = 2;
pub const ALGO_RSA_SIGN: u8 = 3;
pub const ALGO_ECDSA: u8 = 19;
pub const ALGO_EDDSA: u8 = 22;

/// Curve OIDs, as the dotted-octet strings OpenPGP keys carry.
const OID_ED25519: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0xda, 0x47, 0x0f, 0x01];
const OID_NIST_P256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];

/// Hash algorithms (RFC 4880 §9.4).
pub const HASH_SHA1: u8 = 2;
pub const HASH_SHA256: u8 = 8;
pub const HASH_SHA384: u8 = 9;
pub const HASH_SHA512: u8 = 10;

/// Curve key material, for the algorithms that are not RSA.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CurveKey {
    /// Ed25519: the 32-byte compressed point.
    Ed25519(Vec<u8>),
    /// NIST P-256: the affine coordinates, 32 bytes each.
    P256 { x: Vec<u8>, y: Vec<u8> },
}

impl CurveKey {
    /// Bytes per signature component.
    pub fn scalar_len(&self) -> usize {
        32
    }

    pub fn curve_name(&self) -> &'static str {
        match self {
            CurveKey::Ed25519(_) => "Ed25519",
            CurveKey::P256 { .. } => "NIST P-256",
        }
    }
}

/// A public key we can verify signatures with.
#[derive(Debug, Clone)]
pub struct PublicKey {
    /// RSA modulus, big-endian, without leading zeros.
    pub n: Vec<u8>,
    /// RSA public exponent, big-endian.
    pub e: Vec<u8>,
    /// OpenPGP key id: the low 64 bits of the v4 fingerprint.
    pub key_id: u64,
    /// Fingerprint, hex encoded, for messages.
    pub fingerprint: String,
    /// User id, if the key block carried one.
    pub user_id: Option<String>,
    pub algo: u8,
    /// True for a subkey (tag 14): signing subkeys are common.
    pub subkey: bool,
    /// Curve material for EdDSA/ECDSA keys; `None` for RSA.
    pub curve: Option<CurveKey>,
}

impl PublicKey {
    /// Key id as the short uppercase hex form gpg prints.
    pub fn short_id(&self) -> String {
        format!("{:016X}", self.key_id)
    }

    pub fn bits(&self) -> usize {
        if self.curve.is_some() {
            return 256;
        }
        let mut n = self.n.clone();
        while n.first() == Some(&0) {
            n.remove(0);
        }
        match n.first() {
            Some(first) => (n.len() - 1) * 8 + (8 - first.leading_zeros() as usize),
            None => 0,
        }
    }
}

/// A parsed detached signature packet.
#[derive(Debug, Clone)]
pub struct Signature {
    pub version: u8,
    pub kind: u8,
    pub pubkey_algo: u8,
    pub hash_algo: u8,
    /// `version..hashed subpackets`, i.e. the bytes the trailer counts.
    hashed_prefix: Vec<u8>,
    /// First two bytes of the digest, an early-rejection hint.
    pub left16: [u8; 2],
    /// Signature values (MPIs), big-endian without leading zeros.
    mpis: Vec<Vec<u8>>,
    /// Issuer key id, from the unhashed issuer subpacket when present.
    pub issuer: Option<u64>,
    pub created: Option<u32>,
}

impl Signature {
    pub fn algorithm_name(&self) -> &'static str {
        match self.pubkey_algo {
            ALGO_RSA | ALGO_RSA_ENCRYPT | ALGO_RSA_SIGN => "RSA",
            22 => "EdDSA",
            19 => "ECDSA",
            _ => "unknown",
        }
    }

    pub fn hash_name(&self) -> &'static str {
        match self.hash_algo {
            HASH_SHA1 => "SHA-1",
            HASH_SHA256 => "SHA-256",
            HASH_SHA384 => "SHA-384",
            HASH_SHA512 => "SHA-512",
            _ => "unknown",
        }
    }

    /// The raw signature value (the first MPI).
    pub fn signature_value(&self) -> &[u8] {
        self.mpis.first().map(|v| v.as_slice()).unwrap_or(&[])
    }

    /// Digest over `data` as specified for v4 signatures.
    fn digest(&self, data: &[u8]) -> Result<Vec<u8>> {
        let trailer_len = self.hashed_prefix.len() as u32;
        let mut sha256: Option<Sha256> = None;
        let mut sha512: Option<Sha512> = None;
        match self.hash_algo {
            HASH_SHA256 => sha256 = Some(Sha256::new()),
            HASH_SHA384 => sha512 = Some(Sha512::new_384()),
            HASH_SHA512 => sha512 = Some(Sha512::new()),
            HASH_SHA1 => {
                // SHA-1 signatures exist on old packages; we can compute the
                // digest but refuse to trust it (see `verify`).
                let mut buf = Vec::with_capacity(data.len() + self.hashed_prefix.len() + 12);
                buf.extend_from_slice(data);
                buf.extend_from_slice(&self.hashed_prefix);
                buf.extend_from_slice(&[0x04, 0xff]);
                buf.extend_from_slice(&trailer_len.to_be_bytes());
                return Ok(digest::sha1(&buf).to_vec());
            }
            other => {
                return Err(Error::new(format!(
                    "unsupported signature hash algorithm {} (RPF supports SHA-1, SHA-256, SHA-384 and SHA-512)",
                    other
                )))
            }
        }

        let trailer = {
            let mut t = Vec::with_capacity(self.hashed_prefix.len() + 6);
            t.extend_from_slice(&self.hashed_prefix);
            t.extend_from_slice(&[0x04, 0xff]);
            t.extend_from_slice(&trailer_len.to_be_bytes());
            t
        };

        if let Some(mut h) = sha256 {
            h.update(data);
            h.update(&trailer);
            Ok(h.finish().to_vec())
        } else {
            let mut h = sha512.expect("hash algorithm selects a 512-bit digest");
            h.update(data);
            h.update(&trailer);
            let full = h.finish();
            Ok(if self.hash_algo == HASH_SHA384 {
                full[..48].to_vec()
            } else {
                full.to_vec()
            })
        }
    }
}

/// Verify `signature` over `data` with `key`.
pub fn verify(key: &PublicKey, signature: &Signature, data: &[u8]) -> Result<()> {
    if !matches!(
        key.algo,
        ALGO_RSA | ALGO_RSA_ENCRYPT | ALGO_RSA_SIGN | ALGO_ECDSA | ALGO_EDDSA
    ) {
        return Err(Error::new(format!(
            "key {} uses {} signatures, which RPF cannot verify",
            key.short_id(),
            key_algo_name(key.algo)
        )));
    }
    if !matches!(
        signature.pubkey_algo,
        ALGO_RSA | ALGO_RSA_ENCRYPT | ALGO_RSA_SIGN | ALGO_ECDSA | ALGO_EDDSA
    ) {
        return Err(Error::new(format!(
            "signature uses {}, which RPF cannot verify (RSA, Ed25519 and NIST P-256 only)",
            signature.algorithm_name()
        )));
    }
    if signature.hash_algo == HASH_SHA1 {
        return Err(Error::new(
            "signature is made with SHA-1, which RPF refuses to trust; re-sign the package with SHA-256 or better",
        ));
    }

    let digest_bytes = signature.digest(data)?;
    if digest_bytes[..2] != signature.left16 {
        return Err(Error::new(format!(
            "signature by key {} is invalid: digest does not match the signed data",
            key.short_id()
        )));
    }

    if let Some(curve) = &key.curve {
        return verify_curve(key, curve, signature, &digest_bytes);
    }

    let value = signature
        .mpis
        .first()
        .ok_or_else(|| Error::new("signature packet carries no signature value"))?;

    let modulus = bigint::from_be_bytes(&key.n);
    let exponent = bigint::from_be_bytes(&key.e);
    let base = bigint::from_be_bytes(value);
    let recovered = bigint::mod_exp(&base, &exponent, &modulus)?;
    let block = bigint::to_be_bytes(&recovered, key.n.len());

    let expected = pkcs1_v15(&digest_bytes, signature.hash_algo, key.n.len())?;
    if block != expected {
        return Err(Error::new(format!(
            "signature by key {} is invalid: RSA verification failed",
            key.short_id()
        )));
    }
    Ok(())
}

/// Verify an EdDSA or ECDSA signature. Both sign `digest_bytes`, the v4
/// signature digest including the trailer.
fn verify_curve(
    key: &PublicKey,
    curve: &CurveKey,
    signature: &Signature,
    digest_bytes: &[u8],
) -> Result<()> {
    let size = curve.scalar_len();
    if signature.mpis.len() < 2 {
        return Err(Error::new(format!(
            "{} signature packet carries {} value(s), expected 2",
            curve.curve_name(),
            signature.mpis.len()
        )));
    }
    // MPIs drop leading zero octets; curve values are fixed width.
    let first = left_pad(&signature.mpis[0], size, curve.curve_name())?;
    let second = left_pad(&signature.mpis[1], size, curve.curve_name())?;

    let outcome = match curve {
        CurveKey::Ed25519(public) => {
            if signature.hash_algo != HASH_SHA512 {
                return Err(Error::new(format!(
                    "EdDSA signatures must use SHA-512, this one uses {}",
                    signature.hash_name()
                )));
            }
            let mut sig = Vec::with_capacity(64);
            sig.extend_from_slice(&first);
            sig.extend_from_slice(&second);
            crate::ec::ed25519_verify(public, digest_bytes, &sig)
        }
        CurveKey::P256 { x, y } => {
            let mut public = Vec::with_capacity(64);
            public.extend_from_slice(x);
            public.extend_from_slice(y);
            crate::ec::p256_verify(&public, digest_bytes, &first, &second)
        }
    };

    outcome.map_err(|e| {
        Error::new(format!(
            "signature by key {} is invalid: {}",
            key.short_id(),
            e
        ))
    })
}

/// Left-pad a MPI to a fixed width, rejecting anything that does not fit.
fn left_pad(value: &[u8], len: usize, curve: &str) -> Result<Vec<u8>> {
    if value.len() > len {
        return Err(Error::new(format!(
            "{} signature value is {} bytes, expected at most {}",
            curve,
            value.len(),
            len
        )));
    }
    let mut out = vec![0u8; len - value.len()];
    out.extend_from_slice(value);
    Ok(out)
}

/// Strip the 0x40 prefix OpenPGP puts in front of an EdDSA point.
fn strip_point_prefix(point: &[u8], prefix: u8, len: usize, curve: &str) -> Result<Vec<u8>> {
    if point.len() == len + 1 && point[0] == prefix {
        return Ok(point[1..].to_vec());
    }
    // GnuPG writes 0x40 || point, but an older key may store the bare point.
    if point.len() == len {
        return Ok(point.to_vec());
    }
    Err(Error::new(format!(
        "{} public key point is {} bytes, expected {}",
        curve,
        point.len(),
        len + 1
    )))
}

fn hex_oid(oid: &[u8]) -> String {
    oid.iter().map(|b| format!("{:02x}", b)).collect()
}

fn key_algo_name(algo: u8) -> &'static str {
    match algo {
        22 => "EdDSA",
        19 => "ECDSA",
        18 => "ECDH",
        _ => "unknown",
    }
}

/// EMSA-PKCS1-v1_5 encoding of the digest, as RPM signatures use.
fn pkcs1_v15(digest_bytes: &[u8], hash_algo: u8, modulus_len: usize) -> Result<Vec<u8>> {
    const SHA1_PREFIX: &[u8] = &[
        0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14,
    ];
    const SHA256_PREFIX: &[u8] = &[
        0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
        0x05, 0x00, 0x04, 0x20,
    ];
    const SHA384_PREFIX: &[u8] = &[
        0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02,
        0x05, 0x00, 0x04, 0x30,
    ];
    const SHA512_PREFIX: &[u8] = &[
        0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03,
        0x05, 0x00, 0x04, 0x40,
    ];

    let prefix = match hash_algo {
        HASH_SHA1 => SHA1_PREFIX,
        HASH_SHA256 => SHA256_PREFIX,
        HASH_SHA384 => SHA384_PREFIX,
        HASH_SHA512 => SHA512_PREFIX,
        other => {
            return Err(Error::new(format!(
                "unsupported signature hash algorithm {}",
                other
            )))
        }
    };

    let t_len = prefix.len() + digest_bytes.len();
    if modulus_len < t_len + 11 {
        return Err(Error::new("RSA key is too small for this digest"));
    }
    let mut out = Vec::with_capacity(modulus_len);
    out.push(0x00);
    out.push(0x01);
    out.resize(modulus_len - t_len - 1, 0xff);
    out.push(0x00);
    out.extend_from_slice(prefix);
    out.extend_from_slice(digest_bytes);
    Ok(out)
}

// ---------------------------------------------------------------------------
// ASCII armour
// ---------------------------------------------------------------------------

/// Decode an ASCII-armoured OpenPGP block into raw packet bytes.
///
/// Armour headers are ignored and the CRC24 line is skipped: the signature
/// itself is the integrity check that matters, and rejection on a CRC line we
/// mis-parse would lock users out of valid keys.
pub fn dearmor(text: &str) -> Result<Vec<u8>> {
    let mut base64 = String::new();
    let mut in_body = false;
    let mut saw_begin = false;

    for line in text.lines() {
        let line = line.trim();
        if line.starts_with("-----BEGIN PGP") {
            saw_begin = true;
            in_body = false;
            continue;
        }
        if line.starts_with("-----END PGP") {
            break;
        }
        if !saw_begin {
            continue;
        }
        if !in_body {
            // Armour headers ("Version: ...") end at the first blank line.
            if line.is_empty() {
                in_body = true;
            }
            continue;
        }
        if line.starts_with('=') || line.is_empty() {
            continue;
        }
        base64.push_str(line);
    }

    if !saw_begin {
        return Err(Error::new("not an ASCII-armoured OpenPGP block"));
    }
    base64_decode(&base64)
}

pub fn base64_decode(text: &str) -> Result<Vec<u8>> {
    fn value(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }

    let mut out = Vec::with_capacity(text.len() * 3 / 4);
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    for byte in text.bytes() {
        if byte == b'=' || byte.is_ascii_whitespace() {
            continue;
        }
        let v = value(byte).ok_or_else(|| {
            Error::new(format!(
                "invalid base64 character {:?} in armoured data",
                byte as char
            ))
        })?;
        acc = (acc << 6) | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Packet parsing
// ---------------------------------------------------------------------------

/// Split an OpenPGP packet stream into `(tag, body)` pairs.
pub fn packets(data: &[u8]) -> Result<Vec<(u8, &[u8])>> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < data.len() {
        let first = data[i];
        if first & 0x80 == 0 {
            return Err(Error::new(format!(
                "malformed OpenPGP packet: tag byte {:#04x}",
                first
            )));
        }
        let (tag, len, header_len) = if first & 0x40 != 0 {
            // New format.
            let tag = first & 0x3f;
            if i + 1 >= data.len() {
                return Err(Error::new("truncated OpenPGP packet"));
            }
            let l0 = data[i + 1] as usize;
            if l0 < 192 {
                (tag, l0, 2)
            } else if l0 < 224 {
                if i + 2 >= data.len() {
                    return Err(Error::new("truncated OpenPGP packet length"));
                }
                (tag, ((l0 - 192) << 8) + data[i + 2] as usize + 192, 3)
            } else if l0 == 255 {
                if i + 5 >= data.len() {
                    return Err(Error::new("truncated OpenPGP packet length"));
                }
                let len = u32::from_be_bytes([data[i + 2], data[i + 3], data[i + 4], data[i + 5]])
                    as usize;
                (tag, len, 6)
            } else {
                return Err(Error::new(
                    "partial-body OpenPGP packets are not supported",
                ));
            }
        } else {
            // Old format.
            let tag = (first >> 2) & 0x0f;
            let len_type = first & 0x03;
            match len_type {
                0 => {
                    if i + 1 >= data.len() {
                        return Err(Error::new("truncated OpenPGP packet"));
                    }
                    (tag, data[i + 1] as usize, 2)
                }
                1 => {
                    if i + 2 >= data.len() {
                        return Err(Error::new("truncated OpenPGP packet"));
                    }
                    (
                        tag,
                        u16::from_be_bytes([data[i + 1], data[i + 2]]) as usize,
                        3,
                    )
                }
                2 => {
                    if i + 4 >= data.len() {
                        return Err(Error::new("truncated OpenPGP packet"));
                    }
                    (
                        tag,
                        u32::from_be_bytes([data[i + 1], data[i + 2], data[i + 3], data[i + 4]])
                            as usize,
                        5,
                    )
                }
                _ => (tag, data.len() - i - 1, 1),
            }
        };

        let start = i + header_len;
        let end = start
            .checked_add(len)
            .filter(|e| *e <= data.len())
            .ok_or_else(|| Error::new("truncated OpenPGP packet body"))?;
        out.push((tag, &data[start..end]));
        i = end;
    }
    Ok(out)
}

fn mpis(mut data: &[u8]) -> Result<Vec<Vec<u8>>> {
    let mut out = Vec::new();
    while data.len() >= 2 {
        let bits = u16::from_be_bytes([data[0], data[1]]) as usize;
        let len = bits.div_ceil(8);
        data = &data[2..];
        if data.len() < len {
            return Err(Error::new("truncated OpenPGP MPI"));
        }
        out.push(data[..len].to_vec());
        data = &data[len..];
    }
    Ok(out)
}

/// Parse ASCII-armoured public keys.
pub fn parse_public_keys(text: &str) -> Result<Vec<PublicKey>> {
    let raw = dearmor(text)?;
    parse_public_key_packets(&raw)
}

pub fn parse_public_key_packets(raw: &[u8]) -> Result<Vec<PublicKey>> {
    let mut keys = Vec::new();
    let mut pending_user_id: Option<String> = None;

    for (tag, body) in packets(raw)? {
        match tag {
            6 | 14 => {
                let mut key = parse_public_key(body)?;
                key.subkey = tag == 14;
                // Subkeys belong to the user id that precedes them.
                key.user_id = pending_user_id.clone();
                keys.push(key);
            }
            13 => {
                pending_user_id = Some(String::from_utf8_lossy(body).trim().to_string());
            }
            _ => {}
        }
    }

    if keys.is_empty() {
        return Err(Error::new(
            "no public key found in the key block (RPF needs a signing key, not a signature)",
        ));
    }
    Ok(keys)
}

fn parse_public_key(body: &[u8]) -> Result<PublicKey> {
    if body.is_empty() {
        return Err(Error::new("empty public key packet"));
    }
    let version = body[0];
    if version != 4 {
        return Err(Error::new(format!(
            "OpenPGP v{} keys are not supported yet (Fedora and RPM Fusion publish v4 keys)",
            version
        )));
    }
    if body.len() < 6 {
        return Err(Error::new("truncated public key packet"));
    }
    let algo = body[5];
    if !matches!(
        algo,
        ALGO_RSA | ALGO_RSA_ENCRYPT | ALGO_RSA_SIGN | ALGO_ECDSA | ALGO_EDDSA
    ) {
        return Err(Error::new(format!(
            "public key uses {}, which RPF cannot verify (RSA, Ed25519 and NIST P-256 only)",
            key_algo_name(algo)
        )));
    }
    let (n, e, curve) = match algo {
        ALGO_EDDSA | ALGO_ECDSA => {
            // Curve keys carry a length-prefixed OID rather than an MPI.
            if body.len() < 7 {
                return Err(Error::new("curve public key is missing its curve OID"));
            }
            let oid_len = body[6] as usize;
            if body.len() < 7 + oid_len {
                return Err(Error::new("curve public key has a truncated OID"));
            }
            let oid = &body[7..7 + oid_len];
            let expected = if algo == ALGO_EDDSA {
                OID_ED25519
            } else {
                OID_NIST_P256
            };
            if oid != expected {
                return Err(Error::new(format!(
                    "{} key uses curve OID {}, which RPF cannot verify ({} only)",
                    key_algo_name(algo),
                    hex_oid(oid),
                    if algo == ALGO_EDDSA {
                        "Ed25519"
                    } else {
                        "NIST P-256"
                    }
                )));
            }
            let values = mpis(&body[7 + oid_len..])?;
            let point = values
                .first()
                .ok_or_else(|| Error::new("curve public key is missing its point"))?;
            if algo == ALGO_EDDSA {
                let point = strip_point_prefix(point, 0x40, 32, "Ed25519")?;
                (Vec::new(), Vec::new(), Some(CurveKey::Ed25519(point)))
            } else {
                // Uncompressed: 0x04 || X || Y.
                if point.len() != 65 || point[0] != 0x04 {
                    return Err(Error::new(
                        "ECDSA public key is not an uncompressed 65-byte point",
                    ));
                }
                (
                    Vec::new(),
                    Vec::new(),
                    Some(CurveKey::P256 {
                        x: point[1..33].to_vec(),
                        y: point[33..65].to_vec(),
                    }),
                )
            }
        }
        _ => {
            let values = mpis(&body[6..])?;
            if values.len() < 2 {
                return Err(Error::new(
                    "RSA public key is missing its modulus or exponent",
                ));
            }
            (values[0].clone(), values[1].clone(), None)
        }
    };

    // v4 fingerprint: SHA-1 over 0x99, the two-octet length, then the packet.
    let mut material = Vec::with_capacity(body.len() + 3);
    material.push(0x99);
    material.extend_from_slice(&(body.len() as u16).to_be_bytes());
    material.extend_from_slice(body);
    let fingerprint = digest::sha1(&material);
    let mut key_id_bytes = [0u8; 8];
    key_id_bytes.copy_from_slice(&fingerprint[12..20]);

    Ok(PublicKey {
        n,
        e,
        key_id: u64::from_be_bytes(key_id_bytes),
        fingerprint: digest::hex(&fingerprint),
        user_id: None,
        algo,
        subkey: false,
        curve,
    })
}

/// Parse a detached signature that may be armoured (as `repomd.xml.asc` is)
/// or raw (as an RPM's signature header stores it).
pub fn parse_signature_bytes(raw: &[u8]) -> Result<Signature> {
    if raw.starts_with(b"-----BEGIN") {
        let text = String::from_utf8_lossy(raw);
        let binary = dearmor(&text)?;
        return parse_signature(&binary);
    }
    parse_signature(raw)
}

/// Parse a detached signature packet (the blob stored in an RPM's header).
pub fn parse_signature(raw: &[u8]) -> Result<Signature> {
    let packets = packets(raw)?;
    let (tag, body) = packets
        .iter()
        .find(|(tag, _)| *tag == 2)
        .ok_or_else(|| Error::new("no signature packet in the RPM's signature header"))?;
    let _ = tag;
    parse_signature_body(body)
}

fn parse_signature_body(body: &[u8]) -> Result<Signature> {
    if body.len() < 6 {
        return Err(Error::new("truncated signature packet"));
    }
    let version = body[0];
    if version != 4 {
        return Err(Error::new(format!(
            "OpenPGP v{} signatures are not supported",
            version
        )));
    }
    let kind = body[1];
    let pubkey_algo = body[2];
    let hash_algo = body[3];
    let hashed_len = u16::from_be_bytes([body[4], body[5]]) as usize;
    let hashed_end = 6 + hashed_len;
    if body.len() < hashed_end + 4 {
        return Err(Error::new("truncated signature subpacket area"));
    }
    let hashed_subpackets = &body[6..hashed_end];

    let unhashed_len =
        u16::from_be_bytes([body[hashed_end], body[hashed_end + 1]]) as usize;
    let unhashed_start = hashed_end + 2;
    let unhashed_end = unhashed_start + unhashed_len;
    if body.len() < unhashed_end + 2 {
        return Err(Error::new("truncated signature subpacket area"));
    }
    let unhashed = &body[unhashed_start..unhashed_end];
    let mut left16 = [0u8; 2];
    left16.copy_from_slice(&body[unhashed_end..unhashed_end + 2]);
    let values = mpis(&body[unhashed_end + 2..])?;

    let (issuer, created) = signature_metadata(hashed_subpackets, unhashed);

    Ok(Signature {
        version,
        kind,
        pubkey_algo,
        hash_algo,
        hashed_prefix: body[..hashed_end].to_vec(),
        left16,
        mpis: values,
        issuer,
        created,
    })
}

/// Pull the issuer key id and creation time out of the subpacket areas.
///
/// The issuer lives in the *unhashed* area for RPM signatures and in the
/// hashed area for some others; both are checked, the hashed one first because
/// it is the one that is actually signed.
fn signature_metadata(hashed: &[u8], unhashed: &[u8]) -> (Option<u64>, Option<u32>) {
    let mut issuer = None;
    let mut created = None;

    for area in [hashed, unhashed] {
        let mut i = 0usize;
        while i < area.len() {
            let (len, len_bytes) = match area[i] {
                0..=191 => (area[i] as usize, 1),
                192..=254 => {
                    if i + 1 >= area.len() {
                        break;
                    }
                    (
                        ((area[i] as usize - 192) << 8) + area[i + 1] as usize + 192,
                        2,
                    )
                }
                _ => {
                    if i + 4 >= area.len() {
                        break;
                    }
                    (
                        u32::from_be_bytes([area[i + 1], area[i + 2], area[i + 3], area[i + 4]])
                            as usize,
                        5,
                    )
                }
            };
            let start = i + len_bytes;
            let end = start + len;
            if end > area.len() || len == 0 {
                break;
            }
            let kind = area[start] & 0x7f;
            let payload = &area[start + 1..end];
            match kind {
                16 if payload.len() == 8 => {
                    let mut id = [0u8; 8];
                    id.copy_from_slice(payload);
                    if issuer.is_none() {
                        issuer = Some(u64::from_be_bytes(id));
                    }
                }
                33 if payload.len() == 21 => {
                    // Issuer fingerprint: version byte followed by the 20-byte
                    // v4 fingerprint; the key id is its last 8 bytes.
                    let mut id = [0u8; 8];
                    id.copy_from_slice(&payload[13..21]);
                    if issuer.is_none() {
                        issuer = Some(u64::from_be_bytes(id));
                    }
                }
                2 if payload.len() == 4 => {
                    if created.is_none() {
                        created = Some(u32::from_be_bytes([
                            payload[0], payload[1], payload[2], payload[3],
                        ]));
                    }
                }
                _ => {}
            }
            i = end;
        }
    }

    (issuer, created)
}

/// A keyring: the keys a repository's `gpgkey=` entries provide.
#[derive(Debug, Default, Clone)]
pub struct Keyring {
    pub keys: Vec<PublicKey>,
}

impl Keyring {
    pub fn new() -> Self {
        Keyring::default()
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    pub fn add_armored(&mut self, text: &str) -> Result<usize> {
        let parsed = parse_public_keys(text)?;
        let count = parsed.len();
        self.keys.extend(parsed);
        Ok(count)
    }

    pub fn add_keys(&mut self, keys: Vec<PublicKey>) {
        self.keys.extend(keys);
    }

    /// Find the key a signature claims to come from.
    pub fn find(&self, issuer: Option<u64>) -> Option<&PublicKey> {
        match issuer {
            Some(id) => self.keys.iter().find(|k| k.key_id == id),
            None => None,
        }
    }

    pub fn describe(&self) -> Vec<String> {
        self.keys
            .iter()
            .map(|k| match &k.user_id {
                Some(uid) => format!("{} ({})", k.short_id(), uid),
                None => k.short_id(),
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::{Path, PathBuf};

    fn fixture(name: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(name)
    }

    fn keyring(name: &str) -> Keyring {
        let text = std::fs::read_to_string(fixture(name)).unwrap();
        let mut ring = Keyring::new();
        ring.add_armored(&text).unwrap();
        ring
    }

    #[test]
    fn base64_roundtrip() {
        assert_eq!(base64_decode("aGVsbG8=").unwrap(), b"hello");
        assert_eq!(base64_decode("aGVsbG8h").unwrap(), b"hello!");
        assert!(base64_decode("a$b").is_err());
    }

    #[test]
    fn dearmor_rejects_plain_text() {
        assert!(dearmor("hello world").is_err());
    }

    #[test]
    fn parses_rsa_public_key() {
        let ring = keyring("keys/rpm.org-rsa-2048-test.pub");
        // The test key carries a primary key and a signing subkey; both must be
        // available, because packages are usually signed by the subkey.
        assert_eq!(ring.keys.len(), 2);
        let key = &ring.keys[0];
        assert!(!key.subkey);
        assert!(ring.keys[1].subkey);
        assert_eq!(key.algo, ALGO_RSA);
        assert_eq!(key.bits(), 2048);
        assert_eq!(key.short_id(), "4344591E1964C5FC");
        assert_eq!(
            key.fingerprint.to_uppercase(),
            "771B18D3D7BAA28734333C424344591E1964C5FC"
        );
    }

    #[test]
    fn parses_signature_packets() {
        let rpm = std::fs::read(fixture("rpmsig-hello-rsa.rpm")).unwrap();
        // Signature header is 8 entries; tag 268 is the RSA header signature.
        let blob = extract_sig(&rpm, 268).expect("tag 268");
        let sig = parse_signature(&blob).unwrap();
        assert_eq!(sig.version, 4);
        assert_eq!(sig.kind, 0, "binary document signature");
        assert_eq!(sig.pubkey_algo, ALGO_RSA);
        assert_eq!(sig.hash_algo, HASH_SHA256);
        assert!(sig.issuer.is_some());
        assert_eq!(sig.hash_name(), "SHA-256");
        assert_eq!(sig.algorithm_name(), "RSA");
    }

    /// Minimal RPM signature-header reader, independent of `rpm.rs`, so this
    /// test does not lean on the code under test elsewhere.
    fn extract_sig(data: &[u8], wanted: u32) -> Option<Vec<u8>> {
        let start = 96usize;
        let nindex = u32::from_be_bytes([
            data[start + 8],
            data[start + 9],
            data[start + 10],
            data[start + 11],
        ]) as usize;
        let store = start + 16 + nindex * 16;
        for i in 0..nindex {
            let entry = start + 16 + i * 16;
            let tag = u32::from_be_bytes([
                data[entry],
                data[entry + 1],
                data[entry + 2],
                data[entry + 3],
            ]);
            let offset = u32::from_be_bytes([
                data[entry + 8],
                data[entry + 9],
                data[entry + 10],
                data[entry + 11],
            ]) as usize;
            let count = u32::from_be_bytes([
                data[entry + 12],
                data[entry + 13],
                data[entry + 14],
                data[entry + 15],
            ]) as usize;
            if tag == wanted {
                return Some(data[store + offset..store + offset + count].to_vec());
            }
        }
        None
    }
}
