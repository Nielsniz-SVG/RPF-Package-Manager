//! Elliptic curve signature verification: Ed25519 (RFC 8032) and ECDSA on
//! NIST P-256 (FIPS 186-4).
//!
//! Both are *verification only*. There is no key generation and no signing, so
//! there are no secret-dependent operations to leak through timing; the code
//! deliberately favours clarity over constant-time behaviour.
//!
//! Field arithmetic lives in [`crate::bigint::Field`] (Montgomery). Points use
//! projective coordinates so a scalar multiplication needs a single inversion
//! at the very end instead of one per addition.

use crate::bigint::{Field, Limbs};
use crate::digest;
use crate::{Error, Result};

/// Ed25519 verification (RFC 8032 §5.1.7).
///
/// `public` is the 32-byte compressed public key, `signature` the 64-byte
/// `R || S` pair, and `message` the data that was signed.
pub fn ed25519_verify(public: &[u8], message: &[u8], signature: &[u8]) -> Result<()> {
    if public.len() != 32 {
        return Err(Error::new(format!(
            "Ed25519 public key must be 32 bytes, got {}",
            public.len()
        )));
    }
    if signature.len() != 64 {
        return Err(Error::new(format!(
            "Ed25519 signature must be 64 bytes, got {}",
            signature.len()
        )));
    }
    let curve = Curve::ed25519()?;
    let a = curve.decode_point(public)?;
    let r = curve.decode_point(&signature[..32])?;

    let s = scalar_from_le(&signature[32..]);
    if !curve.scalar_is_canonical(&s) {
        return Err(Error::new("Ed25519 signature scalar is out of range"));
    }

    // k = SHA-512(R || A || M) mod L
    let mut hasher_input = Vec::with_capacity(64 + message.len());
    hasher_input.extend_from_slice(&signature[..32]);
    hasher_input.extend_from_slice(public);
    hasher_input.extend_from_slice(message);
    let k = curve.reduce_mod_order(&digest::sha512(&hasher_input));

    // Check [S]B == R + [k]A by comparing encodings.
    let lhs = curve.mul_base(&s);
    let rhs = curve.add(&r, &curve.mul(&a, &k));
    if curve.encode_point(&lhs) == curve.encode_point(&rhs) {
        Ok(())
    } else {
        Err(Error::new("Ed25519 signature does not verify"))
    }
}

/// ECDSA verification on NIST P-256.
///
/// `public` is the 64-byte uncompressed point (`x || y`), `r` and `s` are
/// big-endian scalars, and the digest is hashed-as-given (callers pass the
/// output of the signature's hash algorithm).
pub fn p256_verify(public: &[u8], digest: &[u8], r: &[u8], s: &[u8]) -> Result<()> {
    if public.len() != 64 {
        return Err(Error::new(format!(
            "P-256 public key must be 64 bytes, got {}",
            public.len()
        )));
    }
    let curve = Curve::p256()?;
    let order = Field::new(&P256_ORDER)?;

    let r_scalar = order.from_be(r);
    let s_scalar = order.from_be(s);
    if order.is_zero(&r_scalar) || order.is_zero(&s_scalar) {
        return Err(Error::new("ECDSA signature has a zero component"));
    }
    // r and s must be smaller than the group order.
    if compare_be(r, &P256_ORDER) != std::cmp::Ordering::Less
        || compare_be(s, &P256_ORDER) != std::cmp::Ordering::Less
    {
        return Err(Error::new("ECDSA signature component is out of range"));
    }

    // e = leftmost bits of the digest, truncated to the order's bit length.
    let mut e_bytes = digest.to_vec();
    if e_bytes.len() > 32 {
        e_bytes.truncate(32);
    }
    let e = order.from_be(&e_bytes);

    let w = order.inv(&s_scalar)?;
    let u1 = order.mul(&e, &w);
    let u2 = order.mul(&r_scalar, &w);

    let q = curve.point_from_xy(&public[..32], &public[32..])?;
    let p1 = curve.mul_base(&u1);
    let p2 = curve.mul(&q, &u2);
    let sum = curve.add(&p1, &p2);
    if curve.is_infinity(&sum) {
        return Err(Error::new("ECDSA verification produced the point at infinity"));
    }

    let (x, _y) = curve.affine(&sum)?;
    // x mod n, then compare with r.
    let x_reduced = reduce_bytes_mod(&curve.f, &x, &order)?;
    let x_field = order.from_be(&x_reduced);
    if order.eq(&x_field, &r_scalar) {
        Ok(())
    } else {
        Err(Error::new("ECDSA signature does not verify"))
    }
}

// ---------------------------------------------------------------------------
// Curve parameters
// ---------------------------------------------------------------------------

/// P-256 group order.
const P256_ORDER: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84,
    0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
];

/// Ed25519 group order L = 2^252 + 27742317777372353535851937790883648493.
const ED25519_ORDER: [u8; 32] = [
    0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x14, 0xde, 0xf9, 0xde, 0xa2, 0xf7, 0x9c, 0xd6,
    0x58, 0x12, 0x63, 0x1a, 0x5c, 0xf5, 0xd3, 0xed,
];

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Ed25519,
    P256,
}

/// Point in projective coordinates.
///
/// Ed25519 uses extended coordinates `(X : Y : Z : T)` with `x = X/Z`,
/// `y = Y/Z`, `x*y = T/Z`; P-256 uses Jacobian `(X : Y : Z)` with
/// `x = X/Z^2`, `y = Y/Z^3`. `t` is unused for P-256.
#[derive(Clone)]
struct Point {
    x: Limbs,
    y: Limbs,
    z: Limbs,
    t: Limbs,
}

struct Curve {
    kind: Kind,
    f: Field,
    /// Ed25519: twist coefficient d. Unused for P-256.
    d: Limbs,
    d2: Limbs,
    base: Point,
    /// P-256: curve coefficient b, used when decoding points.
    b: Limbs,
    order: Field,
}

impl Curve {
    fn ed25519() -> Result<Curve> {
        let f = Field::new(&P25519)?;
        let bytes = decode_hex;
        let d = f.from_be(&bytes(
            "52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3",
        ));
        let d2 = f.add(&d, &d);
        let x = f.from_be(&bytes(
            "216936d3cd6e53fec0a4e231fdd6dc5c692cc7609525a7b2c9562d608f25d51a",
        ));
        let y = f.from_be(&bytes(
            "6666666666666666666666666666666666666666666666666666666666666658",
        ));
        // With Z = 1 the extended coordinate is simply T = X*Y.
        let base = Point {
            t: f.mul(&x, &y),
            x,
            y,
            z: f.one(),
        };
        let order = Field::new(&ED25519_ORDER)?;
        Ok(Curve {
            kind: Kind::Ed25519,
            f,
            d,
            d2,
            base,
            b: vec![0],
            order,
        })
    }

    fn p256() -> Result<Curve> {
        let f = Field::new(&P256_PRIME)?;
        let base = Point {
            x: f.from_be(&decode_hex(
                "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
            )),
            y: f.from_be(&decode_hex(
                "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
            )),
            z: f.one(),
            t: f.one(),
        };
        let b = f.from_be(&decode_hex(
            "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
        ));
        let order = Field::new(&P256_ORDER)?;
        Ok(Curve {
            kind: Kind::P256,
            f,
            d: vec![0],
            d2: vec![0],
            base,
            b,
            order,
        })
    }

    fn identity(&self) -> Point {
        match self.kind {
            Kind::Ed25519 => Point {
                x: self.f.zero(),
                y: self.f.one(),
                z: self.f.one(),
                t: self.f.zero(),
            },
            Kind::P256 => Point {
                x: self.f.one(),
                y: self.f.one(),
                z: self.f.zero(),
                t: self.f.zero(),
            },
        }
    }

    fn is_infinity(&self, p: &Point) -> bool {
        match self.kind {
            Kind::Ed25519 => self.f.is_zero(&p.z),
            Kind::P256 => self.f.is_zero(&p.z),
        }
    }

    fn double(&self, p: &Point) -> Point {
        match self.kind {
            Kind::Ed25519 => {
                // dbl-2008-hwcd for a = -1.
                let f = &self.f;
                let a = f.square(&p.x);
                let b = f.square(&p.y);
                let c = f.square(&p.z);
                let c = f.add(&c, &c);
                let d = f.sub(&f.zero(), &a); // a*A with a = -1
                let e = {
                    let sum = f.add(&p.x, &p.y);
                    let sq = f.square(&sum);
                    f.sub(&f.sub(&sq, &a), &b)
                };
                let g = f.add(&d, &b);
                let f_ = f.sub(&g, &c);
                let h = f.sub(&d, &b);
                Point {
                    x: f.mul(&e, &f_),
                    y: f
                        .mul(&g, &h),
                    t: f.mul(&e, &h),
                    z: f.mul(&f_, &g),
                }
            }
            Kind::P256 => {
                // Jacobian doubling with a = -3.
                let f = &self.f;
                if self.f.is_zero(&p.z) {
                    return p.clone();
                }
                let yy = f.square(&p.y);
                let yyyy = f.square(&yy);
                let zz = f.square(&p.z);
                // M = 3*(X - Z^2)*(X + Z^2) since a = -3
                let m = {
                    let d1 = f.sub(&p.x, &zz);
                    let d2 = f.add(&p.x, &zz);
                    let prod = f.mul(&d1, &d2);
                    let three = f.from_u32(3);
                    f.mul(&prod, &three)
                };
                // S = 4*X*Y^2
                let s = {
                    let xy2 = f.mul(&p.x, &yy);
                    let four = f.from_u32(4);
                    f.mul(&xy2, &four)
                };
                let x3 = f.sub(&f.square(&m), &f.add(&s, &s));
                let y3 = {
                    let t = f.sub(&s, &x3);
                    let mt = f.mul(&m, &t);
                    let eight = f.from_u32(8);
                    let e = f.mul(&yyyy, &eight);
                    f.sub(&mt, &e)
                };
                let z3 = {
                    let yz = f.mul(&p.y, &p.z);
                    let two = f.from_u32(2);
                    f.mul(&yz, &two)
                };
                Point {
                    x: x3,
                    y: y3,
                    z: z3,
                    t: self.f.one(),
                }
            }
        }
    }

    fn add(&self, p: &Point, q: &Point) -> Point {
        match self.kind {
            Kind::Ed25519 => {
                // add-2008-hwcd-3
                let f = &self.f;
                let a = f.mul(&f.sub(&p.y, &p.x), &f.sub(&q.y, &q.x));
                let b = f.mul(&f.add(&p.y, &p.x), &f.add(&q.y, &q.x));
                let c = f.mul(&f.mul(&p.t, &self.d2), &q.t);
                let d = {
                    let zz = f.mul(&p.z, &q.z);
                    let two = f.from_u32(2);
                    f.mul(&zz, &two)
                };
                let e = f.sub(&b, &a);
                let f_ = f.sub(&d, &c);
                let g = f.add(&d, &c);
                let h = f.add(&b, &a);
                Point {
                    x: f.mul(&e, &f_),
                    y: f.mul(&g, &h),
                    t: f.mul(&e, &h),
                    z: f.mul(&f_, &g),
                }
            }
            Kind::P256 => {
                // Jacobian addition (add-2007-bl).
                let f = &self.f;
                if f.is_zero(&p.z) {
                    return q.clone();
                }
                if f.is_zero(&q.z) {
                    return p.clone();
                }
                let z1z1 = f.square(&p.z);
                let z2z2 = f.square(&q.z);
                let u1 = f.mul(&p.x, &z2z2);
                let u2 = f.mul(&q.x, &z1z1);
                let s1 = f.mul(&f.mul(&p.y, &q.z), &z2z2);
                let s2 = f.mul(&f.mul(&q.y, &p.z), &z1z1);
                if f.eq(&u1, &u2) {
                    if f.eq(&s1, &s2) {
                        return self.double(p);
                    }
                    return self.identity();
                }
                let h = f.sub(&u2, &u1);
                let i = {
                    let two_h = f.add(&h, &h);
                    f.square(&two_h)
                };
                let j = f.mul(&h, &i);
                let r = {
                    let d = f.sub(&s2, &s1);
                    f.add(&d, &d)
                };
                let v = f.mul(&u1, &i);
                let x3 = f.sub(&f.sub(&f.square(&r), &j), &f.add(&v, &v));
                let y3 = f.sub(
                    &f.mul(&r, &f.sub(&v, &x3)),
                    &f.mul(&f.mul(&s1, &j), &f.from_u32(2)),
                );
                let z3 = {
                    let t = f.add(&p.z, &q.z);
                    let sq = f.square(&t);
                    let s = f.sub(&f.sub(&sq, &z1z1), &z2z2);
                    f.mul(&s, &h)
                };
                Point {
                    x: x3,
                    y: y3,
                    z: z3,
                    t: f.one(),
                }
            }
        }
    }

    fn mul(&self, p: &Point, scalar: &Limbs) -> Point {
        let mut acc = self.identity();
        for limb in scalar.iter().rev() {
            for bit in (0..32).rev() {
                acc = self.double(&acc);
                if (limb >> bit) & 1 == 1 {
                    acc = self.add(&acc, p);
                }
            }
        }
        acc
    }

    fn mul_base(&self, scalar: &Limbs) -> Point {
        self.mul(&self.base, scalar)
    }

    /// Affine coordinates, as big-endian bytes of the field width.
    fn affine(&self, p: &Point) -> Result<(Vec<u8>, Vec<u8>)> {
        if self.is_infinity(p) {
            return Err(Error::new("point at infinity has no affine form"));
        }
        let zinv = self.f.inv(&p.z)?;
        match self.kind {
            Kind::Ed25519 => {
                let x = self.f.mul(&p.x, &zinv);
                let y = self.f.mul(&p.y, &zinv);
                Ok((self.f.to_be(&x), self.f.to_be(&y)))
            }
            Kind::P256 => {
                let zinv2 = self.f.square(&zinv);
                let zinv3 = self.f.mul(&zinv2, &zinv);
                let x = self.f.mul(&p.x, &zinv2);
                let y = self.f.mul(&p.y, &zinv3);
                Ok((self.f.to_be(&x), self.f.to_be(&y)))
            }
        }
    }

    /// RFC 8032 point decompression.
    fn decode_point(&self, bytes: &[u8]) -> Result<Point> {
        if self.kind != Kind::Ed25519 {
            return Err(Error::new("decode_point is Ed25519 only"));
        }
        if bytes.len() != 32 {
            return Err(Error::new("Ed25519 point must be 32 bytes"));
        }
        let f = &self.f;
        // Encodings are little-endian, with the low bit of x in the top bit.
        let mut y_bytes = bytes.to_vec();
        y_bytes.reverse();
        let sign = y_bytes[0] >> 7;
        y_bytes[0] &= 0x7f;

        // Reject non-canonical y (>= p).
        if compare_be(&y_bytes, &P25519) != std::cmp::Ordering::Less {
            return Err(Error::new("Ed25519 point is not canonical"));
        }
        let y = f.from_be(&y_bytes);

        // x^2 = (y^2 - 1) / (d*y^2 + 1)
        let y2 = f.square(&y);
        let u = f.sub(&y2, &f.one());
        let v = f.add(&f.mul(&self.d, &y2), &f.one());
        let vinv = f.inv(&v)?;
        let x2 = f.mul(&u, &vinv);

        // Candidate root: x = x2^((p+3)/8)
        let mut x = f.pow(&x2, &P25519_SQRT_EXP);
        if !f.eq(&f.square(&x), &x2) {
            // Multiply by sqrt(-1) and retry, per RFC 8032.
            let sqrt_m1 = f.pow(&f.from_u32(2), &P25519_SQRT_M1_EXP);
            let candidate = f.mul(&x, &sqrt_m1);
            if f.eq(&f.square(&candidate), &x2) {
                x = candidate;
            } else {
                return Err(Error::new("Ed25519 point is not on the curve"));
            }
        }
        if f.is_zero(&x) && sign == 1 {
            return Err(Error::new("Ed25519 point has an invalid sign bit"));
        }
        if (f.is_odd(&x) as u8) != sign {
            x = f.sub(&f.zero(), &x);
        }
        let t = f.mul(&x, &y);
        Ok(Point { x, y, z: f.one(), t })
    }

    /// RFC 8032 point compression: little-endian y with the low bit of x on top.
    fn encode_point(&self, p: &Point) -> Vec<u8> {
        let (x, y) = self.affine(p).expect("a curve point cannot be infinity here");
        let mut bytes = y;
        bytes.reverse();
        bytes[0] |= (x[x.len() - 1] & 1) << 7;
        bytes
    }

    /// Decode an uncompressed P-256 point given its x and y.
    fn point_from_xy(&self, x: &[u8], y: &[u8]) -> Result<Point> {
        let f = &self.f;
        let px = f.from_be(x);
        let py = f.from_be(y);
        // y^2 == x^3 - 3x + b
        let left = f.square(&py);
        let x3 = f.mul(&f.square(&px), &px);
        let three_x = f.mul(&px, &f.from_u32(3));
        let right = f.add(&f.sub(&x3, &three_x), &self.b);
        if !f.eq(&left, &right) {
            return Err(Error::new("P-256 public key is not on the curve"));
        }
        Ok(Point {
            x: px,
            y: py,
            z: f.one(),
            t: f.one(),
        })
    }

    /// Reduce a little-endian integer (a hash) modulo the group order.
    fn reduce_mod_order(&self, hash: &[u8]) -> Limbs {
        let mut acc = self.order.zero();
        for byte in hash.iter().rev() {
            acc = double_add(&self.order, &acc, *byte);
        }
        acc
    }

    fn scalar_is_canonical(&self, s: &[u32]) -> bool {
        let order = crate::bigint::from_be_bytes(&ED25519_ORDER);
        let mut s = s.to_vec();
        s.resize(order.len(), 0);
        compare_limbs(&s, &order) == std::cmp::Ordering::Less
    }
}

const P25519: [u8; 32] = [
    0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xed,
];

/// (p + 3) / 8, big-endian: the square-root exponent for p = 2^255 - 19.
const P25519_SQRT_EXP: [u8; 32] = [
    0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
];

/// (p - 1) / 4, big-endian; 2^((p-1)/4) is sqrt(-1).
const P25519_SQRT_M1_EXP: [u8; 32] = [
    0x1f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfb,
];

const P256_PRIME: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
];

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

fn compare_be(a: &[u8], b: &[u8]) -> std::cmp::Ordering {
    let len = a.len().max(b.len());
    for i in 0..len {
        let x = if i < len - a.len() { 0 } else { a[i - (len - a.len())] };
        let y = if i < len - b.len() { 0 } else { b[i - (len - b.len())] };
        if x != y {
            return x.cmp(&y);
        }
    }
    std::cmp::Ordering::Equal
}

fn compare_limbs(a: &[u32], b: &[u32]) -> std::cmp::Ordering {
    let len = a.len().max(b.len());
    for i in (0..len).rev() {
        let x = a.get(i).copied().unwrap_or(0);
        let y = b.get(i).copied().unwrap_or(0);
        if x != y {
            return x.cmp(&y);
        }
    }
    std::cmp::Ordering::Equal
}

fn sub_limbs(a: &mut [u32], b: &[u32]) {
    let mut borrow = 0u64;
    for i in 0..a.len() {
        let rhs = b.get(i).copied().unwrap_or(0) as u64 + borrow;
        let lhs = a[i] as u64;
        if lhs >= rhs {
            a[i] = (lhs - rhs) as u32;
            borrow = 0;
        } else {
            a[i] = (lhs + (1u64 << 32) - rhs) as u32;
            borrow = 1;
        }
    }
}

fn scalar_from_le(bytes: &[u8]) -> Limbs {
    let mut limbs = Vec::with_capacity(bytes.len() / 4 + 1);
    for chunk in bytes.chunks(4) {
        let mut value = 0u32;
        for (i, byte) in chunk.iter().enumerate() {
            value |= (*byte as u32) << (8 * i);
        }
        limbs.push(value);
    }
    limbs
}

/// `acc * 256 + byte`, reduced modulo `order`.
fn double_add(order: &Field, acc: &[u32], byte: u8) -> Limbs {
    let mut acc = acc.to_vec();
    for bit in (0..8).rev() {
        acc = double_add_bit(order, &acc, ((byte >> bit) & 1) as u32);
    }
    acc
}

/// `acc * 2 + bit`, reduced modulo `order`.
fn double_add_bit(order: &Field, acc: &[u32], bit: u32) -> Limbs {
    let k = order.limbs();
    let mut wide = vec![0u32; k + 1];
    let mut carry = bit;
    for i in 0..k {
        let value = acc.get(i).copied().unwrap_or(0);
        wide[i] = (value << 1) | carry;
        carry = value >> 31;
    }
    wide[k] = carry;

    let mut modulus = crate::bigint::from_be_bytes(order.modulus());
    modulus.resize(k + 1, 0);
    if compare_limbs(&wide, &modulus) != std::cmp::Ordering::Less {
        sub_limbs(&mut wide, &modulus);
    }
    wide.truncate(k);
    wide
}

/// Reduce a big-endian value taken from `from`'s field modulo `target`.
fn reduce_bytes_mod(from: &Field, value_be: &[u8], target: &Field) -> Result<Vec<u8>> {
    let canonical = from.to_be(&from.from_be(value_be));
    let mut acc = target.zero();
    for byte in &canonical {
        acc = double_add(target, &acc, *byte);
    }
    Ok(target.to_be(&acc))
}

fn decode_hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("hex fixture"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex_to_bytes(text: &str) -> Vec<u8> {
        decode_hex(text)
    }

    /// RFC 8032 §7.1 test vectors.
    #[test]
    fn ed25519_rfc8032_vectors() {
        let cases: [(&str, &str, &str, &str); 3] = [
            (
                "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
                "",
                "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
                "",
            ),
            (
                "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
                "72",
                "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
                "72",
            ),
            (
                "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
                "af82",
                "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
                "af82",
            ),
        ];

        for (public, message, signature, _) in cases {
            let public = hex_to_bytes(public);
            let message = hex_to_bytes(message);
            let signature = hex_to_bytes(signature);
            ed25519_verify(&public, &message, &signature)
                .expect("RFC 8032 vector must verify");

            // Flipping any byte of the message or signature must fail.
            let mut bad = message.clone();
            bad.push(0);
            assert!(ed25519_verify(&public, &bad, &signature).is_err());

            let mut bad_sig = signature.clone();
            bad_sig[0] ^= 1;
            assert!(ed25519_verify(&public, &message, &bad_sig).is_err());
        }
    }

    #[test]
    fn ed25519_rejects_malformed_input() {
        assert!(ed25519_verify(&[0u8; 31], b"", &[0u8; 64]).is_err());
        assert!(ed25519_verify(&[0u8; 32], b"", &[0u8; 63]).is_err());
    }

    /// A deterministic vector (fixed key, message and nonce) cross-checked
    /// against an independent implementation.
    #[test]
    fn p256_known_answer() {
        let public = hex_to_bytes(
            "471c3e758c4904285bba7e53118ed0f524adeb0757d25bd2f8e7b0d76dfa714c\
             dd520f7aca8a8b917acc37f51de8f0c9bbe3ad858382e702dc25a12d09f7a858",
        );
        let r = hex_to_bytes("4fa289719e065f13836623231116f5a77f78731fe4e483fc96218386f896fdf4");
        let s = hex_to_bytes("d371e91139ad1f67e7840edd43c6c16e0cb765aa390de71147470e3b92c9abdf");
        let digest = digest::sha256(b"rpf p256 known answer");
        p256_verify(&public, &digest, &r, &s).expect("known answer must verify");

        // A different message, tampered signature and swapped components fail.
        let other = digest::sha256(b"rpf p256 known answer!");
        assert!(p256_verify(&public, &other, &r, &s).is_err());
        let mut bad = s.clone();
        bad[31] ^= 1;
        assert!(p256_verify(&public, &digest, &r, &bad).is_err());
        assert!(p256_verify(&public, &digest, &s, &r).is_err());
    }

    #[test]
    fn p256_rejects_a_point_off_the_curve() {
        let mut public = hex_to_bytes(
            "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
        );
        public.extend_from_slice(&hex_to_bytes(
            "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
        ));
        // On the curve, but with a nonsense signature.
        assert!(p256_verify(&public, &[0u8; 32], &[1u8; 32], &[2u8; 32]).is_err());

        public[63] ^= 1;
        assert!(p256_verify(&public, &[0u8; 32], &[1u8; 32], &[2u8; 32]).is_err());
    }
}
