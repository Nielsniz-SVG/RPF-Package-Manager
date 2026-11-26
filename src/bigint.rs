//! Minimal big integer arithmetic, enough for RSA signature verification.
//!
//! Only what a verifier needs: modular exponentiation with a public exponent.
//! There is no secret-dependent branching here, so Montgomery multiplication
//! with a fixed window-free square-and-multiply is fine.
//!
//! Numbers are fixed-size little-endian `u32` limb vectors, always the same
//! length as the modulus so that comparisons and subtractions stay simple.

use crate::{Error, Result};

/// Little-endian `u32` limbs.
pub type Limbs = Vec<u32>;

pub fn from_be_bytes(bytes: &[u8]) -> Limbs {
    let mut limbs: Limbs = bytes
        .rchunks(4)
        .map(|chunk| {
            let mut v = 0u32;
            for b in chunk {
                v = (v << 8) | *b as u32;
            }
            v
        })
        .collect();
    if limbs.is_empty() {
        limbs.push(0);
    }
    limbs
}

/// Big-endian bytes, left-padded with zeros to `len`.
pub fn to_be_bytes(limbs: &[u32], len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len];
    for (i, limb) in limbs.iter().enumerate() {
        let start = len.saturating_sub((i + 1) * 4);
        let end = len.saturating_sub(i * 4);
        if start == end {
            break;
        }
        let buf = limb.to_be_bytes();
        let take = end - start;
        out[start..end].copy_from_slice(&buf[4 - take..]);
    }
    out
}

pub fn bit_len(limbs: &[u32]) -> usize {
    for (i, limb) in limbs.iter().enumerate().rev() {
        if *limb != 0 {
            return i * 32 + (32 - limb.leading_zeros() as usize);
        }
    }
    0
}

fn cmp(a: &[u32], b: &[u32]) -> std::cmp::Ordering {
    for i in (0..a.len().max(b.len())).rev() {
        let x = a.get(i).copied().unwrap_or(0);
        let y = b.get(i).copied().unwrap_or(0);
        if x != y {
            return x.cmp(&y);
        }
    }
    std::cmp::Ordering::Equal
}

/// `a -= b`, assuming `a >= b`.
fn sub_assign(a: &mut [u32], b: &[u32]) {
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

/// `-n^-1 mod 2^32`, the Montgomery constant, via Newton's iteration.
fn mont_n0inv(n0: u32) -> u32 {
    let mut inv = 1u32;
    for _ in 0..5 {
        inv = inv.wrapping_mul(2u32.wrapping_sub(n0.wrapping_mul(inv)));
    }
    inv.wrapping_neg()
}

/// CIOS Montgomery multiplication: returns `a * b * R^-1 mod n`, with
/// `R = 2^(32 * n.len())`.
fn mont_mul(a: &[u32], b: &[u32], n: &[u32], n0inv: u32) -> Limbs {
    let k = n.len();
    let mut t = vec![0u32; k + 2];

    for i in 0..k {
        // t += a * b[i]
        let mut carry = 0u64;
        for j in 0..k {
            let sum = t[j] as u64 + (a[j] as u64) * (b[i] as u64) + carry;
            t[j] = sum as u32;
            carry = sum >> 32;
        }
        let sum = t[k] as u64 + carry;
        t[k] = sum as u32;
        t[k + 1] = t[k + 1].wrapping_add((sum >> 32) as u32);

        // t += m * n, chosen so the low limb becomes zero
        let m = (t[0].wrapping_mul(n0inv)) as u32;
        let mut carry = 0u64;
        for j in 0..k {
            let sum = t[j] as u64 + (m as u64) * (n[j] as u64) + carry;
            t[j] = sum as u32;
            carry = sum >> 32;
        }
        let sum = t[k] as u64 + carry;
        t[k] = sum as u32;
        t[k + 1] = t[k + 1].wrapping_add((sum >> 32) as u32);

        // Divide by R: drop the now-zero low limb.
        t.remove(0);
        t.push(0);
    }

    // The CIOS invariant leaves `t < 2n`, so one conditional subtraction is
    // enough - but it must consider the extra limbs, because an RSA modulus
    // with its top bit set makes `t` wider than `n`.
    reduce_once(&mut t, n);
    t.truncate(k);
    t
}

/// Subtract `n` from `t` when `t >= n`, comparing over the wider of the two.
///
/// Requires `t < 2n`.
fn reduce_once(t: &mut Limbs, n: &[u32]) {
    let mut wide_n = n.to_vec();
    if wide_n.len() < t.len() {
        wide_n.resize(t.len(), 0);
    }
    let mut wide_t = t.clone();
    wide_t.resize(wide_n.len(), 0);
    if cmp(&wide_t, &wide_n) != std::cmp::Ordering::Less {
        sub_assign(&mut wide_t, &wide_n);
    }
    *t = wide_t;
}

/// `2^exponent mod n`, by repeated doubling. Only used for the Montgomery
/// constants, so the loop count is small (at most 64 * 128 iterations).
fn pow2_mod(exponent: usize, n: &[u32]) -> Limbs {
    // One spare limb holds the carry out of a doubling, which happens whenever
    // the modulus has its top bit set (every full-size RSA modulus does).
    let mut x = vec![0u32; n.len() + 1];
    x[0] = 1;
    for _ in 0..exponent {
        let mut carry = 0u32;
        for limb in x.iter_mut() {
            let next = *limb >> 31;
            *limb = (*limb << 1) | carry;
            carry = next;
        }
        reduce_once(&mut x, n);
    }
    x.truncate(n.len());
    x
}

/// `base^exponent mod modulus`.
///
/// `base` must already be reduced (RSA signatures always are: the MPI cannot
/// exceed the modulus), and the modulus must be odd.
pub fn mod_exp(base: &[u32], exponent: &[u32], modulus: &[u32]) -> Result<Limbs> {
    let k = modulus.len();
    if modulus[0] & 1 == 0 {
        return Err(Error::new("RSA modulus must be odd"));
    }
    if base.len() > k || cmp(&pad(base, k), modulus) != std::cmp::Ordering::Less {
        return Err(Error::new("RSA value is not smaller than the modulus"));
    }
    let base = pad(base, k);
    let n0inv = mont_n0inv(modulus[0]);
    let r2 = pow2_mod(64 * k, modulus);

    // Convert into Montgomery form: aR mod n = mont_mul(a, R^2).
    let a_mont = mont_mul(&base, &r2, modulus, n0inv);
    let one = {
        let mut v = vec![0u32; k];
        v[0] = 1;
        v
    };

    let mut acc = one.clone();
    // acc starts as 1 (plain), which equals R^-1 in Montgomery terms, so
    // squaring it as mont_mul(1,1) would give R^-1, not 1. Convert first.
    acc = mont_mul(&acc, &r2, modulus, n0inv);

    let bits = bit_len(exponent);
    for bit in (0..bits).rev() {
        acc = mont_mul(&acc, &acc.clone(), modulus, n0inv);
        if (exponent[bit / 32] >> (bit % 32)) & 1 == 1 {
            acc = mont_mul(&acc, &a_mont, modulus, n0inv);
        }
    }

    // Convert out of Montgomery form.
    Ok(mont_mul(&acc, &one, modulus, n0inv))
}

fn pad(value: &[u32], len: usize) -> Limbs {
    let mut out = value.to_vec();
    out.resize(len, 0);
    out
}

/// A prime modulus with Montgomery arithmetic, for elliptic curve work.
///
/// Values stay in the ordinary (non-Montgomery) domain at this level: the
/// conversions happen inside [`Field::mul`] and [`Field::pow`]. That costs a
/// couple of multiplications per operation but keeps the curve code readable,
/// and verification is only a few thousand field operations.
#[derive(Clone)]
pub struct Field {
    n: Limbs,
    n0inv: u32,
    r2: Limbs,
    one_mont: Limbs,
    n_bytes: Vec<u8>,
}

impl Field {
    pub fn new(modulus_be: &[u8]) -> Result<Field> {
        let n = from_be_bytes(modulus_be);
        if n.first().copied().unwrap_or(0) & 1 == 0 {
            return Err(Error::new("field modulus must be odd"));
        }
        let n0inv = mont_n0inv(n[0]);
        let r2 = pow2_mod(64 * n.len(), &n);
        let mut one = vec![0u32; n.len()];
        one[0] = 1;
        let one_mont = mont_mul(&one, &r2, &n, n0inv);
        Ok(Field {
            n,
            n0inv,
            r2,
            one_mont,
            n_bytes: modulus_be.to_vec(),
        })
    }

    pub fn limbs(&self) -> usize {
        self.n.len()
    }

    pub fn byte_len(&self) -> usize {
        self.n_bytes.len()
    }

    pub fn modulus(&self) -> &[u8] {
        &self.n_bytes
    }

    /// Big-endian bytes into field elements, zero-extended to full width.
    pub fn from_be(&self, bytes: &[u8]) -> Limbs {
        let mut v = from_be_bytes(bytes);
        v.resize(self.n.len(), 0);
        v
    }

    pub fn to_be(&self, v: &Limbs) -> Vec<u8> {
        to_be_bytes(v, self.n.len() * 4)
    }

    pub fn zero(&self) -> Limbs {
        vec![0u32; self.n.len()]
    }

    pub fn one(&self) -> Limbs {
        let mut v = self.zero();
        v[0] = 1;
        v
    }

    pub fn from_u32(&self, value: u32) -> Limbs {
        let mut v = self.zero();
        v[0] = value;
        v
    }

    pub fn is_zero(&self, a: &[u32]) -> bool {
        a.iter().all(|l| *l == 0)
    }

    pub fn eq(&self, a: &[u32], b: &[u32]) -> bool {
        cmp(&self.fit(a), &self.fit(b)) == std::cmp::Ordering::Equal
    }

    pub fn is_odd(&self, a: &[u32]) -> bool {
        a.first().copied().unwrap_or(0) & 1 == 1
    }

    fn fit(&self, a: &[u32]) -> Limbs {
        let mut v = a.to_vec();
        v.resize(self.n.len(), 0);
        v
    }

    pub fn add(&self, a: &[u32], b: &[u32]) -> Limbs {
        let a = self.fit(a);
        let b = self.fit(b);
        // One spare limb keeps the carry, which matters when the modulus has
        // its top bit set (every NIST prime does).
        let mut wide = vec![0u32; self.n.len() + 1];
        let mut carry = 0u64;
        for i in 0..a.len() {
            let sum = a[i] as u64 + b[i] as u64 + carry;
            wide[i] = sum as u32;
            carry = sum >> 32;
        }
        wide[a.len()] = carry as u32;
        self.reduce_wide(wide)
    }

    pub fn sub(&self, a: &[u32], b: &[u32]) -> Limbs {
        let a = self.fit(a);
        let b = self.fit(b);
        let mut wide = vec![0u32; self.n.len() + 1];
        wide[..a.len()].copy_from_slice(&a);
        let mut n_wide = self.n.clone();
        n_wide.push(0);
        // a - b + n, which is in [0, 2n) because both inputs are reduced.
        add_assign(&mut wide, &n_wide);
        sub_assign(&mut wide, &b);
        self.reduce_wide(wide)
    }

    /// Bring a value below `2n` back into `[0, n)` and to the modulus width.
    fn reduce_wide(&self, mut wide: Limbs) -> Limbs {
        let mut n_wide = self.n.clone();
        n_wide.resize(wide.len(), 0);
        if cmp(&wide, &n_wide) != std::cmp::Ordering::Less {
            sub_assign(&mut wide, &n_wide);
        }
        wide.truncate(self.n.len());
        wide
    }

    pub fn mul(&self, a: &[u32], b: &[u32]) -> Limbs {
        let a_m = self.to_mont(a);
        let b_m = self.to_mont(b);
        let product = mont_mul(&a_m, &b_m, &self.n, self.n0inv);
        self.from_mont(&product)
    }

    pub fn square(&self, a: &[u32]) -> Limbs {
        let a_m = self.to_mont(a);
        let squared = mont_mul(&a_m, &a_m, &self.n, self.n0inv);
        self.from_mont(&squared)
    }

    fn to_mont(&self, a: &[u32]) -> Limbs {
        let a = self.fit(a);
        mont_mul(&a, &self.r2, &self.n, self.n0inv)
    }

    fn from_mont(&self, a: &[u32]) -> Limbs {
        // Reducing by R^-1 means multiplying by 1 in the Montgomery domain's
        // ordinary representation, *not* by `one_mont` (which is R itself).
        let one = self.one();
        mont_mul(&self.fit(a), &one, &self.n, self.n0inv)
    }

    /// `a^exponent`, with the exponent as big-endian bytes.
    pub fn pow(&self, a: &[u32], exponent: &[u8]) -> Limbs {
        // Work entirely in the Montgomery domain: one conversion in, one out.
        let base = self.to_mont(a);
        let mut acc = self.one_mont.clone();
        let mut started = false;
        for byte in exponent {
            for bit in (0..8).rev() {
                if started {
                    acc = mont_mul(&acc, &acc.clone(), &self.n, self.n0inv);
                }
                if (byte >> bit) & 1 == 1 {
                    acc = mont_mul(&acc, &base, &self.n, self.n0inv);
                    started = true;
                }
            }
        }
        self.from_mont(&acc)
    }

    /// Modular inverse by Fermat's little theorem, valid for prime moduli.
    pub fn inv(&self, a: &[u32]) -> Result<Limbs> {
        if self.is_zero(a) {
            return Err(Error::new("cannot invert zero"));
        }
        // n - 2
        let mut exponent = self.n_bytes.clone();
        let mut borrow = 2u16;
        for byte in exponent.iter_mut().rev() {
            let value = *byte as u16;
            if value >= borrow {
                *byte = (value - borrow) as u8;
                break;
            }
            *byte = (value + 256 - borrow) as u8;
            borrow = 1;
        }
        Ok(self.pow(a, &exponent))
    }
}

fn add_assign(a: &mut [u32], b: &[u32]) {
    let mut carry = 0u64;
    for i in 0..a.len() {
        let sum = a[i] as u64 + b.get(i).copied().unwrap_or(0) as u64 + carry;
        a[i] = sum as u32;
        carry = sum >> 32;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn from_hex(text: &str) -> Limbs {
        let padded = if text.len() % 2 == 1 {
            format!("0{}", text)
        } else {
            text.to_string()
        };
        let bytes: Vec<u8> = (0..padded.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&padded[i..i + 2], 16).unwrap())
            .collect();
        from_be_bytes(&bytes)
    }

    fn to_hex(limbs: &[u32], len: usize) -> String {
        to_be_bytes(limbs, len)
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect()
    }

    fn num(value: u32) -> Limbs {
        vec![value]
    }

    #[test]
    fn roundtrips_bytes() {
        let value = from_hex("00ff0102030405");
        assert_eq!(to_hex(&value, 7), "00ff0102030405");
        assert_eq!(bit_len(&value), 48);
        assert_eq!(bit_len(&[0]), 0);
    }

    #[test]
    fn small_modexp() {
        // 4^13 mod 497 = 445
        assert_eq!(mod_exp(&num(4), &num(13), &num(497)).unwrap()[0], 445);
        // 2^10 mod 1001 = 23 (the modulus must be odd for Montgomery)
        assert_eq!(mod_exp(&num(2), &num(10), &num(1001)).unwrap()[0], 23);
        // x^0 = 1
        assert_eq!(mod_exp(&num(7), &num(0), &num(13)).unwrap()[0], 1);
        // 2^1 mod 3 = 2
        assert_eq!(mod_exp(&num(2), &num(1), &num(3)).unwrap()[0], 2);
    }

    #[test]
    fn fermat_little_theorem_on_a_large_prime() {
        // 2^521 - 1 is prime. a^(p-1) = 1 mod p must hold.
        let mut p = vec![0xffff_ffffu32; 17];
        // Clear everything above bit 520.
        p[16] = 0x0000_01ff;
        let mut exp = p.clone();
        sub_assign(&mut exp, &num(1));
        let result = mod_exp(&num(3), &exp, &p).unwrap();
        assert_eq!(result[0], 1);
        assert!(result[1..].iter().all(|l| *l == 0));
    }

    #[test]
    fn rejects_even_modulus_and_oversized_base() {
        assert!(mod_exp(&num(2), &num(3), &num(4)).is_err());
        assert!(mod_exp(&num(9), &num(3), &num(7)).is_err());
    }

    #[test]
    fn subtraction_borrows_correctly() {
        let mut a = from_hex("0100000000");
        let b = from_hex("0000000001");
        sub_assign(&mut a, &b);
        assert_eq!(to_hex(&a, 5), "00ffffffff");
    }
}
