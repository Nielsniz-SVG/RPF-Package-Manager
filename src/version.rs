//! RPM version comparison.
//!
//! This is a faithful reimplementation of `rpmvercmp()` from rpm's
//! `lib/rpmvercmp.c`, including the `~` (tilde: sorts *before* anything) and
//! `^` (caret: sorts *after* the shorter string) special cases introduced in
//! rpm 4.10 and 4.15 respectively. Getting this bit-identical to rpm matters:
//! any divergence silently changes which versions the solver considers newer.

use std::cmp::Ordering;

/// Compare two version strings the way rpm does.
pub fn rpmvercmp(a: &str, b: &str) -> Ordering {
    if a == b {
        return Ordering::Equal;
    }

    let one = a.as_bytes();
    let two = b.as_bytes();
    let (mut i, mut j) = (0usize, 0usize);

    loop {
        // Skip separators, but never skip over tilde/caret: they are
        // significant and handled explicitly below.
        while i < one.len() && !is_segment_start(one[i]) {
            i += 1;
        }
        while j < two.len() && !is_segment_start(two[j]) {
            j += 1;
        }

        // Tilde: "1.0~rc1" is older than "1.0".
        let one_tilde = i < one.len() && one[i] == b'~';
        let two_tilde = j < two.len() && two[j] == b'~';
        if one_tilde || two_tilde {
            if !one_tilde {
                return Ordering::Greater;
            }
            if !two_tilde {
                return Ordering::Less;
            }
            i += 1;
            j += 1;
            continue;
        }

        // Caret: "1.0^git1" is newer than "1.0", but older than "1.0.1".
        let one_caret = i < one.len() && one[i] == b'^';
        let two_caret = j < two.len() && two[j] == b'^';
        if one_caret || two_caret {
            if i >= one.len() {
                // `one` ended at a segment boundary; `two` has a caret, which
                // always sorts *after* the end of the other version.
                return Ordering::Less;
            }
            if j >= two.len() {
                return Ordering::Greater;
            }
            if !one_caret {
                return Ordering::Greater;
            }
            if !two_caret {
                return Ordering::Less;
            }
            i += 1;
            j += 1;
            continue;
        }

        if i >= one.len() || j >= two.len() {
            break;
        }

        // Take one segment from each: either a run of digits or a run of
        // letters. Numeric segments always beat alphabetic ones.
        let start_one = i;
        let start_two = j;
        let numeric = one[start_one].is_ascii_digit();
        if numeric {
            while i < one.len() && one[i].is_ascii_digit() {
                i += 1;
            }
            while j < two.len() && two[j].is_ascii_digit() {
                j += 1;
            }
        } else {
            while i < one.len() && one[i].is_ascii_alphabetic() {
                i += 1;
            }
            while j < two.len() && two[j].is_ascii_alphabetic() {
                j += 1;
            }
        }
        let seg_one = &one[start_one..i];
        let seg_two = &two[start_two..j];

        // `two` has the other segment type here: numeric wins over alpha.
        if seg_two.is_empty() {
            return if numeric {
                Ordering::Greater
            } else {
                Ordering::Less
            };
        }

        if numeric {
            // Strip leading zeros so "007" == "7".
            let mut s1 = seg_one;
            while !s1.is_empty() && s1[0] == b'0' {
                s1 = &s1[1..];
            }
            let mut s2 = seg_two;
            while !s2.is_empty() && s2[0] == b'0' {
                s2 = &s2[1..];
            }
            // After stripping, a longer number is bigger ("10" > "9").
            if s1.len() != s2.len() {
                return s1.len().cmp(&s2.len());
            }
            let ord = s1.cmp(s2);
            if ord != Ordering::Equal {
                return ord;
            }
        } else {
            let ord = seg_one.cmp(seg_two);
            if ord != Ordering::Equal {
                return ord;
            }
        }
    }

    if i >= one.len() && j >= two.len() {
        Ordering::Equal
    } else if i >= one.len() {
        Ordering::Less
    } else {
        Ordering::Greater
    }
}

#[inline]
fn is_segment_start(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'~' || b == b'^'
}

/// A full epoch:version-release triple.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Evr {
    pub epoch: u32,
    pub version: String,
    /// `None` means "no release given" — relevant for dependency matching,
    /// where `foo >= 1.0` deliberately ignores the release of candidates.
    pub release: Option<String>,
}

impl Evr {
    /// Parse `[epoch:]version[-release]`.
    pub fn parse(s: &str) -> Evr {
        let s = s.trim();
        let (epoch, rest) = match s.find(':') {
            Some(idx) if s[..idx].chars().all(|c| c.is_ascii_digit()) && idx > 0 => {
                (s[..idx].parse::<u32>().unwrap_or(0), &s[idx + 1..])
            }
            _ => (0, s),
        };
        // The release starts at the *last* '-', since versions may contain '-'
        // only in malformed data but releases conventionally come last.
        match rest.rfind('-') {
            Some(idx) => Evr {
                epoch,
                version: rest[..idx].to_string(),
                release: Some(rest[idx + 1..].to_string()),
            },
            None => Evr {
                epoch,
                version: rest.to_string(),
                release: None,
            },
        }
    }

    /// Parse a version that must not carry a release (rpm's `EVR` in a
    /// `Provides`, where the release is meaningful only if explicitly set).
    pub fn to_string_full(&self) -> String {
        let mut out = String::new();
        if self.epoch != 0 {
            out.push_str(&self.epoch.to_string());
            out.push(':');
        }
        out.push_str(&self.version);
        if let Some(rel) = &self.release {
            out.push('-');
            out.push_str(rel);
        }
        out
    }

    /// Total ordering over the full epoch:version-release.
    pub fn cmp_full(&self, other: &Evr) -> Ordering {
        match self.epoch.cmp(&other.epoch) {
            Ordering::Equal => {}
            ord => return ord,
        }
        match rpmvercmp(&self.version, &other.version) {
            Ordering::Equal => {}
            ord => return ord,
        }
        let empty = String::new();
        rpmvercmp(
            self.release.as_ref().unwrap_or(&empty),
            other.release.as_ref().unwrap_or(&empty),
        )
    }

    /// Compare as a dependency does: if `self` (the requirement) specifies no
    /// release, the candidate's release is ignored.
    pub fn cmp_dep(&self, other: &Evr) -> Ordering {
        match self.epoch.cmp(&other.epoch) {
            Ordering::Equal => {}
            ord => return ord,
        }
        match rpmvercmp(&self.version, &other.version) {
            Ordering::Equal => {}
            ord => return ord,
        }
        match &self.release {
            None => Ordering::Equal,
            Some(rel) => {
                let empty = String::new();
                rpmvercmp(rel, other.release.as_ref().unwrap_or(&empty))
            }
        }
    }
}

impl std::fmt::Display for Evr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_string_full())
    }
}

impl PartialOrd for Evr {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Evr {
    fn cmp(&self, other: &Self) -> Ordering {
        self.cmp_full(other)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cmp::Ordering::{Equal, Greater, Less};

    #[test]
    fn rpmvercmp_matches_rpm_test_suite() {
        // Cases lifted from rpm's own tests/rpmvercmp.at.
        let cases: &[(&str, &str, Ordering)] = &[
            ("1.0", "1.0", Equal),
            ("1.0", "2.0", Less),
            ("2.0", "1.0", Greater),
            ("2.0.1", "2.0", Greater),
            ("2.0.1", "2.0.1", Equal),
            ("2.1", "2.0.1", Greater),
            ("2.0.1a", "2.0.1", Greater),
            ("2.0.1a", "2.0.1a", Equal),
            ("5.5p1", "5.5p1", Equal),
            ("5.5p1", "5.5p2", Less),
            ("5.5p10", "5.5p1", Greater),
            ("10xyz", "10.1xyz", Less),
            ("xyz10", "xyz10.1", Less),
            ("xyz.4", "xyz.4", Equal),
            ("xyz.4", "8", Less),
            ("8", "xyz.4", Greater),
            ("xyz.4", "2", Less),
            ("5.5p2", "5.6p1", Less),
            ("5.6p1", "6.5p1", Less),
            ("6.0.rc1", "6.0", Greater),
            ("10b2", "10a1", Greater),
            ("10a2", "10b2", Less),
            ("1.0aa", "1.0aa", Equal),
            ("1.0a", "1.0aa", Less),
            ("1.0aa", "1.0a", Greater),
            ("10.0001", "10.0001", Equal),
            ("10.0001", "10.1", Equal),
            ("10.1", "10.0001", Equal),
            ("10.0001", "10.0039", Less),
            ("10.0039", "10.0001", Greater),
            ("4.999.9", "5.0", Less),
            ("5.0", "4.999.9", Greater),
            ("20101121", "20101122", Less),
            ("20101122", "20101121", Greater),
            ("2_0", "2_0", Equal),
            ("2.0", "2_0", Equal),
            ("2_0", "2.0", Equal),
            ("a", "a", Equal),
            ("a+", "a+", Equal),
            ("a+", "a_", Equal),
            ("+a", "_a", Equal),
            ("+", "_", Equal),
            ("a", "a+", Equal),
            ("a+", "a", Equal),
            ("1.0~rc1", "1.0", Less),
            ("1.0~rc1", "1.0~rc1", Equal),
            ("1.0~rc1", "1.0~rc2", Less),
            ("1.0~rc1~git123", "1.0~rc1", Less),
            ("1.0~rc1~git123", "1.0~rc1~git123", Equal),
            ("1.0~rc1", "1.0^git1", Less),
            ("1.0^git1", "1.0~rc1", Greater),
            ("1.0^", "1.0", Greater),
            ("1.0^", "1.0^", Equal),
            ("1.0^git1", "1.0", Greater),
            ("1.0^git1", "1.0^git1", Equal),
            ("1.0^git1", "1.0^git2", Less),
            ("1.0^20160101", "1.0.1", Less),
            ("1.0^20160101", "1.0^20160101", Equal),
            ("1.0", "1.0^20160101", Less),
            ("1.0^20160101^git1", "1.0^20160101", Greater),
            ("1.0~~", "1.0~", Less),
            ("1.0~~", "1.0", Less),
            ("1.0~", "1.0", Less),
            ("1.0~~a", "1.0~a", Less),
        ];
        for (a, b, expected) in cases {
            assert_eq!(
                rpmvercmp(a, b),
                *expected,
                "rpmvercmp({:?}, {:?}) should be {:?}",
                a,
                b,
                expected
            );
            // Antisymmetry must hold for every pair.
            assert_eq!(
                rpmvercmp(b, a),
                expected.out_reverse(),
                "rpmvercmp({:?}, {:?}) asymmetric",
                b,
                a
            );
        }
    }

    #[test]
    fn evr_parsing() {
        let e = Evr::parse("1:2.3-4");
        assert_eq!(e.epoch, 1);
        assert_eq!(e.version, "2.3");
        assert_eq!(e.release.as_deref(), Some("4"));

        let e = Evr::parse("2.3");
        assert_eq!(e.epoch, 0);
        assert_eq!(e.version, "2.3");
        assert_eq!(e.release, None);

        // Not an epoch: the prefix is not numeric.
        let e = Evr::parse("a:2.3");
        assert_eq!(e.epoch, 0);
        assert_eq!(e.version, "a:2.3");

        assert_eq!(Evr::parse("1:2.3-4").to_string_full(), "1:2.3-4");
        assert_eq!(Evr::parse("2.3").to_string_full(), "2.3");
    }

    #[test]
    fn evr_epoch_dominates() {
        assert_eq!(Evr::parse("1:0.1-1").cmp_full(&Evr::parse("9.9-9")), Greater);
        assert_eq!(Evr::parse("0.1-1").cmp_full(&Evr::parse("0:0.1-1")), Equal);
    }

    #[test]
    fn dep_comparison_ignores_release_when_unspecified() {
        let req = Evr::parse("1.2.3");
        assert_eq!(req.cmp_dep(&Evr::parse("1.2.3-99.fc41")), Equal);
        // ...but respects it when the requirement names one.
        let req = Evr::parse("1.2.3-5");
        assert_eq!(req.cmp_dep(&Evr::parse("1.2.3-4")), Greater);
    }

    #[test]
    fn sorting_versions() {
        let mut v = ["1.10", "1.9", "1.0~rc1", "1.0", "2.0", "1.0^git1"]
            .iter()
            .map(|s| Evr::parse(s))
            .collect::<Vec<_>>();
        v.sort();
        let got: Vec<String> = v.iter().map(|e| e.to_string_full()).collect();
        assert_eq!(
            got,
            ["1.0~rc1", "1.0", "1.0^git1", "1.9", "1.10", "2.0"]
        );
    }

    trait Reverse {
        fn out_reverse(self) -> Self;
    }
    impl Reverse for Ordering {
        fn out_reverse(self) -> Self {
            match self {
                Less => Greater,
                Greater => Less,
                Equal => Equal,
            }
        }
    }
}
