//! Dependency semantics: capability names, version constraints, and Fedora's
//! "rich" dependencies (`(a if b)`, `(a or b)`, `(a without b)`, ...).

use crate::version::Evr;
use std::cmp::Ordering;
use std::fmt;

/// A tiny stand-in for the `bitflags` crate (RPF takes no dependencies).
macro_rules! bitflags_like {
    (
        $(#[$meta:meta])*
        pub struct $name:ident: $ty:ty {
            $(const $flag:ident = $value:expr;)*
        }
    ) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Default, PartialEq, Eq)]
        pub struct $name(pub $ty);

        impl $name {
            $(pub const $flag: $name = $name($value);)*

            pub const NONE: $name = $name(0);

            pub fn bits(self) -> $ty { self.0 }

            pub fn contains(self, other: $name) -> bool {
                (self.0 & other.0) == other.0
            }

            pub fn is_empty(self) -> bool { self.0 == 0 }

            pub fn insert(&mut self, other: $name) { self.0 |= other.0; }
        }

        impl std::ops::BitOr for $name {
            type Output = $name;
            fn bitor(self, rhs: $name) -> $name { $name(self.0 | rhs.0) }
        }

        impl std::ops::BitAnd for $name {
            type Output = $name;
            fn bitand(self, rhs: $name) -> $name { $name(self.0 & rhs.0) }
        }
    };
}

bitflags_like! {
    /// Comparison operator of a dependency, mirroring rpm's `RPMSENSE_*` bits
    /// so that the values survive a round-trip through repository metadata.
    pub struct DepFlags: u8 {
        const LESS = 0b0000_0010;
        const GREATER = 0b0000_0100;
        const EQUAL = 0b0000_1000;
    }
}

impl DepFlags {
    /// `<=`
    pub const LE: DepFlags = DepFlags(DepFlags::LESS.0 | DepFlags::EQUAL.0);
    /// `>=`
    pub const GE: DepFlags = DepFlags(DepFlags::GREATER.0 | DepFlags::EQUAL.0);

    /// Parse the symbolic form used in `primary.xml` (`EQ`, `LT`, `LE`,
    /// `GT`, `GE`), and the rpm command-line form for good measure.
    pub fn parse(s: &str) -> DepFlags {
        match s.trim() {
            "EQ" | "=" | "==" => DepFlags::EQUAL,
            "LT" | "<" => DepFlags::LESS,
            "LE" | "<=" => DepFlags::LE,
            "GT" | ">" => DepFlags::GREATER,
            "GE" | ">=" => DepFlags::GE,
            "" => DepFlags::NONE,
            _ => DepFlags::NONE,
        }
    }

    /// Does a candidate version satisfy `requirement` under these flags?
    ///
    /// `ord` is requirement.cmp(candidate), so a `>=` requirement is met when
    /// the candidate sorts after (or equal to) the requirement.
    pub fn satisfied_by_evr(self, requirement: &Evr, candidate: &Evr) -> bool {
        if self.is_empty() {
            return true;
        }
        let ord = requirement.cmp_dep(candidate);
        match self.bits() {
            x if x == DepFlags::EQUAL.bits() => ord == Ordering::Equal,
            x if x == DepFlags::LESS.bits() => ord == Ordering::Greater,
            x if x == DepFlags::LE.bits() => ord == Ordering::Greater || ord == Ordering::Equal,
            x if x == DepFlags::GREATER.bits() => ord == Ordering::Less,
            x if x == DepFlags::GE.bits() => ord == Ordering::Less || ord == Ordering::Equal,
            _ => true,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self.0 {
            x if x == DepFlags::EQUAL.0 => "=",
            x if x == DepFlags::LESS.0 => "<",
            x if x == DepFlags::LE.0 => "<=",
            x if x == DepFlags::GREATER.0 => ">",
            x if x == DepFlags::GE.0 => ">=",
            _ => "",
        }
    }
}

impl fmt::Debug for DepFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DepFlags({})", self.as_str())
    }
}

/// One `Requires`/`Provides`/... entry, optionally versioned.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Depend {
    pub name: String,
    pub flags: DepFlags,
    pub evr: Option<Evr>,
    /// Rich dependencies keep their source expression for error messages and
    /// are evaluated through [`RichDep`].
    pub rich: Option<RichDep>,
}

impl Depend {
    pub fn simple(name: impl Into<String>) -> Self {
        Depend {
            name: name.into(),
            flags: DepFlags::NONE,
            evr: None,
            rich: None,
        }
    }

    pub fn versioned(name: impl Into<String>, flags: DepFlags, evr: Evr) -> Self {
        Depend {
            name: name.into(),
            flags,
            evr: Some(evr),
            rich: None,
        }
    }

    pub fn is_versioned(&self) -> bool {
        self.evr.is_some() && !self.flags.is_empty()
    }

    /// Can this dependency be satisfied by a capability with the given name and
    /// (optional) version? This is rpm's `rpmdsCompare`.
    pub fn satisfied_by(&self, cap_name: &str, cap_evr: Option<&Evr>) -> bool {
        if self.name != cap_name {
            return false;
        }
        if !self.is_versioned() {
            return true;
        }
        let (Some(req), Some(cand)) = (&self.evr, cap_evr) else {
            // A versioned requirement can never be met by an unversioned
            // provide.
            return false;
        };
        self.flags.satisfied_by_evr(req, cand)
    }
}

impl fmt::Display for Depend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(rich) = &self.rich {
            return write!(f, "({})", rich);
        }
        match (&self.evr, self.flags.is_empty()) {
            (Some(evr), false) => write!(f, "{} {} {}", self.name, self.flags.as_str(), evr),
            _ => f.write_str(&self.name),
        }
    }
}

/// Rich dependency operators: `and`, `or`, `if`, `unless`, `with`, `without`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RichOp {
    And,
    Or,
    If,
    Unless,
    With,
    Without,
}

impl RichOp {
    fn parse(s: &str) -> Option<RichOp> {
        Some(match s {
            "and" => RichOp::And,
            "or" => RichOp::Or,
            "if" => RichOp::If,
            "unless" => RichOp::Unless,
            "with" => RichOp::With,
            "without" => RichOp::Without,
            _ => return None,
        })
    }

    fn as_str(self) -> &'static str {
        match self {
            RichOp::And => "and",
            RichOp::Or => "or",
            RichOp::If => "if",
            RichOp::Unless => "unless",
            RichOp::With => "with",
            RichOp::Without => "without",
        }
    }
}

/// A parsed rich dependency expression.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RichDep {
    Term(Box<Depend>),
    Expr(RichOp, Box<RichDep>, Box<RichDep>),
}

impl RichDep {
    /// Parse a rich dependency (the surrounding parentheses are optional).
    ///
    /// The tricky part is that capability names may themselves contain
    /// parentheses when they are not separated by whitespace, e.g.
    /// `python3dist(setuptools)`, so a `(` that directly follows a name
    /// character belongs to the name rather than opening a group.
    pub fn parse(input: &str) -> Option<RichDep> {
        let mut toks = tokenize(input)?;
        let expr = parse_expr(&mut toks)?;
        if !toks.is_empty() {
            return None;
        }
        Some(expr)
    }

    pub fn to_string_flat(&self) -> String {
        match self {
            RichDep::Term(d) => d.to_string(),
            RichDep::Expr(op, l, r) => {
                format!("{} {} {}", l.to_string_flat(), op.as_str(), r.to_string_flat())
            }
        }
    }
}

impl fmt::Display for RichDep {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RichDep::Term(d) => write!(f, "{}", d),
            RichDep::Expr(op, l, r) => write!(f, "({} {} {})", l, op.as_str(), r),
        }
    }
}

fn tokenize(input: &str) -> Option<Vec<String>> {
    let b = input.as_bytes();
    let mut i = 0;
    let mut out = Vec::new();
    while i < b.len() {
        let c = b[i];
        if c.is_ascii_whitespace() {
            i += 1;
            continue;
        }
        if c == b'(' {
            // Standing alone only when preceded by whitespace or at the start.
            let prev_is_name = i > 0 && !b[i - 1].is_ascii_whitespace() && b[i - 1] != b'(';
            if prev_is_name {
                // Handled by the word scanner below; should not happen.
                return None;
            }
            out.push("(".to_string());
            i += 1;
            continue;
        }
        if c == b')' {
            out.push(")".to_string());
            i += 1;
            continue;
        }
        // Comparison operators.
        if c == b'<' || c == b'>' || c == b'=' {
            let start = i;
            while i < b.len() && matches!(b[i], b'<' | b'>' | b'=') {
                i += 1;
            }
            out.push(input[start..i].to_string());
            continue;
        }
        // A word, optionally containing a balanced parenthesised suffix.
        let start = i;
        let mut depth = 0i32;
        while i < b.len() {
            let ch = b[i];
            if ch.is_ascii_whitespace() {
                break;
            }
            if ch == b'(' {
                depth += 1;
                i += 1;
                continue;
            }
            if ch == b')' {
                if depth == 0 {
                    break; // closing the enclosing group
                }
                depth -= 1;
                i += 1;
                continue;
            }
            i += 1;
        }
        if depth != 0 {
            return None;
        }
        out.push(input[start..i].to_string());
    }
    Some(out)
}

fn parse_expr(toks: &mut Vec<String>) -> Option<RichDep> {
    // A parenthesised group is just a nested expression; rich dependencies
    // carry no operator precedence, so one operator per group is enough.
    if toks.first().map(|s| s == "(").unwrap_or(false) {
        toks.remove(0);
        let inner = parse_expr(toks)?;
        if toks.first().map(|s| s == ")").unwrap_or(false) {
            toks.remove(0);
        } else {
            return None;
        }
        return Some(inner);
    }

    let left = parse_term(toks)?;
    match toks.first().and_then(|t| RichOp::parse(t)) {
        Some(op) => {
            toks.remove(0);
            let right = parse_expr(toks)?;
            Some(RichDep::Expr(op, Box::new(left), Box::new(right)))
        }
        None => Some(left),
    }
}

/// Parse a single capability, optionally followed by a version constraint.
fn parse_term(toks: &mut Vec<String>) -> Option<RichDep> {
    let name = toks.first()?.clone();
    if name == ")" || name == "(" || RichOp::parse(&name).is_some() {
        return None;
    }
    toks.remove(0);

    let mut flags = DepFlags::NONE;
    let mut evr = None;
    if let Some(f) = toks.first().and_then(|t| parse_flag_token(t)) {
        if !f.is_empty() {
            toks.remove(0);
            let ver = toks.first()?.clone();
            if ver == ")" || ver == "(" || RichOp::parse(&ver).is_some() {
                return None;
            }
            toks.remove(0);
            flags = f;
            evr = Some(Evr::parse(&ver));
        }
    }

    Some(RichDep::Term(Box::new(Depend {
        name,
        flags,
        evr,
        rich: None,
    })))
}

fn parse_flag_token(s: &str) -> Option<DepFlags> {
    match s {
        "=" | "==" | "<" | "<=" | ">" | ">=" => Some(DepFlags::parse(s)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simple_dependency_matching() {
        let d = Depend::simple("bash");
        assert!(d.satisfied_by("bash", None));
        assert!(!d.satisfied_by("zsh", None));

        let d = Depend::versioned("bash", DepFlags::GE, Evr::parse("5.0"));
        assert!(d.satisfied_by("bash", Some(&Evr::parse("5.2.21-1.fc41"))));
        assert!(d.satisfied_by("bash", Some(&Evr::parse("5.0"))));
        assert!(!d.satisfied_by("bash", Some(&Evr::parse("4.4"))));
        // Unversioned provide cannot satisfy a versioned requirement.
        assert!(!d.satisfied_by("bash", None));
        // Different name never matches.
        assert!(!d.satisfied_by("sh", Some(&Evr::parse("9.9"))));
    }

    #[test]
    fn all_operators() {
        let cand = Evr::parse("2.0");
        let cases = [
            (DepFlags::EQUAL, "2.0", true),
            (DepFlags::EQUAL, "2.1", false),
            (DepFlags::LESS, "2.1", true),
            (DepFlags::LESS, "2.0", false),
            (DepFlags::LE, "2.0", true),
            (DepFlags::LE, "1.9", false),
            (DepFlags::GREATER, "1.9", true),
            (DepFlags::GREATER, "2.0", false),
            (DepFlags::GE, "2.0", true),
            (DepFlags::GE, "2.1", false),
        ];
        for (flags, req, expected) in cases {
            let d = Depend::versioned("x", flags, Evr::parse(req));
            assert_eq!(
                d.satisfied_by("x", Some(&cand)),
                expected,
                "{} {} {} vs {}",
                "x",
                flags.as_str(),
                req,
                cand
            );
        }
    }

    #[test]
    fn flags_parse_both_dialects() {
        assert_eq!(DepFlags::parse("GE"), DepFlags::GE);
        assert_eq!(DepFlags::parse(">="), DepFlags::GE);
        assert_eq!(DepFlags::parse("EQ"), DepFlags::EQUAL);
        assert_eq!(DepFlags::parse("LT"), DepFlags::LESS);
        assert_eq!(DepFlags::LE.as_str(), "<=");
        assert_eq!(DepFlags::GE.bits(), 12);
        assert_eq!(DepFlags::LE.bits(), 10);
    }

    #[test]
    fn rich_dep_parsing_and_display() {
        let d = RichDep::parse("(foo if bar)").unwrap();
        assert_eq!(d.to_string(), "(foo if bar)");

        let d = RichDep::parse("(python3dist(setuptools) or python3dist(pip))").unwrap();
        assert_eq!(d.to_string(), "(python3dist(setuptools) or python3dist(pip))");

        let d = RichDep::parse("(a >= 1.0 and b < 2.0)").unwrap();
        assert_eq!(d.to_string(), "(a >= 1.0 and b < 2.0)");

        // without the outer parens is accepted too
        assert_eq!(
            RichDep::parse("a without b").unwrap().to_string(),
            "(a without b)"
        );

        assert!(RichDep::parse("(a if)").is_none());
        assert!(RichDep::parse("(a xor b)").is_none());
    }

    #[test]
    fn rich_dep_nested_names_with_parens() {
        // The classic case: a name that looks like a call.
        let d = RichDep::parse("(python3dist(foo) with python3dist(bar))").unwrap();
        match &d {
            RichDep::Expr(RichOp::With, l, r) => {
                assert_eq!(**l, RichDep::Term(Box::new(Depend::simple("python3dist(foo)"))));
                assert_eq!(**r, RichDep::Term(Box::new(Depend::simple("python3dist(bar)"))));
            }
            other => panic!("unexpected parse: {:?}", other),
        }
    }
}
