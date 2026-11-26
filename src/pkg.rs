//! The package model shared by repository metadata and local `.rpm` files.

use crate::deps::{Depend, DepFlags};
use crate::version::Evr;
use std::cmp::Ordering;

/// One installable package, as described by repository metadata or an `.rpm`
/// header.
#[derive(Clone, Debug, Default)]
pub struct Package {
    pub name: String,
    pub epoch: u32,
    pub version: String,
    pub release: String,
    pub arch: String,
    pub summary: String,
    pub description: String,
    pub url: String,
    pub license: String,
    pub vendor: String,
    pub group: String,
    pub packager: String,
    /// Seconds since the epoch.
    pub buildtime: u64,
    /// Size of the `.rpm` file itself.
    pub download_size: u64,
    /// Size once installed.
    pub installed_size: u64,
    /// Path of the `.rpm` relative to the repository root.
    pub location: String,
    /// `(algorithm, hex digest)` of the package file.
    pub checksum: Option<(String, String)>,
    pub provides: Vec<Depend>,
    pub requires: Vec<Depend>,
    pub conflicts: Vec<Depend>,
    pub obsoletes: Vec<Depend>,
    pub recommends: Vec<Depend>,
    pub suggests: Vec<Depend>,
    pub supplements: Vec<Depend>,
    pub enhances: Vec<Depend>,
    /// The files marked "primary" in `primary.xml` (a subset of all files).
    pub files: Vec<String>,
    /// Repository id this package came from; empty for local files.
    pub repo: String,
}

impl Package {
    pub fn evr(&self) -> Evr {
        Evr {
            epoch: self.epoch,
            version: self.version.clone(),
            release: if self.release.is_empty() {
                None
            } else {
                Some(self.release.clone())
            },
        }
    }

    /// `name-version-release`
    pub fn nevr(&self) -> String {
        format!("{}-{}-{}", self.name, self.version, self.release)
    }

    /// `name-[epoch:]version-release`
    pub fn nevra(&self) -> String {
        if self.epoch != 0 {
            format!(
                "{}-{}:{}-{}.{}",
                self.name, self.epoch, self.version, self.release, self.arch
            )
        } else {
            format!("{}-{}-{}.{}", self.name, self.version, self.release, self.arch)
        }
    }

    pub fn nevr_signed(&self) -> String {
        if self.epoch != 0 {
            format!("{}:{}", self.name_signature(), self.epoch)
        } else {
            self.name_signature()
        }
    }

    fn name_signature(&self) -> String {
        format!("{}-{}-{}", self.name, self.version, self.release)
    }

    /// Basename of the package file, e.g. `bash-5.2.21-1.fc41.x86_64.rpm`.
    pub fn filename(&self) -> String {
        match self.location.rsplit('/').next() {
            Some(f) if !f.is_empty() => f.to_string(),
            _ => format!("{}.rpm", self.nevra()),
        }
    }

    /// Ordering by EVR only (not arch).
    pub fn cmp_evr(&self, other: &Package) -> Ordering {
        self.evr().cmp_full(&other.evr())
    }

    /// `true` if this package can be installed on the given architecture set
    /// (`noarch` always matches).
    pub fn arch_matches(&self, arches: &[String]) -> bool {
        self.arch == "noarch" || arches.iter().any(|a| *a == self.arch)
    }

    /// Every capability this package provides, including the implicit
    /// `name = EVR` and `name(arch) = EVR` that rpm adds automatically.
    pub fn all_provides(&self) -> Vec<Depend> {
        let evr = self.evr();
        let mut out = Vec::with_capacity(self.provides.len() + 2);
        out.push(Depend::versioned(
            self.name.clone(),
            DepFlags::EQUAL,
            evr.clone(),
        ));
        if !self.arch.is_empty() {
            out.push(Depend::versioned(
                format!("{}({})", self.name, self.arch),
                DepFlags::EQUAL,
                evr.clone(),
            ));
        }
        out.extend(self.provides.iter().cloned());
        out
    }

    /// Does this package satisfy the given dependency?
    ///
    /// Checks, in order: the implicit `name` and `name(arch)` capabilities,
    /// then every explicit provide. A versioned requirement is never satisfied
    /// by an unversioned provide, matching rpm.
    pub fn satisfies(&self, dep: &Depend) -> bool {
        if let Some(crate::deps::RichDep::Term(term)) = &dep.rich {
            return self.satisfies(term);
        }

        let evr = self.evr();
        if dep.name == self.name {
            return Self::cap_matches(dep, &evr);
        }
        if !self.arch.is_empty() && dep.name == format!("{}({})", self.name, self.arch) {
            return Self::cap_matches(dep, &evr);
        }

        self.provides.iter().any(|p| {
            if p.name != dep.name {
                return false;
            }
            match &p.evr {
                Some(prov_evr) => Self::cap_matches(dep, prov_evr),
                None => !dep.is_versioned(),
            }
        })
    }

    fn cap_matches(dep: &Depend, cap_evr: &Evr) -> bool {
        match (&dep.evr, dep.is_versioned()) {
            (Some(req), true) => dep.flags.satisfied_by_evr(req, cap_evr),
            _ => true,
        }
    }

    /// All file paths, for "which package owns this file" queries.
    pub fn owns_file(&self, path: &str) -> bool {
        self.files.iter().any(|f| f == path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pkg(name: &str, ver: &str, rel: &str, arch: &str) -> Package {
        Package {
            name: name.to_string(),
            version: ver.to_string(),
            release: rel.to_string(),
            arch: arch.to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn nevra_formatting() {
        let p = pkg("bash", "5.2.21", "1.fc41", "x86_64");
        assert_eq!(p.nevra(), "bash-5.2.21-1.fc41.x86_64");
        assert_eq!(p.nevr(), "bash-5.2.21-1.fc41");

        let mut p = pkg("bash", "5.2.21", "1.fc41", "x86_64");
        p.epoch = 2;
        assert_eq!(p.nevra(), "bash-2:5.2.21-1.fc41.x86_64");
    }

    #[test]
    fn implicit_self_provide() {
        let p = pkg("bash", "5.2.21", "1.fc41", "x86_64");
        // Name alone.
        assert!(p.satisfies(&Depend::simple("bash")));
        // Versioned self-provide.
        let dep = Depend::versioned("bash", DepFlags::GE, Evr::parse("5.0"));
        assert!(p.satisfies(&dep));
        let dep = Depend::versioned("bash", DepFlags::GE, Evr::parse("6.0"));
        assert!(!p.satisfies(&dep));
        // name(arch) capability.
        assert!(p.satisfies(&Depend::simple("bash(x86_64)")));
    }

    #[test]
    fn explicit_provides_are_honoured() {
        let mut p = pkg("bash", "5.2.21", "1.fc41", "x86_64");
        p.provides.push(Depend::versioned(
            "/bin/sh",
            DepFlags::EQUAL,
            Evr::parse("5.2.21-1.fc41"),
        ));
        assert!(p.satisfies(&Depend::simple("/bin/sh")));
        let dep = Depend::versioned("/bin/sh", DepFlags::GE, Evr::parse("5.0"));
        assert!(p.satisfies(&dep));
    }

    #[test]
    fn arch_matching() {
        let p = pkg("tzdata", "2024a", "1.fc41", "noarch");
        assert!(p.arch_matches(&["x86_64".to_string()]));
        let p = pkg("glibc", "2.40", "1.fc41", "x86_64");
        assert!(p.arch_matches(&["x86_64".to_string()]));
        assert!(!p.arch_matches(&["aarch64".to_string()]));
    }

    #[test]
    fn evr_ordering() {
        let a = pkg("x", "1.0", "1", "x86_64");
        let b = pkg("x", "1.1", "1", "x86_64");
        assert_eq!(a.cmp_evr(&b), Ordering::Less);
    }
}
