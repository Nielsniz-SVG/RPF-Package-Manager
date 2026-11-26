//! RPF's own installed-package database.
//!
//! Milestone 1 keeps its own record of installed packages under
//! `<dbpath>/installed.rpf` rather than writing to the rpmdb (which would mean
//! reimplementing rpm's SQLite schema from scratch). Interoperating with the
//! real rpmdb is phase 2 — see `docs/PHASE1.md`.
//!
//! Format: a small, line-oriented text file so it can be inspected and
//! repaired with ordinary tools. Fields are tab separated:
//!
//! ```text
//! pkg<TAB>name<TAB>epoch<TAB>version<TAB>release<TAB>arch<TAB>install_time<TAB>repo
//! file<TAB>path<TAB>size<TAB>mode<TAB>pkg-nevra
//! ```

use crate::pkg::Package;
use crate::{Error, Result};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

pub const DB_FILE: &str = "installed.rpf";

#[derive(Debug, Clone, Default)]
pub struct FileRecord {
    pub path: String,
    pub size: u64,
    pub mode: u32,
}

#[derive(Debug, Clone, Default)]
pub struct InstalledDb {
    pub packages: Vec<Package>,
    pub files: HashMap<String, Vec<FileRecord>>,
    pub install_times: HashMap<String, u64>,
}

impl InstalledDb {
    pub fn path(dbpath: &Path) -> PathBuf {
        dbpath.join(DB_FILE)
    }

    pub fn load(dbpath: &Path) -> Result<InstalledDb> {
        let path = Self::path(dbpath);
        let mut db = InstalledDb::default();
        let text = match fs::read_to_string(&path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(db),
            Err(e) => return Err(Error::new(format!("{}: {}", path.display(), e))),
        };

        for line in text.lines() {
            if line.starts_with('#') || line.trim().is_empty() {
                continue;
            }
            let fields: Vec<&str> = line.split('\t').collect();
            match fields.first().copied() {
                Some("pkg") if fields.len() >= 8 => {
                    let pkg = Package {
                        name: fields[1].to_string(),
                        epoch: fields[2].parse().unwrap_or(0),
                        version: fields[3].to_string(),
                        release: fields[4].to_string(),
                        arch: fields[5].to_string(),
                        repo: fields[7].to_string(),
                        ..Default::default()
                    };
                    db.install_times
                        .insert(pkg.nevra(), fields[6].parse().unwrap_or(0));
                    db.packages.push(pkg);
                }
                Some("file") if fields.len() >= 5 => {
                    let record = FileRecord {
                        path: fields[1].to_string(),
                        size: fields[2].parse().unwrap_or(0),
                        mode: u32::from_str_radix(fields[3], 8).unwrap_or(0o644),
                    };
                    db.files
                        .entry(fields[4].to_string())
                        .or_default()
                        .push(record);
                }
                _ => {}
            }
        }
        Ok(db)
    }

    pub fn save(&self, dbpath: &Path) -> Result<()> {
        fs::create_dir_all(dbpath)
            .map_err(|e| Error::new(format!("{}: {}", dbpath.display(), e)))?;
        let mut out = String::from("# RPF installed packages v1\n");
        for pkg in &self.packages {
            let time = self.install_times.get(&pkg.nevra()).copied().unwrap_or(0);
            out.push_str(&format!(
                "pkg\t{}\t{}\t{}\t{}\t{}\t{}\t{}\n",
                pkg.name, pkg.epoch, pkg.version, pkg.release, pkg.arch, time, pkg.repo
            ));
            if let Some(files) = self.files.get(&pkg.nevra()) {
                for f in files {
                    out.push_str(&format!(
                        "file\t{}\t{}\t{:o}\t{}\n",
                        f.path,
                        f.size,
                        f.mode,
                        pkg.nevra()
                    ));
                }
            }
        }
        let path = Self::path(dbpath);
        let tmp = path.with_extension("tmp");
        fs::write(&tmp, out).map_err(|e| Error::new(format!("{}: {}", tmp.display(), e)))?;
        fs::rename(&tmp, &path).map_err(|e| Error::new(format!("{}: {}", path.display(), e)))?;
        Ok(())
    }

    pub fn get(&self, name: &str) -> Option<&Package> {
        self.packages.iter().find(|p| p.name == name)
    }

    pub fn is_installed(&self, name: &str) -> bool {
        self.get(name).is_some()
    }

    /// Which installed package owns a path, if any.
    pub fn owner_of(&self, path: &str) -> Option<&Package> {
        let nevra = self
            .files
            .iter()
            .find(|(_, records)| records.iter().any(|r| r.path == path))
            .map(|(k, _)| k.clone())?;
        self.packages.iter().find(|p| p.nevra() == nevra)
    }

    pub fn add(&mut self, mut pkg: Package, files: Vec<FileRecord>, install_time: u64) {
        pkg.repo = pkg.repo.clone();
        let nevra = pkg.nevra();
        self.packages.retain(|p| p.name != pkg.name);
        self.files.retain(|k, _| k != &nevra);
        self.files.insert(nevra.clone(), files);
        self.install_times.insert(nevra, install_time);
        self.packages.push(pkg);
        self.packages.sort_by(|a, b| a.name.cmp(&b.name));
    }

    pub fn remove(&mut self, name: &str) -> Option<Vec<FileRecord>> {
        let pkg = self.packages.iter().find(|p| p.name == name)?.clone();
        let nevra = pkg.nevra();
        self.packages.retain(|p| p.name != name);
        self.install_times.remove(&nevra);
        self.files.remove(&nevra)
    }
}

/// Packages installed in the rpmdb of the target root, if `rpm` is available.
/// Used as a fallback so RPF can reason about a system it did not populate.
pub fn rpmdb_packages(installroot: &Path) -> Vec<Package> {
    let output = std::process::Command::new("rpm")
        .arg("--root")
        .arg(installroot)
        .args([
            "-qa",
            "--queryformat",
            "%{NAME}\\t%{EPOCHNUM}\\t%{VERSION}\\t%{RELEASE}\\t%{ARCH}\\t%{SUMMARY}\\n",
        ])
        .output();

    let Ok(out) = output else { return Vec::new() };
    if !out.status.success() {
        return Vec::new();
    }
    let text = String::from_utf8_lossy(&out.stdout);
    text.lines()
        .filter_map(|line| {
            let f: Vec<&str> = line.split('\t').collect();
            if f.len() < 5 {
                return None;
            }
            Some(Package {
                name: f[0].to_string(),
                epoch: f[1].parse().unwrap_or(0),
                version: f[2].to_string(),
                release: f[3].to_string(),
                arch: f[4].to_string(),
                summary: f.get(5).unwrap_or(&"").to_string(),
                repo: "@System".to_string(),
                ..Default::default()
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("rpf-db-{}-{}", tag, std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn pkg(name: &str, ver: &str) -> Package {
        Package {
            name: name.to_string(),
            version: ver.to_string(),
            release: "1.fc41".to_string(),
            arch: "x86_64".to_string(),
            repo: "fedora".to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn empty_db_loads_without_a_file() {
        let dir = tmpdir("empty");
        let db = InstalledDb::load(&dir).unwrap();
        assert!(db.packages.is_empty());
    }

    #[test]
    fn roundtrip_with_file_manifests() {
        let dir = tmpdir("roundtrip");
        let mut db = InstalledDb::default();
        db.add(
            pkg("bash", "5.2.21"),
            vec![
                FileRecord {
                    path: "/usr/bin/bash".into(),
                    size: 1234,
                    mode: 0o755,
                },
                FileRecord {
                    path: "/etc/bashrc".into(),
                    size: 10,
                    mode: 0o644,
                },
            ],
            1_700_000_000,
        );
        db.add(pkg("tzdata", "2024a"), vec![], 1_700_000_001);
        db.save(&dir).unwrap();

        let loaded = InstalledDb::load(&dir).unwrap();
        assert_eq!(loaded.packages.len(), 2);
        // Sorted by name on add.
        assert_eq!(loaded.packages[0].name, "bash");
        assert_eq!(loaded.packages[1].name, "tzdata");
        assert_eq!(loaded.install_times.get("bash-5.2.21-1.fc41.x86_64"), Some(&1_700_000_000));

        let files = loaded.files.get("bash-5.2.21-1.fc41.x86_64").unwrap();
        assert_eq!(files.len(), 2);
        assert_eq!(files[0].mode, 0o755);
        assert_eq!(
            loaded.owner_of("/usr/bin/bash").map(|p| p.name.as_str()),
            Some("bash")
        );
        assert!(loaded.owner_of("/nope").is_none());
    }

    #[test]
    fn remove_returns_manifest() {
        let dir = tmpdir("remove");
        let mut db = InstalledDb::default();
        db.add(
            pkg("bash", "5.2.21"),
            vec![FileRecord {
                path: "/usr/bin/bash".into(),
                size: 1,
                mode: 0o755,
            }],
            1,
        );
        db.save(&dir).unwrap();

        let mut loaded = InstalledDb::load(&dir).unwrap();
        let files = loaded.remove("bash").unwrap();
        assert_eq!(files.len(), 1);
        assert!(!loaded.is_installed("bash"));
        assert!(loaded.files.is_empty());
        loaded.save(&dir).unwrap();
        assert!(InstalledDb::load(&dir).unwrap().packages.is_empty());
    }

    #[test]
    fn installing_same_name_replaces_record() {
        let mut db = InstalledDb::default();
        db.add(pkg("bash", "5.2.21"), vec![], 1);
        db.add(pkg("bash", "5.3.0"), vec![], 2);
        assert_eq!(db.packages.len(), 1);
        assert_eq!(db.packages[0].version, "5.3.0");
    }

    #[test]
    fn tolerates_garbage_lines() {
        let dir = tmpdir("garbage");
        fs::write(
            InstalledDb::path(&dir),
            "# comment\nnonsense\npkg\tonly\tthree\nfile\ta\t1\t644\n",
        )
        .unwrap();
        let db = InstalledDb::load(&dir).unwrap();
        assert!(db.packages.is_empty());
        assert!(db.files.is_empty());
    }
}
