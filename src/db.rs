//! RPF's own installed-package database.
//!
//! Milestone 1 keeps its own record of installed packages under
//! `<dbpath>/installed.rpf` rather than writing to the rpmdb (which would mean
//! reimplementing rpm's own on-disk schema from scratch).
//!
//! Reading interoperates with the real rpmdb: `rpm -qa --xml --files` gives
//! name, EVR, architecture, dependencies and file lists in a documented,
//! stable format, and RPF parses it with its own XML reader. That means a
//! system populated by dnf is understood well enough to resolve against and to
//! remove from. Writing the rpmdb is deliberately out of scope: rpm owns those
//! bytes, and writing them without rpm's own library risks corrupting the
//! database. Installing with RPF therefore records packages in `installed.rpf`,
//! which `rpm -qa` will not show.
//!
//! Format: a small, line-oriented text file so it can be inspected and
//! repaired with ordinary tools. Fields are tab separated:
//!
//! ```text
//! pkg<TAB>name<TAB>epoch<TAB>version<TAB>release<TAB>arch<TAB>install_time<TAB>repo
//! dep<TAB>pkg-nevra<TAB>kind<TAB>name<TAB>flags<TAB>evr
//! file<TAB>path<TAB>size<TAB>mode<TAB>pkg-nevra
//! ```
//!
//! `kind` is one of `R` (requires), `P` (provides), `C` (conflicts) or
//! `O` (obsoletes). Dependency records are what make `rpf remove` able to
//! refuse to break other packages.

use crate::deps::{Depend, DepFlags};
use crate::pkg::Package;
use crate::version::Evr;
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

        let mut pending_deps: Vec<(String, char, Depend)> = Vec::new();

        for line in text.lines() {
            if line.starts_with('#') || line.trim().is_empty() {
                continue;
            }
            let fields: Vec<&str> = line.split('\t').collect();
            match fields.first().copied() {
                Some("dep") if fields.len() >= 6 => {
                    let nevra = fields[1].to_string();
                    let kind = fields[2].chars().next().unwrap_or('R');
                    let flags = DepFlags(fields[4].parse::<u8>().unwrap_or(0));
                    let evr = if fields[5].is_empty() {
                        None
                    } else {
                        Some(Evr::parse(fields[5]))
                    };
                    pending_deps.push((
                        nevra,
                        kind,
                        Depend {
                            name: fields[3].to_string(),
                            flags,
                            evr,
                            rich: None,
                        },
                    ));
                }
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

        // Attach dependency records now that every package is loaded.
        for (nevra, kind, depend) in pending_deps {
            if let Some(pkg) = db.packages.iter_mut().find(|p| p.nevra() == nevra) {
                match kind {
                    'P' => pkg.provides.push(depend),
                    'C' => pkg.conflicts.push(depend),
                    'O' => pkg.obsoletes.push(depend),
                    _ => pkg.requires.push(depend),
                }
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
            for (kind, deps) in [
                ('P', &pkg.provides),
                ('R', &pkg.requires),
                ('C', &pkg.conflicts),
                ('O', &pkg.obsoletes),
            ] {
                for dep in deps {
                    out.push_str(&format!(
                        "dep\t{}\t{}\t{}\t{}\t{}\n",
                        pkg.nevra(),
                        kind,
                        dep.name,
                        dep.flags.bits(),
                        dep.evr
                            .as_ref()
                            .map(|e| e.to_string_full())
                            .unwrap_or_default()
                    ));
                }
            }
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
    if let Some((packages, _)) = rpmdb_entries(installroot) {
        return packages;
    }
    rpmdb_packages_flat(installroot)
}

/// Read packages *and* file manifests from the rpmdb.
///
/// Returns `None` when rpm is unavailable or fails, so callers can fall back to
/// `installed.rpf` alone.
pub fn rpmdb_entries(installroot: &Path) -> Option<(Vec<Package>, HashMap<String, Vec<FileRecord>>)> {
    let output = std::process::Command::new("rpm")
        .arg("--root")
        .arg(installroot)
        .args(["-qa", "--xml", "--files"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let parsed = parse_rpmdb_xml(&text).ok()?;
    Some(parsed)
}

/// Parse `rpm -qa --xml --files` output.
///
/// rpm emits one `<rpmPackage>` per package with a `<version>` element, an
/// `<arch>`, and a `<format>` block holding `<rpm:entry>` elements for
/// provides/requires/conflicts/obsoletes plus `<file>` entries.
pub fn parse_rpmdb_xml(text: &str) -> Result<(Vec<Package>, HashMap<String, Vec<FileRecord>>)> {
    let doc = crate::xml::parse(text)?;
    let mut packages = Vec::new();
    let mut files: HashMap<String, Vec<FileRecord>> = HashMap::new();

    fn collect<'a>(node: &'a crate::xml::Node, name: &str, out: &mut Vec<&'a crate::xml::Node>) {
        if node.name == name {
            out.push(node);
        }
        for child in &node.children {
            collect(child, name, out);
        }
    }

    fn deps_in(node: &crate::xml::Node, list: &str) -> Vec<Depend> {
        let mut out = Vec::new();
        for child in &node.children {
            if child.name == list || child.name.ends_with(&format!(":{}", list)) {
                let mut entries = Vec::new();
                collect(child, "rpm:entry", &mut entries);
                out.extend(entries.into_iter().map(depend_from_entry));
            }
        }
        out
    }

    let mut nodes = Vec::new();
    collect(&doc, "rpmPackage", &mut nodes);

    for node in nodes {
        let mut pkg = Package {
            repo: "@System".to_string(),
            ..Default::default()
        };
        for child in &node.children {
            match child.name.as_str() {
                "name" => pkg.name = child.text.trim().to_string(),
                "arch" => pkg.arch = child.text.trim().to_string(),
                "summary" => pkg.summary = child.text.trim().to_string(),
                "version" => {
                    pkg.version = child.attr("ver").unwrap_or("").to_string();
                    pkg.release = child.attr("rel").unwrap_or("").to_string();
                    pkg.epoch = child
                        .attr("epoch")
                        .and_then(|e| e.parse().ok())
                        .unwrap_or(0);
                }
                "format" => {
                    pkg.provides = deps_in(child, "provides");
                    pkg.requires = deps_in(child, "requires");
                    pkg.conflicts = deps_in(child, "conflicts");
                    pkg.obsoletes = deps_in(child, "obsoletes");

                    let mut file_nodes = Vec::new();
                    collect(child, "file", &mut file_nodes);
                    let manifest: Vec<FileRecord> = file_nodes
                        .iter()
                        .filter_map(|file| {
                            let path = file.text.trim().to_string();
                            if path.is_empty() {
                                return None;
                            }
                            Some(FileRecord {
                                path,
                                size: file.attr("size").and_then(|s| s.parse().ok()).unwrap_or(0),
                                mode: 0,
                            })
                        })
                        .collect();
                    if !manifest.is_empty() {
                        files.insert(pkg.nevra(), manifest);
                    }
                }
                _ => {}
            }
        }
        if !pkg.name.is_empty() {
            packages.push(pkg);
        }
    }

    Ok((packages, files))
}

fn depend_from_entry(entry: &crate::xml::Node) -> Depend {
    let flags = match entry.attr("flags").unwrap_or("") {
        "EQ" => DepFlags::EQUAL,
        "LT" => DepFlags::LESS,
        "GT" => DepFlags::GREATER,
        "LE" => DepFlags::LE,
        "GE" => DepFlags::GE,
        _ => DepFlags::NONE,
    };
    let epoch = entry.attr("epoch").and_then(|e| e.parse().ok()).unwrap_or(0);
    let evr = match (entry.attr("ver"), entry.attr("rel")) {
        (Some(ver), Some(rel)) => Some(Evr {
            epoch,
            version: ver.to_string(),
            release: Some(rel.to_string()),
        }),
        (Some(ver), None) => Some(Evr {
            epoch,
            version: ver.to_string(),
            release: None,
        }),
        _ => None,
    };
    Depend {
        name: entry.attr("name").unwrap_or("").to_string(),
        flags,
        evr,
        rich: None,
    }
}

fn rpmdb_packages_flat(installroot: &Path) -> Vec<Package> {
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
    fn dependencies_survive_a_roundtrip() {
        let dir = tmpdir("deps");
        let mut db = InstalledDb::default();
        let mut pkg = pkg("app", "1.0");
        pkg.requires.push(Depend::versioned(
            "glibc",
            DepFlags::GE,
            Evr::parse("2.38"),
        ));
        pkg.requires.push(Depend::simple("/bin/sh"));
        pkg.provides.push(Depend::simple("webclient"));
        db.add(pkg, vec![], 1);
        db.save(&dir).unwrap();

        let loaded = InstalledDb::load(&dir).unwrap();
        let app = loaded.get("app").unwrap();
        assert_eq!(app.requires.len(), 2, "requires must be persisted");
        assert_eq!(app.requires[0].name, "glibc");
        assert_eq!(app.requires[0].flags, DepFlags::GE);
        assert_eq!(
            app.requires[0].evr.as_ref().unwrap().version,
            "2.38"
        );
        assert_eq!(app.provides.len(), 1);
        assert_eq!(app.provides[0].name, "webclient");
    }

    /// Modelled on `rpm -qa --xml --files` output.
    const RPMDB_XML: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<rpmHeader>
<rpmPackage>
<name>bash</name>
<version epoch="0" ver="5.2.21" rel="1.fc41"/>
<arch>x86_64</arch>
<summary>The GNU Bourne Again shell</summary>
<format>
<rpm:license>GPLv3+</rpm:license>
<rpm:group>System Environment/Shells</rpm:group>
<rpm:provides><rpm:entry name="bash" flags="EQ" epoch="0" ver="5.2.21" rel="1.fc41"/><rpm:entry name="/bin/sh"/></rpm:provides>
<rpm:requires><rpm:entry name="glibc" flags="GE" epoch="0" ver="2.38"/><rpm:entry name="rpmlib(CompressedFileNames)" flags="LE" epoch="0" ver="3.0.4" rel="1"/></rpm:requires>
<rpm:conflicts><rpm:entry name="bash-completion" flags="LT" epoch="0" ver="2.0"/></rpm:conflicts>
<file type="dir">/etc/bash_completion.d</file>
<file>/usr/bin/bash</file>
<file size="1234">/usr/share/doc/bash/README</file>
</format>
</rpmPackage>
<rpmPackage>
<name>glibc</name>
<version epoch="0" ver="2.40" rel="3.fc41"/>
<arch>x86_64</arch>
<summary>The GNU C Library</summary>
<format>
<rpm:provides><rpm:entry name="glibc" flags="EQ" epoch="0" ver="2.40" rel="3.fc41"/></rpm:provides>
<rpm:requires/>
</format>
</rpmPackage>
</rpmHeader>
"#;

    #[test]
    fn parses_rpmdb_xml_with_dependencies_and_files() {
        let (packages, files) = parse_rpmdb_xml(RPMDB_XML).unwrap();
        assert_eq!(packages.len(), 2);

        let bash = packages.iter().find(|p| p.name == "bash").unwrap();
        assert_eq!(bash.version, "5.2.21");
        assert_eq!(bash.release, "1.fc41");
        assert_eq!(bash.arch, "x86_64");
        assert_eq!(bash.repo, "@System");
        assert_eq!(bash.provides.len(), 2);
        assert_eq!(bash.provides[1].name, "/bin/sh");
        assert_eq!(bash.requires.len(), 2);
        assert_eq!(bash.requires[0].name, "glibc");
        assert_eq!(bash.requires[0].flags, DepFlags::GE);
        assert_eq!(
            bash.requires[0].evr.as_ref().unwrap().version,
            "2.38"
        );
        assert_eq!(bash.conflicts.len(), 1);
        assert_eq!(bash.conflicts[0].flags, DepFlags::LESS);

        // The shell capability must make a `require /bin/sh` resolvable.
        let sh = Depend {
            name: "/bin/sh".to_string(),
            flags: DepFlags::NONE,
            evr: None,
            rich: None,
        };
        assert!(bash.satisfies(&sh));

        let manifest = files.get(&bash.nevra()).expect("file manifest");
        assert_eq!(manifest.len(), 3);
        assert!(manifest.iter().any(|f| f.path == "/usr/bin/bash"));
        assert_eq!(
            manifest
                .iter()
                .find(|f| f.path == "/usr/share/doc/bash/README")
                .unwrap()
                .size,
            1234
        );
    }

    #[test]
    fn empty_rpmdb_xml_is_not_an_error() {
        let (packages, files) = parse_rpmdb_xml("<rpmHeader></rpmHeader>").unwrap();
        assert!(packages.is_empty());
        assert!(files.is_empty());
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
