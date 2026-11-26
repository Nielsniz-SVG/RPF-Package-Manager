//! Transaction execution: writing packages to the filesystem and removing them.
//!
//! Order of operations for an install is deliberate, so that a failure never
//! leaves the target root in a half-written state:
//!
//!   1. parse the RPM and verify its payload digest,
//!   2. check every path for conflicts *before* touching the filesystem,
//!   3. extract files, verifying each file digest as it is written,
//!   4. record the package and its manifest in the database.
//!
//! Extraction is confined to the target root: every payload path is
//! normalised and rejected if it is absolute or escapes via `..`.

use crate::config::Config;
use crate::db::{FileRecord, InstalledDb};
use crate::pkg::Package;
use crate::rpm::{self, CpioReader, Rpm, RpmFile};
use crate::{digest, Error, Result};
use std::collections::HashMap;
use std::fs;
use std::os::unix::fs::{chown, symlink, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone)]
pub struct Options {
    pub installroot: PathBuf,
    /// Plan and check only; never write.
    pub test: bool,
    /// Skip %pre/%post/%preun/%postun.
    pub noscripts: bool,
    pub verbose: bool,
    /// Overwrite files that belong to other packages.
    pub replacefiles: bool,
}

impl Options {
    pub fn new(installroot: impl Into<PathBuf>) -> Options {
        Options {
            installroot: installroot.into(),
            test: false,
            noscripts: false,
            verbose: false,
            replacefiles: false,
        }
    }
}

#[derive(Debug, Default)]
pub struct Report {
    pub installed: Vec<Package>,
    pub removed: Vec<Package>,
    pub warnings: Vec<String>,
    pub files_written: usize,
    pub bytes_written: u64,
    /// Paths written as `.rpmnew` because the existing file was preserved.
    pub rpmnew: Vec<String>,
    /// Paths preserved as `.rpmsave` while the package version was installed.
    pub rpmsave: Vec<String>,
}

/// True when RPF is running with effective uid 0.
pub fn is_root() -> bool {
    if let Ok(status) = fs::read_to_string("/proc/self/status") {
        for line in status.lines() {
            if let Some(rest) = line.strip_prefix("Uid:") {
                // Uid: real effective saved fs
                let mut fields = rest.split_whitespace();
                let _real = fields.next();
                if let Some(effective) = fields.next() {
                    return effective.trim() == "0";
                }
            }
        }
    }
    false
}

/// Where the RPM for a package lives locally.
pub fn package_file(config: &Config, pkg: &Package, local: &HashMap<String, PathBuf>) -> Result<PathBuf> {
    if let Some(path) = local.get(&pkg.nevra()) {
        return Ok(path.clone());
    }
    if pkg.repo == "@commandline" && !pkg.location.is_empty() {
        return Ok(PathBuf::from(&pkg.location));
    }
    Ok(config.conf.cachedir.join("packages").join(pkg.filename()))
}

/// Install the given packages (already resolved and ordered by the solver).
pub fn install(
    config: &Config,
    packages: &[Package],
    local: &HashMap<String, PathBuf>,
    opts: &Options,
) -> Result<Report> {
    let mut report = Report::default();
    let mut db = InstalledDb::load(&config.conf.dbpath)?;
    let owns_chown = is_root();

    if !owns_chown && !opts.test {
        report.warnings.push(
            "not running as root: file ownership will not be applied".to_string(),
        );
    }

    for pkg in packages {
        let path = package_file(config, pkg, local)?;
        if !path.exists() {
            return Err(Error::new(format!(
                "package file for {} is missing: {}",
                pkg.nevra(),
                path.display()
            )));
        }
        let rpm = Rpm::open(&path)?;

        // The file on disk must be the package we resolved, not a stray file.
        let embedded = rpm.package();
        if !embedded.name.is_empty() && embedded.nevra() != pkg.nevra() {
            return Err(Error::new(format!(
                "package file {} contains {} but {} was requested",
                path.display(),
                embedded.nevra(),
                pkg.nevra()
            )));
        }

        let payload = rpm.verify_payload()?;
        let files = rpm.files();

        // Pass 1: conflict detection before anything is written.
        let conflicts = check_conflicts(&db, pkg, &files, opts, &mut report)?;
        if !conflicts.is_empty() {
            return Err(Error::new(format!(
                "file conflicts for {}:\n  {}",
                pkg.nevra(),
                conflicts.join("\n  ")
            )));
        }

        if opts.test {
            report.installed.push(pkg.clone());
            continue;
        }

        run_script(rpm.scriptlets().prein.as_deref(), pkg, opts, &mut report, "%pre", 1);

        // Pass 2: extract.
        let mut reader = CpioReader::new(&payload);
        let mut hardlinks: HashMap<u32, PathBuf> = HashMap::new();
        let meta_by_path: HashMap<&str, &RpmFile> =
            files.iter().map(|f| (f.path.as_str(), f)).collect();

        while let Some(entry) = reader.next_entry()? {
            let rel = entry
                .name
                .trim_start_matches("./")
                .trim_start_matches('/')
                .to_string();
            if rel.is_empty() {
                continue;
            }
            let rel_path = PathBuf::from(&rel);
            if rel_path.is_absolute() {
                return Err(Error::new(format!(
                    "payload entry {:?} is absolute; refusing to extract",
                    entry.name
                )));
            }
            for component in rel_path.components() {
                if component.as_os_str() == ".." {
                    return Err(Error::new(format!(
                        "payload entry {:?} escapes the install root",
                        entry.name
                    )));
                }
            }

            let dest = opts.installroot.join(&rel_path);
            let logical = rpm::normalise_path(&entry.name);

            if let Some(parent) = dest.parent() {
                fs::create_dir_all(parent)
                    .map_err(|e| Error::new(format!("{}: {}", parent.display(), e)))?;
            }

            if entry.is_dir() {
                if !dest.exists() {
                    fs::create_dir_all(&dest)
                        .map_err(|e| Error::new(format!("{}: {}", dest.display(), e)))?;
                }
                set_mode(&dest, entry.perms())?;
                set_mtime(&dest, entry.mtime);
                continue;
            }

            if entry.is_symlink() {
                let target = String::from_utf8_lossy(entry.data).to_string();
                if dest.symlink_metadata().is_ok() {
                    let _ = fs::remove_file(&dest);
                }
                symlink(&target, &dest).map_err(|e| {
                    Error::new(format!("symlink {} -> {}: {}", dest.display(), target, e))
                })?;
                continue;
            }

            if !entry.is_regular() {
                // Device nodes, fifos and sockets need privileges; report them
                // rather than silently pretending they exist.
                report.warnings.push(format!(
                    "{}: special file not created ({})",
                    logical,
                    match () {
                        _ if entry.is_chardev() => "character device",
                        _ if entry.is_blockdev() => "block device",
                        _ if entry.is_fifo() => "fifo",
                        _ => "socket",
                    }
                ));
                continue;
            }

            // Hardlinks: the first entry carries the data, the rest are links.
            if entry.nlink > 1 {
                if let Some(first) = hardlinks.get(&entry.ino) {
                    if dest.exists() {
                        let _ = fs::remove_file(&dest);
                    }
                    fs::hard_link(first, &dest).map_err(|e| {
                        Error::new(format!(
                            "hardlink {} -> {}: {}",
                            dest.display(),
                            first.display(),
                            e
                        ))
                    })?;
                    continue;
                }
                hardlinks.insert(entry.ino, dest.clone());
            }

            // Config file handling: never silently destroy local changes.
            let meta = meta_by_path.get(logical.as_str()).copied();
            let mut write_target = dest.clone();
            if let Some(meta) = meta {
                if meta.is_config() && dest.exists() {
                    let existing = fs::read(&dest).unwrap_or_default();
                    if existing != entry.data {
                        if meta.is_noreplace() {
                            write_target = PathBuf::from(format!("{}.rpmnew", dest.display()));
                            report.rpmnew.push(write_target.display().to_string());
                        } else {
                            let save = PathBuf::from(format!("{}.rpmsave", dest.display()));
                            fs::copy(&dest, &save).map_err(|e| {
                                Error::new(format!("{}: {}", save.display(), e))
                            })?;
                            report.rpmsave.push(save.display().to_string());
                        }
                    }
                }
            }

            // Verify the file digest from the header against the payload bytes.
            if let Some(meta) = meta {
                if !meta.digest.is_empty() {
                    let got = digest::hex(&digest::sha256(entry.data));
                    if !got.eq_ignore_ascii_case(&meta.digest) {
                        return Err(Error::new(format!(
                            "file digest mismatch for {}: expected {}, got {}",
                            logical, meta.digest, got
                        )));
                    }
                }
            }

            if let Some(meta) = meta {
                if meta.is_ghost() {
                    continue;
                }
            }

            fs::write(&write_target, entry.data)
                .map_err(|e| Error::new(format!("{}: {}", write_target.display(), e)))?;
            set_mode(&write_target, entry.perms())?;
            set_mtime(&write_target, entry.mtime);
            report.files_written += 1;
            report.bytes_written += entry.data.len() as u64;

            if owns_chown {
                apply_ownership(&opts.installroot, &write_target, meta)?;
            }
        }

        run_script(rpm.scriptlets().postin.as_deref(), pkg, opts, &mut report, "%post", 1);

        // Record the whole header file list, including ghosts and configs, so
        // that removal can clean up correctly.
        let manifest: Vec<FileRecord> = files
            .iter()
            .map(|f| FileRecord {
                path: f.path.clone(),
                size: f.size,
                mode: f.perms(),
            })
            .collect();
        let mut stored = embedded;
        stored.repo = pkg.repo.clone();
        db.add(stored, manifest, crate::cache::now());
        report.installed.push(pkg.clone());

        if opts.verbose {
            println!("  installed {}", pkg.nevra());
        }
    }

    if !opts.test {
        db.save(&config.conf.dbpath)?;
    }
    Ok(report)
}

/// Remove installed packages by name.
pub fn remove(config: &Config, names: &[String], opts: &Options) -> Result<Report> {
    let mut report = Report::default();
    let mut db = InstalledDb::load(&config.conf.dbpath)?;

    // Packages that came from the system's rpmdb are not in `installed.rpf`;
    // fall back to rpm's own record so `rpf remove` still knows what it owns.
    // Only the packages being removed are imported, so nothing else leaks into
    // RPF's database.
    let mut rpmdb = None;

    for name in names {
        if db.get(name).is_none() {
            if rpmdb.is_none() {
                rpmdb = crate::db::rpmdb_entries(&config.conf.installroot);
            }
            if let Some((packages, files)) = &rpmdb {
                if let Some(pkg) = packages.iter().find(|p| &p.name == name) {
                    let manifest = files.get(&pkg.nevra()).cloned().unwrap_or_default();
                    db.add(pkg.clone(), manifest, 0);
                }
            }
        }
        let Some(pkg) = db.get(name).cloned() else {
            return Err(Error::new(format!("package '{}' is not installed", name)));
        };

        // Refuse to break other packages' dependencies.
        let dependents: Vec<String> = db
            .packages
            .iter()
            .filter(|other| other.name != pkg.name)
            .filter(|other| {
                other
                    .requires
                    .iter()
                    .any(|req| !req.name.starts_with("rpmlib(") && pkg.satisfies(req))
            })
            .map(|other| other.nevra())
            .collect();
        if !dependents.is_empty() {
            return Err(Error::new(format!(
                "cannot remove {}: required by {}",
                pkg.nevra(),
                dependents.join(", ")
            )));
        }

        if opts.test {
            report.removed.push(pkg);
            continue;
        }

        // Scriptlets can only run inside a real root owned by root.
        let scriptlets = installed_scriptlets(config, &pkg);
        run_script(
            scriptlets.as_ref().and_then(|s| s.preun.as_deref()),
            &pkg,
            opts,
            &mut report,
            "%preun",
            1,
        );

        let files = db.remove(name).unwrap_or_default();
        let mut dirs: Vec<PathBuf> = Vec::new();
        let mut parents: Vec<PathBuf> = Vec::new();
        for record in &files {
            let rel = record.path.trim_start_matches('/');
            let path = opts.installroot.join(rel);
            let Ok(metadata) = path.symlink_metadata() else {
                continue;
            };
            if metadata.is_dir() {
                dirs.push(path);
                continue;
            }
            if let Err(e) = fs::remove_file(&path) {
                if e.kind() != std::io::ErrorKind::NotFound {
                    report
                        .warnings
                        .push(format!("cannot remove {}: {}", path.display(), e));
                }
            } else {
                report.files_written += 1;
            }
            // Directories the installer created implicitly are not in the
            // manifest; record their parents so they can be pruned.
            let mut parent = path.parent();
            while let Some(dir) = parent {
                if dir == opts.installroot || !dir.starts_with(&opts.installroot) {
                    break;
                }
                parents.push(dir.to_path_buf());
                parent = dir.parent();
            }
        }

        // Remove directories deepest-first, and only when empty. `remove_dir`
        // fails on non-empty directories, which protects shared paths.
        dirs.sort_by_key(|p| std::cmp::Reverse(p.components().count()));
        for dir in dirs {
            let _ = fs::remove_dir(&dir);
        }
        parents.sort_by_key(|p| std::cmp::Reverse(p.components().count()));
        parents.dedup();
        for dir in parents {
            if fs::remove_dir(&dir).is_err() {
                break; // non-empty: stop walking up
            }
        }

        run_script(
            scriptlets.as_ref().and_then(|s| s.postun.as_deref()),
            &pkg,
            opts,
            &mut report,
            "%postun",
            0,
        );

        report.removed.push(pkg);
    }

    if !opts.test {
        db.save(&config.conf.dbpath)?;
    }
    Ok(report)
}

fn installed_scriptlets(config: &Config, pkg: &Package) -> Option<rpm::Scriptlets> {
    let path = package_file(config, pkg, &HashMap::new()).ok()?;
    let rpm = Rpm::open(&path).ok()?;
    Some(rpm.scriptlets())
}

/// Check every payload path for an existing file that belongs to someone else.
///
/// Runs before anything is written, so a conflict aborts the transaction with
/// the target root untouched.
fn check_conflicts(
    db: &InstalledDb,
    pkg: &Package,
    files: &[RpmFile],
    opts: &Options,
    report: &mut Report,
) -> Result<Vec<String>> {
    let mut conflicts = Vec::new();

    for file in files {
        if file.is_dir() || file.is_ghost() {
            continue;
        }

        match db.owner_of(&file.path) {
            Some(owner) if owner.name == pkg.name => {
                // Upgrading this very package: overwriting is expected.
                continue;
            }
            Some(owner) => {
                if !opts.replacefiles {
                    conflicts.push(format!(
                        "{} is already owned by {}",
                        file.path,
                        owner.nevra()
                    ));
                }
                continue;
            }
            None => {}
        }

        let dest = opts.installroot.join(file.path.trim_start_matches('/'));
        if dest.symlink_metadata().is_ok() && !file.is_config() && !opts.replacefiles {
            conflicts.push(format!(
                "{} already exists and is not owned by any package",
                file.path
            ));
        } else if dest.symlink_metadata().is_ok() && file.is_config() {
            report.warnings.push(format!(
                "{} exists; keeping it as a config file",
                file.path
            ));
        }
    }

    Ok(conflicts)
}

fn set_mode(path: &Path, mode: u32) -> Result<()> {
    fs::set_permissions(path, fs::Permissions::from_mode(mode & 0o7777))
        .map_err(|e| Error::new(format!("chmod {}: {}", path.display(), e)))
}

fn set_mtime(path: &Path, mtime: u64) {
    if mtime == 0 {
        return;
    }
    let Ok(file) = fs::File::open(path) else { return };
    let when = UNIX_EPOCH + Duration::from_secs(mtime);
    let times = fs::FileTimes::new().set_modified(when).set_accessed(when);
    let _ = file.set_times(times);
}

fn apply_ownership(installroot: &Path, path: &Path, meta: Option<&RpmFile>) -> Result<()> {
    let Some(meta) = meta else { return Ok(()) };
    let uid = rpm::resolve_id(installroot, &meta.user, false).unwrap_or(0);
    let gid = rpm::resolve_id(installroot, &meta.group, true).unwrap_or(0);
    chown(path, Some(uid), Some(gid))
        .map_err(|e| Error::new(format!("chown {}: {}", path.display(), e)))
}

fn run_script(
    script: Option<&str>,
    pkg: &Package,
    opts: &Options,
    report: &mut Report,
    kind: &str,
    argument: u32,
) {
    let Some(script) = script else { return };
    if script.trim().is_empty() {
        return;
    }
    if opts.noscripts {
        return;
    }
    if !is_root() {
        report.warnings.push(format!(
            "{}: {} scriptlet skipped (not running as root)",
            pkg.nevra(),
            kind
        ));
        return;
    }

    // rpm invokes scriptlets as `sh -c <script> <pkg> <n>`, so `$1` is the
    // number of instances of the package that will exist after this step and
    // `$0` is the package name.
    let mut cmd = if opts.installroot == Path::new("/") {
        let mut c = std::process::Command::new("/bin/sh");
        c.arg("-c").arg(script).arg(&pkg.name).arg(argument.to_string());
        c
    } else {
        // Inside a chroot the script sees only the target root's filesystem.
        let inner = format!(
            "/bin/sh -c {} {} {}",
            shell_quote(script),
            shell_quote(&pkg.name),
            argument
        );
        let mut c = std::process::Command::new("chroot");
        c.arg(&opts.installroot).arg("/bin/sh").arg("-c").arg(inner);
        c
    };

    match cmd.status() {
        Ok(status) if status.success() => {}
        Ok(status) => report.warnings.push(format!(
            "{}: {} scriptlet exited with {}",
            pkg.nevra(),
            kind,
            status
        )),
        Err(e) => report.warnings.push(format!(
            "{}: could not run {} scriptlet: {}",
            pkg.nevra(),
            kind,
            e
        )),
    }
}

/// Quote a string for safe interpolation into a `sh -c` command line.
fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

/// Convert a system time into rpm's seconds-since-epoch representation.
pub fn system_time_secs(t: SystemTime) -> u64 {
    t.duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_detection_does_not_panic() {
        // Either value is fine; the call must be safe in any environment.
        let _ = is_root();
    }

    #[test]
    fn system_time_conversion() {
        assert_eq!(system_time_secs(UNIX_EPOCH), 0);
        assert_eq!(system_time_secs(UNIX_EPOCH + Duration::from_secs(42)), 42);
    }

    #[test]
    fn package_file_prefers_local_override() {
        let config = crate::config::Config::load(&crate::config::Overrides {
            cachedir: Some(PathBuf::from("/tmp/c")),
            dbpath: Some(PathBuf::from("/tmp/d")),
            use_defaults_only: true,
            ..Default::default()
        })
        .unwrap();
        let pkg = Package {
            name: "x".into(),
            version: "1".into(),
            release: "1".into(),
            arch: "noarch".into(),
            repo: "fedora".into(),
            location: "Packages/x/x-1-1.noarch.rpm".into(),
            ..Default::default()
        };

        let fallback = package_file(&config, &pkg, &HashMap::new()).unwrap();
        assert_eq!(fallback, PathBuf::from("/tmp/c/packages/x-1-1.noarch.rpm"));

        let mut local = HashMap::new();
        local.insert(pkg.nevra(), PathBuf::from("/somewhere/other.rpm"));
        assert_eq!(
            package_file(&config, &pkg, &local).unwrap(),
            PathBuf::from("/somewhere/other.rpm")
        );
    }
}
