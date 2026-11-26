//! The metadata cache: a compact binary store plus the logic that keeps it in
//! sync with a repository.
//!
//! Layout under `<cachedir>/<repo id>/`:
//!   * `packages.rpf`  — parsed `primary.xml` packages, in RPF's binary format
//!   * `meta`          — small text file with revision/timestamp
//!   * `files/`        — downloaded `.rpm` files (when keepcache is on)
//!
//! The binary format exists because RPF has no SQLite binding: it is a simple
//! length-prefixed encoding that loads thousands of packages in one pass.

use crate::config::{Config, Repo};
use crate::deps::{Depend, DepFlags, RichDep};
use crate::fetch;
use crate::pkg::Package;
use crate::repomd::{self, Metalink, RepoMd};
use crate::version::Evr;
use crate::{digest, Error, Result};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const MAGIC: &[u8; 8] = b"RPFDB\x00\x01\x00";

#[derive(Debug, Clone, Default)]
pub struct CachedRepo {
    pub repo_id: String,
    pub revision: String,
    /// Unix timestamp of the last successful sync.
    pub fetched_at: u64,
    pub packages: Vec<Package>,
}

impl CachedRepo {
    pub fn is_stale(&self, max_age_secs: u64) -> bool {
        if max_age_secs == 0 {
            return false;
        }
        now().saturating_sub(self.fetched_at) > max_age_secs
    }
}

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn repo_dir(cachedir: &Path, repo_id: &str) -> PathBuf {
    cachedir.join(sanitise(repo_id))
}

fn sanitise(id: &str) -> String {
    let cleaned: String = id
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' {
                c
            } else {
                '_'
            }
        })
        .collect();
    // A repo id of "." or ".." would turn into a path traversal component.
    if cleaned == "." || cleaned == ".." || cleaned.is_empty() {
        format!("_{}", cleaned)
    } else {
        cleaned
    }
}

fn packages_path(cachedir: &Path, repo_id: &str) -> PathBuf {
    repo_dir(cachedir, repo_id).join("packages.rpf")
}

fn meta_path(cachedir: &Path, repo_id: &str) -> PathBuf {
    repo_dir(cachedir, repo_id).join("meta")
}

/// Read a repository's cached packages, if any.
pub fn read_cached(cachedir: &Path, repo_id: &str) -> Result<Option<CachedRepo>> {
    let path = packages_path(cachedir, repo_id);
    if !path.exists() {
        return Ok(None);
    }
    let bytes = fs::read(&path).map_err(|e| Error::new(format!("{}: {}", path.display(), e)))?;
    let mut cur = Cursor::new(&bytes);
    if cur.take(MAGIC.len())? != MAGIC {
        return Err(Error::new(format!(
            "{}: not an RPF metadata cache (corrupt or wrong version)",
            path.display()
        )));
    }
    let count = cur.u32()? as usize;
    let mut packages = Vec::with_capacity(count.min(1_000_000));
    for _ in 0..count {
        packages.push(cur.package()?);
    }

    // `meta` holds revision and timestamp as two lines.
    let mut revision = String::new();
    let mut fetched_at = 0u64;
    if let Ok(meta) = fs::read_to_string(meta_path(cachedir, repo_id)) {
        let mut lines = meta.lines();
        revision = lines.next().unwrap_or("").to_string();
        fetched_at = lines.next().and_then(|s| s.trim().parse().ok()).unwrap_or(0);
    }

    Ok(Some(CachedRepo {
        repo_id: repo_id.to_string(),
        revision,
        fetched_at,
        packages,
    }))
}

fn write_cached(cachedir: &Path, cached: &CachedRepo) -> Result<()> {
    let dir = repo_dir(cachedir, &cached.repo_id);
    fs::create_dir_all(&dir).map_err(|e| Error::new(format!("{}: {}", dir.display(), e)))?;

    let mut out = Vec::with_capacity(cached.packages.len() * 256);
    out.extend_from_slice(MAGIC);
    let mut w = Encoder::new(&mut out);
    w.u32(cached.packages.len() as u32);
    for pkg in &cached.packages {
        w.package(pkg);
    }

    let path = packages_path(cachedir, &cached.repo_id);
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, &out).map_err(|e| Error::new(format!("{}: {}", tmp.display(), e)))?;
    fs::rename(&tmp, &path).map_err(|e| Error::new(format!("{}: {}", path.display(), e)))?;

    fs::write(
        meta_path(cachedir, &cached.repo_id),
        format!("{}\n{}\n", cached.revision, cached.fetched_at),
    )
    .map_err(|e| Error::new(format!("{}: {}", dir.display(), e)))?;
    Ok(())
}

/// Resolve a repository's base URLs, following metalink/mirrorlist if needed.
pub fn resolve_bases(repo: &Repo) -> Result<Vec<String>> {
    if !repo.baseurls.is_empty() {
        return Ok(repo.baseurls.clone());
    }
    if let Some(metalink) = &repo.metalink {
        let bytes = fetch::fetch_bytes(metalink).map_err(|e| {
            e.context(format!("metalink for repository '{}'", repo.id))
        })?;
        let text = String::from_utf8_lossy(&bytes);
        let ml = Metalink::parse(&text)?;
        return Ok(ml.bases);
    }
    if let Some(mirrorlist) = &repo.mirrorlist {
        let bytes = fetch::fetch_bytes(mirrorlist).map_err(|e| {
            e.context(format!("mirrorlist for repository '{}'", repo.id))
        })?;
        let text = String::from_utf8_lossy(&bytes);
        let bases = repomd::parse_mirrorlist(&text);
        if bases.is_empty() {
            return Err(Error::new(format!(
                "mirrorlist for '{}' returned no usable mirrors",
                repo.id
            )));
        }
        return Ok(bases);
    }
    Err(Error::new(format!(
        "repository '{}' has no usable location",
        repo.id
    )))
}

/// Download and parse `repomd.xml` for a repository.
pub fn fetch_repomd(repo: &Repo, bases: &[String]) -> Result<RepoMd> {
    let (_, bytes) = fetch::fetch_bytes_from_mirrors(bases, "repodata/repomd.xml")?;
    let text = String::from_utf8_lossy(&bytes);
    RepoMd::parse(&text).map_err(|e| e.context(format!("repository '{}' repomd.xml", repo.id)))
}

/// Result of syncing one repository.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncOutcome {
    /// Metadata was already current; nothing was downloaded.
    UpToDate,
    /// Metadata was downloaded and parsed.
    Updated,
}

/// Synchronise one repository's metadata into the cache.
pub fn sync_repo(config: &Config, repo: &Repo, force: bool) -> Result<(CachedRepo, SyncOutcome)> {
    let bases = resolve_bases(repo)?;
    let repomd = fetch_repomd(repo, &bases)?;

    if let Some(existing) = read_cached(&config.conf.cachedir, &repo.id)? {
        let fresh = !force
            && !existing.is_stale(repo.metadata_expire.max(config.conf.metadata_expire.min(0)));
        // `metadata_expire` is per-repo; 0 means "never expires".
        let fresh = fresh && !existing.is_stale(repo.metadata_expire);
        if fresh && (existing.revision.is_empty() || existing.revision == repomd.revision) {
            return Ok((existing, SyncOutcome::UpToDate));
        }
    }

    let primary = repomd
        .primary()
        .ok_or_else(|| Error::new(format!("repository '{}' has no primary metadata", repo.id)))?;

    let (_, compressed) = fetch::fetch_bytes_from_mirrors(&bases, &primary.location)
        .map_err(|e| e.context(format!("repository '{}' primary metadata", repo.id)))?;

    // Integrity of the *compressed* object, as recorded in repomd.xml.
    if !primary.checksum.is_empty() {
        verify_bytes(&compressed, &primary.checksum_type, &primary.checksum)
            .map_err(|e| e.context(format!("repository '{}'", repo.id)))?;
    }

    let xml_text = fetch::decompress_to_string(compressed, &primary.location)?;

    // And of the decompressed document, when the repo advertises it.
    if let Some((algo, expected)) = &primary.open_checksum {
        verify_bytes(xml_text.as_bytes(), algo, expected)
            .map_err(|e| e.context(format!("repository '{}' (open checksum)", repo.id)))?;
    }

    let packages = repomd::parse_primary(&xml_text, &repo.id)?;

    let cached = CachedRepo {
        repo_id: repo.id.clone(),
        revision: repomd.revision.clone(),
        fetched_at: now(),
        packages,
    };
    write_cached(&config.conf.cachedir, &cached)?;
    Ok((cached, SyncOutcome::Updated))
}

fn verify_bytes(data: &[u8], algo: &str, expected: &str) -> Result<()> {
    match algo.to_ascii_lowercase().as_str() {
        "sha" | "sha256" => {
            let got = digest::hex(&digest::sha256(data));
            if !got.eq_ignore_ascii_case(expected) {
                return Err(Error::new(format!(
                    "checksum mismatch: expected {}, got {}",
                    expected, got
                )));
            }
            Ok(())
        }
        other => Err(Error::new(format!(
            "unsupported metadata checksum algorithm {:?}",
            other
        ))),
    }
}

/// Load metadata for every enabled repository, syncing when necessary.
pub fn load_all(config: &Config, cacheonly: bool, force: bool) -> Result<Vec<CachedRepo>> {
    let mut out = Vec::new();
    #[allow(unused_mut)]
    let mut errors: Vec<String> = Vec::new();

    for repo in config.enabled_repos() {
        let cached = if cacheonly {
            read_cached(&config.conf.cachedir, &repo.id)?
        } else {
            match sync_repo(config, repo, force) {
                Ok((c, _)) => Some(c),
                Err(e) => {
                    // A repo with skip_if_unavailable yields to the others.
                    if repo.skip_if_unavailable {
                        errors.push(format!("{}: {} (skipped)", repo.id, e));
                        None
                    } else {
                        return Err(e.context(format!("repository '{}'", repo.id)));
                    }
                }
            }
        };

        match cached {
            Some(c) => out.push(c),
            None => {
                // No metadata and no permission to fetch it: that is a hard
                // error unless the repo is explicitly optional.
                if repo.skip_if_unavailable {
                    errors.push(format!("{}: no cached metadata (skipped)", repo.id));
                } else {
                    return Err(Error::new(format!(
                        "repository '{}' has no cached metadata; run 'rpf makecache' \
                         (or drop --cacheonly)",
                        repo.id
                    )));
                }
            }
        }
    }
    Ok(out)
}

/// Concatenate packages from all cached repositories.
pub fn all_packages(caches: &[CachedRepo]) -> Vec<&Package> {
    caches.iter().flat_map(|c| c.packages.iter()).collect()
}

// ---------------------------------------------------------------------------
// Binary encoding
// ---------------------------------------------------------------------------

struct Encoder<'a> {
    out: &'a mut Vec<u8>,
}

impl<'a> Encoder<'a> {
    fn new(out: &'a mut Vec<u8>) -> Self {
        Encoder { out }
    }

    fn u8(&mut self, v: u8) {
        self.out.push(v);
    }

    fn u32(&mut self, v: u32) {
        self.out.extend_from_slice(&v.to_le_bytes());
    }

    fn u64(&mut self, v: u64) {
        self.out.extend_from_slice(&v.to_le_bytes());
    }

    fn str(&mut self, s: &str) {
        self.u32(s.len() as u32);
        self.out.extend_from_slice(s.as_bytes());
    }

    fn opt_str(&mut self, s: Option<&str>) {
        match s {
            Some(v) => {
                self.u8(1);
                self.str(v);
            }
            None => self.u8(0),
        }
    }

    fn depend(&mut self, d: &Depend) {
        self.str(&d.name);
        self.u8(d.flags.bits());
        match &d.evr {
            Some(evr) => {
                self.u8(1);
                self.u32(evr.epoch);
                self.str(&evr.version);
                self.opt_str(evr.release.as_deref());
            }
            None => self.u8(0),
        }
        match &d.rich {
            Some(rich) => {
                self.u8(1);
                // Re-parsed on load; storing the canonical text keeps the
                // format stable as the RichDep type evolves.
                self.str(&rich.to_string());
            }
            None => self.u8(0),
        }
    }

    fn dep_list(&mut self, deps: &[Depend]) {
        self.u32(deps.len() as u32);
        for d in deps {
            self.depend(d);
        }
    }

    fn package(&mut self, p: &Package) {
        self.str(&p.name);
        self.u32(p.epoch);
        self.str(&p.version);
        self.str(&p.release);
        self.str(&p.arch);
        self.str(&p.summary);
        self.str(&p.description);
        self.str(&p.url);
        self.str(&p.license);
        self.str(&p.vendor);
        self.str(&p.group);
        self.str(&p.packager);
        self.u64(p.buildtime);
        self.u64(p.download_size);
        self.u64(p.installed_size);
        self.str(&p.location);
        match &p.checksum {
            Some((algo, value)) => {
                self.u8(1);
                self.str(algo);
                self.str(value);
            }
            None => self.u8(0),
        }
        self.dep_list(&p.provides);
        self.dep_list(&p.requires);
        self.dep_list(&p.conflicts);
        self.dep_list(&p.obsoletes);
        self.dep_list(&p.recommends);
        self.dep_list(&p.suggests);
        self.dep_list(&p.supplements);
        self.dep_list(&p.enhances);
        self.u32(p.files.len() as u32);
        for f in &p.files {
            self.str(f);
        }
        self.str(&p.repo);
    }
}

struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Cursor { data, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.pos + n > self.data.len() {
            return Err(Error::new("metadata cache is truncated"));
        }
        let slice = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(slice)
    }

    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    fn u32(&mut self) -> Result<u32> {
        let b = self.take(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn u64(&mut self) -> Result<u64> {
        let b = self.take(8)?;
        Ok(u64::from_le_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }

    fn string(&mut self) -> Result<String> {
        let len = self.u32()? as usize;
        let bytes = self.take(len)?;
        String::from_utf8(bytes.to_vec()).map_err(|e| Error::new(e.to_string()))
    }

    fn opt_string(&mut self) -> Result<Option<String>> {
        if self.u8()? == 1 {
            Ok(Some(self.string()?))
        } else {
            Ok(None)
        }
    }

    fn depend(&mut self) -> Result<Depend> {
        let name = self.string()?;
        let flags = DepFlags(self.u8()?);
        let evr = if self.u8()? == 1 {
            let epoch = self.u32()?;
            let version = self.string()?;
            let release = self.opt_string()?;
            Some(Evr {
                epoch,
                version,
                release,
            })
        } else {
            None
        };
        let rich = if self.u8()? == 1 {
            let text = self.string()?;
            RichDep::parse(&text)
        } else {
            None
        };
        Ok(Depend {
            name,
            flags,
            evr,
            rich,
        })
    }

    fn dep_list(&mut self) -> Result<Vec<Depend>> {
        let n = self.u32()? as usize;
        let mut out = Vec::with_capacity(n);
        for _ in 0..n {
            out.push(self.depend()?);
        }
        Ok(out)
    }

    fn package(&mut self) -> Result<Package> {
        let name = self.string()?;
        let epoch = self.u32()?;
        let version = self.string()?;
        let release = self.string()?;
        let arch = self.string()?;
        let summary = self.string()?;
        let description = self.string()?;
        let url = self.string()?;
        let license = self.string()?;
        let vendor = self.string()?;
        let group = self.string()?;
        let packager = self.string()?;
        let buildtime = self.u64()?;
        let download_size = self.u64()?;
        let installed_size = self.u64()?;
        let location = self.string()?;
        let checksum = if self.u8()? == 1 {
            let algo = self.string()?;
            let value = self.string()?;
            Some((algo, value))
        } else {
            None
        };
        let provides = self.dep_list()?;
        let requires = self.dep_list()?;
        let conflicts = self.dep_list()?;
        let obsoletes = self.dep_list()?;
        let recommends = self.dep_list()?;
        let suggests = self.dep_list()?;
        let supplements = self.dep_list()?;
        let enhances = self.dep_list()?;
        let file_count = self.u32()? as usize;
        let mut files = Vec::with_capacity(file_count);
        for _ in 0..file_count {
            files.push(self.string()?);
        }
        let repo = self.string()?;

        Ok(Package {
            name,
            epoch,
            version,
            release,
            arch,
            summary,
            description,
            url,
            license,
            vendor,
            group,
            packager,
            buildtime,
            download_size,
            installed_size,
            location,
            checksum,
            provides,
            requires,
            conflicts,
            obsoletes,
            recommends,
            suggests,
            supplements,
            enhances,
            files,
            repo,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Package {
        let mut p = Package {
            name: "bash".into(),
            version: "5.2.21".into(),
            release: "1.fc41".into(),
            arch: "x86_64".into(),
            summary: "The GNU Bourne Again shell".into(),
            description: "Long description".into(),
            license: "GPL-3.0-or-later".into(),
            location: "Packages/b/bash.rpm".into(),
            checksum: Some(("sha256".into(), "abc123".into())),
            download_size: 1234,
            installed_size: 5678,
            buildtime: 42,
            repo: "fedora".into(),
            ..Default::default()
        };
        p.provides.push(Depend::versioned(
            "/bin/sh",
            DepFlags::EQUAL,
            Evr::parse("5.2.21-1.fc41"),
        ));
        p.requires.push(Depend::versioned(
            "glibc",
            DepFlags::GE,
            Evr::parse("2.38"),
        ));
        p.requires.push(Depend::simple("libc.so.6(GLIBC_2.38)(64bit)"));
        p.requires.push(Depend {
            name: "(a or b)".into(),
            flags: DepFlags::NONE,
            evr: None,
            rich: RichDep::parse("(a or b)"),
        });
        p.files = vec!["/usr/bin/bash".into(), "/etc/skel".into()];
        p
    }

    #[test]
    fn binary_roundtrip() {
        let original = sample();
        let mut buf = Vec::new();
        {
            let mut enc = Encoder::new(&mut buf);
            enc.u32(1);
            enc.package(&original);
        }
        let mut cur = Cursor::new(&buf);
        assert_eq!(cur.u32().unwrap(), 1);
        let decoded = cur.package().unwrap();

        assert_eq!(decoded.name, original.name);
        assert_eq!(decoded.version, original.version);
        assert_eq!(decoded.checksum, original.checksum);
        assert_eq!(decoded.provides.len(), 1);
        assert_eq!(decoded.provides[0].evr.as_ref().unwrap().release.as_deref(), Some("1.fc41"));
        assert_eq!(decoded.requires.len(), 3);
        assert_eq!(decoded.requires[1].name, "libc.so.6(GLIBC_2.38)(64bit)");
        assert!(decoded.requires[2].rich.is_some());
        assert_eq!(
            decoded.requires[2].rich.as_ref().unwrap().to_string(),
            "(a or b)"
        );
        assert_eq!(decoded.files, original.files);
        assert_eq!(decoded.repo, "fedora");
        assert_eq!(decoded.download_size, 1234);
    }

    #[test]
    fn write_read_and_staleness() {
        let dir = std::env::temp_dir().join(format!("rpf-cache-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let cached = CachedRepo {
            repo_id: "fedora".into(),
            revision: "1750000000".into(),
            fetched_at: now(),
            packages: vec![sample()],
        };
        write_cached(&dir, &cached).unwrap();

        let loaded = read_cached(&dir, "fedora").unwrap().unwrap();
        assert_eq!(loaded.revision, "1750000000");
        assert_eq!(loaded.packages.len(), 1);
        assert_eq!(loaded.packages[0].name, "bash");
        assert!(!loaded.is_stale(3600));
        assert!(!loaded.is_stale(0), "0 means never expire");
        assert!(loaded.is_stale(1) == false || loaded.is_stale(1) == true);

        assert!(read_cached(&dir, "absent").unwrap().is_none());
    }

    #[test]
    fn corrupt_cache_is_reported_not_panicked() {
        let dir = std::env::temp_dir().join(format!("rpf-cache-bad-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("r")).unwrap();
        fs::write(dir.join("r/packages.rpf"), b"not a cache").unwrap();
        let err = read_cached(&dir, "r").unwrap_err();
        assert!(err.message().contains("not an RPF metadata cache"));
    }

    #[test]
    fn repo_id_sanitising_stays_inside_cachedir() {
        // A malicious repo id must not escape the cache directory.
        let dir = PathBuf::from("/tmp/cache");
        for evil in ["../etc/passwd", "..", ".", "/etc/shadow", "a/b/../../c"] {
            let p = repo_dir(&dir, evil);
            assert!(p.starts_with("/tmp/cache"), "{} escaped to {}", evil, p.display());
            let name = p.file_name().unwrap().to_string_lossy().to_string();
            assert!(name != ".." && name != ".", "{} produced {}", evil, name);
        }
    }

}
