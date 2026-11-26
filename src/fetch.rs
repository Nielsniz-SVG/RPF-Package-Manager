//! Transport: fetching URLs and decompressing metadata.
//!
//! RPF is dependency-free, so instead of linking an HTTP/TLS stack it drives
//! the system `curl` (present on every Fedora installation) and `xz`/`zstd`/
//! `gzip` for compression. Local `file://` URLs are handled in-process, which
//! is what makes repository fixtures testable without a network.

use crate::{Error, Result};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// Where a URL points.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    File,
    Http,
    Https,
}

pub fn scheme_of(url: &str) -> Option<Scheme> {
    if url.starts_with("file://") {
        Some(Scheme::File)
    } else if url.starts_with("https://") {
        Some(Scheme::Https)
    } else if url.starts_with("http://") {
        Some(Scheme::Http)
    } else if url.starts_with('/') {
        Some(Scheme::File)
    } else {
        None
    }
}

/// Convert a `file://` URL (or bare path) into a filesystem path.
pub fn local_path(url: &str) -> Option<PathBuf> {
    if let Some(rest) = url.strip_prefix("file://") {
        // file:///path -> /path ; file://host/path is not supported.
        if rest.starts_with('/') {
            Some(PathBuf::from(rest))
        } else {
            None
        }
    } else if url.starts_with('/') {
        Some(PathBuf::from(url))
    } else {
        None
    }
}

/// Join a base URL and a relative path, tolerating both trailing and missing
/// slashes on either side.
pub fn join_url(base: &str, rel: &str) -> String {
    let base = base.trim_end_matches('/');
    let rel = rel.trim_start_matches('/');
    format!("{}/{}", base, rel)
}

fn require_curl() -> Result<()> {
    static CHECKED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    let ok = *CHECKED.get_or_init(|| {
        Command::new("curl")
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    });
    if ok {
        Ok(())
    } else {
        Err(Error::new(
            "the 'curl' command is required for network access but was not found in PATH",
        ))
    }
}

/// Fetch a URL to memory. Intended for small documents (repomd, metalink).
pub fn fetch_bytes(url: &str) -> Result<Vec<u8>> {
    match scheme_of(url) {
        Some(Scheme::File) => {
            let path = local_path(url).ok_or_else(|| Error::new(format!("bad file URL {}", url)))?;
            std::fs::read(&path).map_err(|e| Error::new(format!("{}: {}", path.display(), e)))
        }
        Some(_) => {
            require_curl()?;
            let out = Command::new("curl")
                .args([
                    "--fail",
                    "--location",
                    "--silent",
                    "--show-error",
                    "--retry",
                    "2",
                    "--connect-timeout",
                    "20",
                    "--max-time",
                    "300",
                    "--max-redirs",
                    "5",
                    url,
                ])
                .output()
                .map_err(|e| Error::new(format!("failed to run curl: {}", e)))?;
            if !out.status.success() {
                let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
                return Err(Error::new(format!(
                    "download failed for {}: {}",
                    url,
                    if stderr.is_empty() {
                        format!("curl exited with {}", out.status)
                    } else {
                        stderr
                    }
                )));
            }
            Ok(out.stdout)
        }
        None => Err(Error::new(format!("unsupported URL scheme: {}", url))),
    }
}

/// Fetch a URL to a file, atomically (download to `.part`, then rename).
pub fn fetch_to_file(url: &str, dest: &Path) -> Result<()> {
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| Error::new(format!("{}: {}", parent.display(), e)))?;
    }
    let tmp = dest.with_extension("part");
    match scheme_of(url) {
        Some(Scheme::File) => {
            let src = local_path(url).ok_or_else(|| Error::new(format!("bad file URL {}", url)))?;
            std::fs::copy(&src, &tmp)
                .map_err(|e| Error::new(format!("{}: {}", src.display(), e)))?;
        }
        Some(_) => {
            require_curl()?;
            let mut cmd = Command::new("curl");
            cmd.args([
                "--fail",
                "--location",
                "--silent",
                "--show-error",
                "--retry",
                "2",
                "--connect-timeout",
                "20",
                "--max-time",
                "1800",
                "--output",
            ])
            .arg(&tmp)
            .arg(url);
            let out = cmd
                .output()
                .map_err(|e| Error::new(format!("failed to run curl: {}", e)))?;
            if !out.status.success() {
                let _ = std::fs::remove_file(&tmp);
                let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
                return Err(Error::new(format!(
                    "download failed for {}: {}",
                    url,
                    if stderr.is_empty() {
                        format!("curl exited with {}", out.status)
                    } else {
                        stderr
                    }
                )));
            }
        }
        None => return Err(Error::new(format!("unsupported URL scheme: {}", url))),
    }
    std::fs::rename(&tmp, dest).map_err(|e| Error::new(format!("{}: {}", dest.display(), e)))?;
    Ok(())
}

/// Try a list of base URLs in order until one succeeds, returning the one that
/// worked. Mirrors are tried sequentially on purpose: it keeps failures
/// debuggable and avoids hammering every mirror at once.
pub fn fetch_bytes_from_mirrors(
    bases: &[String],
    rel: &str,
) -> Result<(String, Vec<u8>)> {
    let mut last_err = None;
    for base in bases {
        let url = join_url(base, rel);
        match fetch_bytes(&url) {
            Ok(bytes) => return Ok((base.clone(), bytes)),
            Err(e) => last_err = Some(e),
        }
    }
    Err(last_err.unwrap_or_else(|| Error::new("no mirrors available")))
}

/// Compression of a metadata file, inferred from its name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Compression {
    None,
    Gzip,
    Xz,
    Zstd,
    Bzip2,
    Lzma,
}

impl Compression {
    pub fn from_filename(name: &str) -> Compression {
        let lower = name.to_ascii_lowercase();
        if lower.ends_with(".gz") {
            Compression::Gzip
        } else if lower.ends_with(".xz") {
            Compression::Xz
        } else if lower.ends_with(".zst") || lower.ends_with(".zstd") {
            Compression::Zstd
        } else if lower.ends_with(".bz2") {
            Compression::Bzip2
        } else if lower.ends_with(".lzma") {
            Compression::Lzma
        } else {
            Compression::None
        }
    }

    pub fn command(self) -> Option<(&'static str, &'static [&'static str])> {
        match self {
            Compression::None => None,
            Compression::Gzip => Some(("gzip", &["-dc"])),
            Compression::Xz => Some(("xz", &["-dc"])),
            Compression::Zstd => Some(("zstd", &["-dc"])),
            Compression::Bzip2 => Some(("bzip2", &["-dc"])),
            Compression::Lzma => Some(("xz", &["--format=lzma", "-dc"])),
        }
    }
}

/// Decompress (or pass through) metadata bytes using the system tool.
pub fn decompress(data: Vec<u8>, compression: Compression) -> Result<Vec<u8>> {
    let Some((program, args)) = compression.command() else {
        return Ok(data);
    };

    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|_| {
            Error::new(format!(
                "cannot decompress metadata: '{}' not found in PATH \
                 (install it, or point the repo at uncompressed metadata)",
                program
            ))
        })?;

    // Feed stdin from a separate thread: writing a large buffer inline while
    // the child fills its stdout pipe would deadlock.
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| Error::new(format!("cannot write to {}", program)))?;
    let writer = std::thread::spawn(move || {
        let _ = stdin.write_all(&data);
    });

    let out = child
        .wait_with_output()
        .map_err(|e| Error::new(format!("{}: {}", program, e)))?;
    let _ = writer.join();

    if !out.status.success() {
        return Err(Error::new(format!(
            "{} failed to decompress metadata: {}",
            program,
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(out.stdout)
}

/// Convenience: decompress metadata and interpret it as UTF-8 text.
pub fn decompress_to_string(data: Vec<u8>, name: &str) -> Result<String> {
    let bytes = decompress(data, Compression::from_filename(name))?;
    String::from_utf8(bytes)
        .map_err(|e| Error::new(format!("metadata {} is not valid UTF-8: {}", name, e)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_handling() {
        assert_eq!(scheme_of("file:///tmp/x"), Some(Scheme::File));
        assert_eq!(scheme_of("/tmp/x"), Some(Scheme::File));
        assert_eq!(scheme_of("https://example.org/x"), Some(Scheme::Https));
        assert_eq!(scheme_of("http://example.org/x"), Some(Scheme::Http));
        assert_eq!(scheme_of("ftp://example.org/x"), None);

        assert_eq!(
            local_path("file:///tmp/x").unwrap(),
            PathBuf::from("/tmp/x")
        );
        assert!(local_path("file://host/x").is_none());

        assert_eq!(
            join_url("https://e.org/repo/", "repodata/repomd.xml"),
            "https://e.org/repo/repodata/repomd.xml"
        );
        assert_eq!(
            join_url("https://e.org/repo", "/repodata/repomd.xml"),
            "https://e.org/repo/repodata/repomd.xml"
        );
    }

    #[test]
    fn compression_detection() {
        assert_eq!(
            Compression::from_filename("primary.xml.gz"),
            Compression::Gzip
        );
        assert_eq!(
            Compression::from_filename("primary.xml.zst"),
            Compression::Zstd
        );
        assert_eq!(Compression::from_filename("primary.xml.xz"), Compression::Xz);
        assert_eq!(
            Compression::from_filename("primary.xml"),
            Compression::None
        );
    }

    #[test]
    fn gzip_roundtrip_via_system_tool() {
        // Build a gzip stream with the system gzip, then decompress it through
        // the same path RPF uses in production.
        let child = Command::new("sh")
            .arg("-c")
            .arg("printf 'hello rpf' | gzip -c")
            .stdout(Stdio::piped())
            .spawn()
            .expect("sh available");
        let out = child.wait_with_output().unwrap();
        assert!(out.status.success());
        let text = decompress_to_string(out.stdout, "x.xml.gz").unwrap();
        assert_eq!(text, "hello rpf");
    }

    #[test]
    fn uncompressed_passthrough() {
        let text = decompress_to_string(b"<a/>".to_vec(), "x.xml").unwrap();
        assert_eq!(text, "<a/>");
    }

    #[test]
    fn local_file_fetch() {
        let dir = std::env::temp_dir().join(format!("rpf-fetch-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("data.txt");
        std::fs::write(&path, b"content").unwrap();

        let url = format!("file://{}", path.display());
        assert_eq!(fetch_bytes(&url).unwrap(), b"content");

        let dest = dir.join("copy.txt");
        fetch_to_file(&url, &dest).unwrap();
        assert_eq!(std::fs::read(&dest).unwrap(), b"content");

        // Missing files surface as errors, not panics.
        assert!(fetch_bytes("file:///nonexistent/x").is_err());
    }
}
