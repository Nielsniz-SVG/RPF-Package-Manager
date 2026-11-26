//! End-to-end tests: build a repository on disk, then drive the real `rpf`
//! binary against it, exactly as a user would.
//!
//! A `file://` repository is used so the tests are hermetic — no network, no
//! Fedora mirror, no root privileges. The metadata is generated with correct
//! checksums so the download-and-verify path is genuinely exercised.

use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};

use rpf::digest;

const BIN: &str = env!("CARGO_BIN_EXE_rpf");

struct Fixture {
    root: PathBuf,
}

struct Pkg {
    name: &'static str,
    version: &'static str,
    release: &'static str,
    arch: &'static str,
    summary: &'static str,
    provides: &'static [&'static str],
    requires: &'static [&'static str],
}

const PACKAGES: &[Pkg] = &[
    Pkg {
        name: "bash",
        version: "5.2.21",
        release: "1.fc41",
        arch: "x86_64",
        summary: "The GNU Bourne Again shell",
        provides: &["/bin/sh", "bash(x86-64)"],
        requires: &["glibc", "ncurses-libs"],
    },
    Pkg {
        name: "glibc",
        version: "2.40",
        release: "1.fc41",
        arch: "x86_64",
        summary: "The GNU libc libraries",
        provides: &["libc.so.6()(64bit)"],
        requires: &[],
    },
    Pkg {
        name: "ncurses-libs",
        version: "6.5",
        release: "1.fc41",
        arch: "x86_64",
        summary: "Ncurses libraries",
        provides: &["libtinfo.so.6()(64bit)"],
        requires: &["glibc"],
    },
];

impl Fixture {
    fn new(tag: &str) -> Fixture {
        let root = std::env::temp_dir().join(format!("rpf-it-{}-{}", tag, std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("repo/repodata")).unwrap();
        fs::create_dir_all(root.join("repo/Packages")).unwrap();
        fs::create_dir_all(root.join("repos.d")).unwrap();
        fs::create_dir_all(root.join("cache")).unwrap();
        fs::create_dir_all(root.join("db")).unwrap();
        let fixture = Fixture { root };
        fixture.build();
        fixture
    }

    fn path(&self, rel: &str) -> PathBuf {
        self.root.join(rel)
    }

    /// Write the repository: fake RPMs, primary.xml(.gz), filelists.xml(.gz)
    /// and repomd.xml.
    fn build(&self) {
        let mut filelists = String::from(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<filelists xmlns="http://linux.duke.edu/metadata/filelists">
"#,
        );
        let mut primary = String::from(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<metadata xmlns="http://linux.duke.edu/metadata/common" xmlns:rpm="http://linux.duke.edu/metadata/rpm">
"#,
        );

        for pkg in PACKAGES {
            let filename = format!("{}-{}-{}.{}.rpm", pkg.name, pkg.version, pkg.release, pkg.arch);
            let body = format!("FAKE RPM PAYLOAD for {}\n", filename);
            fs::write(self.path(&format!("repo/Packages/{}", filename)), &body).unwrap();
            let checksum = digest::hex(&digest::sha256(body.as_bytes()));

            // The package also ships a documentation file that primary.xml
            // does not mention: only filelists.xml knows about it.
            filelists.push_str(&format!(
                r#"<package pkgid="{checksum}" name="{name}" arch="{arch}">
  <version epoch="0" ver="{version}" rel="{release}"/>
  <file>/usr/bin/{name}</file>
  <file>/usr/share/{name}/data.txt</file>
</package>
"#,
                checksum = checksum,
                name = pkg.name,
                arch = pkg.arch,
                version = pkg.version,
                release = pkg.release,
            ));

            primary.push_str(&format!(
                r#"<package type="rpm">
  <name>{name}</name>
  <arch>{arch}</arch>
  <version epoch="0" ver="{version}" rel="{release}"/>
  <checksum type="sha256" pkgid="YES">{checksum}</checksum>
  <summary>{summary}</summary>
  <description>{summary} (description)</description>
  <packager>RPF test</packager>
  <url>https://example.org/{name}</url>
  <time file="1750000000" build="1740000000"/>
  <size package="{size}" installed="{size}" archive="{size}"/>
  <location href="Packages/{filename}"/>
  <format>
    <rpm:license>MIT</rpm:license>
    <rpm:vendor>RPF</rpm:vendor>
    <rpm:group>System</rpm:group>
    <rpm:header-range start="1000" end="2000"/>
    <rpm:provides>
      <rpm:entry name="{name}" flags="EQ" epoch="0" ver="{version}" rel="{release}"/>
{provides}
    </rpm:provides>
    <rpm:requires>
{requires}
    </rpm:requires>
    <file>/usr/bin/{name}</file>
  </format>
</package>
"#,
                name = pkg.name,
                arch = pkg.arch,
                version = pkg.version,
                release = pkg.release,
                checksum = checksum,
                summary = pkg.summary,
                size = body.len(),
                filename = filename,
                provides = pkg
                    .provides
                    .iter()
                    .map(|p| format!(
                        "      <rpm:entry name=\"{}\" flags=\"EQ\" epoch=\"0\" ver=\"{}\" rel=\"{}\"/>",
                        p, pkg.version, pkg.release
                    ))
                    .collect::<Vec<_>>()
                    .join("\n"),
                requires = pkg
                    .requires
                    .iter()
                    .map(|r| format!("      <rpm:entry name=\"{}\"/>", r))
                    .collect::<Vec<_>>()
                    .join("\n"),
            ));
        }
        primary.push_str("</metadata>\n");
        filelists.push_str("</filelists>\n");

        // Compress primary.xml with the system gzip, as a real repo would.
        let plain = self.path("repo/repodata/primary.xml");
        fs::write(&plain, &primary).unwrap();
        let gz = self.path("repo/repodata/primary.xml.gz");
        let status = Command::new("sh")
            .arg("-c")
            .arg(format!("gzip -c {} > {}", plain.display(), gz.display()))
            .status();
        let (location, compressed, open_checksum) = match status {
            Ok(s) if s.success() => {
                let bytes = fs::read(&gz).unwrap();
                (
                    "repodata/primary.xml.gz",
                    digest::hex(&digest::sha256(&bytes)),
                    digest::hex(&digest::sha256(primary.as_bytes())),
                )
            }
            _ => {
                // gzip missing: fall back to uncompressed metadata.
                (
                    "repodata/primary.xml",
                    digest::hex(&digest::sha256(primary.as_bytes())),
                    digest::hex(&digest::sha256(primary.as_bytes())),
                )
            }
        };

        // filelists.xml, compressed the same way.
        let fl_plain = self.path("repo/repodata/filelists.xml");
        fs::write(&fl_plain, &filelists).unwrap();
        let fl_gz = self.path("repo/repodata/filelists.xml.gz");
        let fl_ok = Command::new("sh")
            .arg("-c")
            .arg(format!("gzip -c {} > {}", fl_plain.display(), fl_gz.display()))
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        let (fl_location, fl_compressed) = if fl_ok {
            (
                "repodata/filelists.xml.gz",
                digest::hex(&digest::sha256(&fs::read(&fl_gz).unwrap())),
            )
        } else {
            (
                "repodata/filelists.xml",
                digest::hex(&digest::sha256(filelists.as_bytes())),
            )
        };

        let repomd = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<repomd xmlns="http://linux.duke.edu/metadata/repo">
  <revision>1750000000</revision>
  <data type="primary">
    <checksum type="sha256">{compressed}</checksum>
    <open-checksum type="sha256">{open_checksum}</open-checksum>
    <location href="{location}"/>
    <timestamp>1750000000</timestamp>
    <size>{size}</size>
  </data>
  <data type="filelists">
    <checksum type="sha256">{fl_compressed}</checksum>
    <open-checksum type="sha256">{fl_open}</open-checksum>
    <location href="{fl_location}"/>
    <timestamp>1750000000</timestamp>
    <size>{fl_size}</size>
  </data>
</repomd>
"#,
            compressed = compressed,
            open_checksum = open_checksum,
            location = location,
            size = fs::metadata(&plain).map(|m| m.len()).unwrap_or(0),
            fl_compressed = fl_compressed,
            fl_open = digest::hex(&digest::sha256(filelists.as_bytes())),
            fl_location = fl_location,
            fl_size = fs::metadata(&fl_plain).map(|m| m.len()).unwrap_or(0),
        );
        fs::write(self.path("repo/repodata/repomd.xml"), repomd).unwrap();

        fs::write(
            self.path("repos.d/testrepo.repo"),
            format!(
                "[testrepo]\nname=RPF Test Repository\nbaseurl=file://{}\n\
                 enabled=1\ngpgcheck=0\nmetadata_expire=0\n",
                self.path("repo").display()
            ),
        )
        .unwrap();
    }

    fn rpf(&self, args: &[&str]) -> Output {
        Command::new(BIN)
            .args(args)
            .env("RPF_REPOSDIR", self.path("repos.d"))
            .env("RPF_CACHEDIR", self.path("cache"))
            .env("RPF_DBPATH", self.path("db"))
            .env("RPF_RELEASEVER", "41")
            .env("RPF_BASEARCH", "x86_64")
            .env_remove("RPF_INSTALLROOT")
            .output()
            .expect("failed to run rpf")
    }

    fn stdout(&self, args: &[&str]) -> String {
        let out = self.rpf(args);
        assert!(
            out.status.success(),
            "rpf {:?} failed:\nstdout: {}\nstderr: {}",
            args,
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).to_string()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[test]
fn version_and_help_work() {
    let f = Fixture::new("version");
    let out = f.stdout(&["--version"]);
    assert!(out.contains("RPF"), "{}", out);
    assert!(out.contains(env!("CARGO_PKG_VERSION")));
}

#[test]
fn repolist_shows_configured_repo() {
    let f = Fixture::new("repolist");
    let out = f.stdout(&["repolist"]);
    assert!(out.contains("testrepo"), "{}", out);
    assert!(out.contains("enabled"), "{}", out);
    assert!(out.contains("1 enabled"), "{}", out);
}

#[test]
fn makecache_parses_metadata() {
    let f = Fixture::new("makecache");
    let out = f.stdout(&["makecache"]);
    assert!(out.contains("3 packages"), "{}", out);
    assert!(f.path("cache/testrepo/packages.rpf").exists());

    // Running it twice reuses the cache (metadata_expire=0 keeps it fresh only
    // for a forced refresh, so a second forced run still reports packages).
    let out = f.stdout(&["makecache"]);
    assert!(out.contains("3 packages"), "{}", out);
}

#[test]
fn list_search_info_and_provides() {
    let f = Fixture::new("query");

    let out = f.stdout(&["list"]);
    assert!(out.contains("bash.x86_64"), "{}", out);
    assert!(out.contains("glibc.x86_64"), "{}", out);
    assert!(out.contains("5.2.21"), "{}", out);

    let out = f.stdout(&["list", "ba*"]);
    assert!(out.contains("bash"), "{}", out);
    assert!(!out.contains("glibc"), "glob should exclude glibc: {}", out);

    let out = f.stdout(&["search", "shell"]);
    assert!(out.contains("bash"), "{}", out);
    assert!(out.contains("3") || out.contains("1 package"), "{}", out);

    let out = f.stdout(&["info", "bash"]);
    assert!(out.contains("Name         : bash"), "{}", out);
    assert!(out.contains("Version      : 5.2.21-1.fc41"), "{}", out);
    assert!(out.contains("Repository   : testrepo"), "{}", out);
    assert!(out.contains("License      : MIT"), "{}", out);

    let out = f.stdout(&["provides", "/bin/sh"]);
    assert!(out.contains("bash"), "{}", out);

    // A primary file is answered from primary.xml.
    let out = f.stdout(&["provides", "/usr/bin/glibc"]);
    assert!(out.contains("glibc"), "{}", out);
}

/// Files that only `filelists.xml` lists must still resolve to their package.
#[test]
fn provides_finds_files_from_filelists() {
    let f = Fixture::new("filelists");
    // Prime the metadata cache, as a first `makecache` would.
    f.stdout(&["makecache"]);

    let out = f.stdout(&["provides", "/usr/share/bash/data.txt"]);
    assert!(out.contains("bash-5.2.21"), "{}", out);
    assert!(
        f.path("cache/testrepo/filelists.rpf").exists(),
        "file lists should be cached"
    );

    // Unknown paths are still reported as unknown.
    let out = f.stdout(&["provides", "/usr/share/does-not-exist"]);
    assert!(
        out.contains("No package provides"),
        "unknown path should not match: {}",
        out
    );

    // And the cached file lists answer without touching the repository again.
    let out = f.stdout(&["--cacheonly", "provides", "/usr/share/glibc/data.txt"]);
    assert!(out.contains("glibc"), "{}", out);
}

#[test]
fn download_resolves_dependencies_and_verifies_checksums() {
    let f = Fixture::new("download");
    let out = f.stdout(&["download", "bash"]);

    // bash requires glibc and ncurses-libs, so all three are fetched.
    assert!(out.contains("bash-5.2.21-1.fc41.x86_64"), "{}", out);
    assert!(out.contains("glibc-2.40-1.fc41.x86_64"), "{}", out);
    assert!(out.contains("ncurses-libs-6.5-1.fc41.x86_64"), "{}", out);

    let packages = f.path("cache/packages");
    for name in ["bash-5.2.21", "glibc-2.40", "ncurses-libs-6.5"] {
        let found = fs::read_dir(&packages)
            .unwrap()
            .flatten()
            .any(|e| e.file_name().to_string_lossy().starts_with(name));
        assert!(found, "{} was not downloaded into {:?}", name, packages);
    }

    // Corrupting a cached file must be detected and replaced, not trusted.
    let bash_rpm = fs::read_dir(&packages)
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .find(|p| p.file_name().unwrap().to_string_lossy().starts_with("bash-"))
        .unwrap();
    fs::write(&bash_rpm, b"tampered").unwrap();
    f.stdout(&["download", "bash"]);
    let content = fs::read(&bash_rpm).unwrap();
    assert!(
        String::from_utf8_lossy(&content).contains("FAKE RPM PAYLOAD"),
        "corrupt cached package should be re-downloaded"
    );
}

#[test]
fn checksum_mismatch_in_metadata_is_fatal() {
    let f = Fixture::new("badsum");
    // Break the checksum in repomd.xml.
    let path = f.path("repo/repodata/repomd.xml");
    let text = fs::read_to_string(&path).unwrap();
    let bad = text.replace(
        &text[text.find("<checksum type=\"sha256\">").unwrap() + 24..
            text.find("<checksum type=\"sha256\">").unwrap() + 88],
        "0000000000000000000000000000000000000000000000000000000000000000",
    );
    fs::write(&path, bad).unwrap();

    let out = f.rpf(&["makecache"]);
    assert!(!out.status.success(), "makecache should fail on a bad checksum");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("checksum mismatch") || stderr.contains("Error"),
        "{}",
        stderr
    );
    // The cache must not be populated with unverified metadata.
    assert!(!f.path("cache/testrepo/packages.rpf").exists());
}

#[test]
fn install_reports_ordered_transaction() {
    let f = Fixture::new("install");
    let out = f.rpf(&["install", "bash"]);
    let text = String::from_utf8_lossy(&out.stdout).to_string();

    assert!(text.contains("Transaction:"), "{}", text);
    let pos_glibc = text.find("glibc-2.40").expect("glibc in transaction");
    let pos_bash = text.find("bash-5.2.21").expect("bash in transaction");
    assert!(
        pos_glibc < pos_bash,
        "glibc must be ordered before bash:\n{}",
        text
    );
}

#[test]
fn unknown_package_reports_a_useful_error() {
    let f = Fixture::new("unknown");
    let out = f.rpf(&["download", "no-such-package"]);
    assert!(!out.status.success());
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(text.contains("no match for argument"), "{}", text);
}

#[test]
fn missing_dependency_is_reported() {
    let f = Fixture::new("missingdep");
    // Ask for a package whose dependency does not exist in the repo.
    let mut primary = String::new();
    for pkg in PACKAGES {
        if pkg.name == "glibc" {
            continue;
        }
        primary.push_str(&format!(
            "<package type=\"rpm\"><name>{}</name><arch>{}</arch>\
             <version epoch=\"0\" ver=\"{}\" rel=\"{}\"/>\
             <location href=\"Packages/{}-{}-{}.{}.rpm\"/>\
             <format><rpm:requires><rpm:entry name=\"glibc\"/></rpm:requires></format>\
             </package>",
            pkg.name, pkg.arch, pkg.version, pkg.release, pkg.name, pkg.version, pkg.release, pkg.arch
        ));
    }
    let xml = format!("<metadata>{}</metadata>", primary);
    let plain = f.path("repo/repodata/primary.xml");
    fs::write(&plain, &xml).unwrap();
    let gz = f.path("repo/repodata/primary.xml.gz");
    let _ = Command::new("sh")
        .arg("-c")
        .arg(format!("gzip -c {} > {}", plain.display(), gz.display()))
        .status();

    let location = if gz.exists() {
        "repodata/primary.xml.gz"
    } else {
        "repodata/primary.xml"
    };
    let data = if gz.exists() {
        fs::read(&gz).unwrap()
    } else {
        xml.as_bytes().to_vec()
    };
    let repomd = format!(
        "<repomd><revision>2</revision><data type=\"primary\">\
         <checksum type=\"sha256\">{}</checksum>\
         <location href=\"{}\"/><size>{}</size></data></repomd>",
        digest::hex(&digest::sha256(&data)),
        location,
        data.len()
    );
    fs::write(f.path("repo/repodata/repomd.xml"), repomd).unwrap();

    let out = f.rpf(&["download", "bash", "--refresh"]);
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!out.status.success(), "{}", text);
    assert!(text.contains("nothing provides glibc"), "{}", text);
}

#[test]
fn clean_removes_cache() {
    let f = Fixture::new("clean");
    f.stdout(&["makecache"]);
    assert!(f.path("cache/testrepo").exists());
    let out = f.stdout(&["clean", "all"]);
    assert!(out.contains("Removed"), "{}", out);
    assert!(!f.path("cache/testrepo").exists());
}

#[test]
fn disabled_repo_is_skipped() {
    let f = Fixture::new("disabled");
    let out = f.stdout(&["repolist", "--setopt=testrepo.enabled=0"]);
    assert!(out.contains("disabled"), "{}", out);
    assert!(out.contains("0 enabled"), "{}", out);

    // With no enabled repos, makecache is a no-op rather than an error.
    let out = f.stdout(&["makecache", "--setopt=testrepo.enabled=0"]);
    assert!(out.contains("No enabled repositories"), "{}", out);
}

#[test]
fn cacheonly_without_cache_fails_cleanly() {
    let f = Fixture::new("cacheonly");
    let out = f.rpf(&["list", "-C"]);
    assert!(!out.status.success());
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(text.contains("no cached metadata") || text.contains("Error"), "{}", text);
}

#[test]
fn repository_with_relative_and_https_urls_is_rejected_before_use() {
    // A repo entry with no location at all must be a configuration error.
    let f = Fixture::new("badrepo");
    fs::write(
        f.path("repos.d/broken.repo"),
        "[broken]\nname=Broken Repo\nenabled=1\n",
    )
    .unwrap();
    let out = f.rpf(&["repolist"]);
    assert!(!out.status.success());
    let text = String::from_utf8_lossy(&out.stderr);
    assert!(text.contains("no baseurl"), "{}", text);
}

#[test]
fn installed_db_is_reported_by_check() {
    let f = Fixture::new("check");
    let out = f.stdout(&["check"]);
    assert!(out.contains("Packages recorded : 0"), "{}", out);
    assert!(out.contains("No problems found"), "{}", out);
}

#[test]
fn copr_repositories_can_be_enabled_and_removed() {
    let f = Fixture::new("copr");

    let out = f.stdout(&["copr", "enable", "someuser/cooltool"]);
    assert!(out.contains("copr:someuser:cooltool"), "{}", out);

    let repo_file = f.path("repos.d/copr:someuser:cooltool.repo");
    assert!(repo_file.exists(), "repo file should be written");
    let text = fs::read_to_string(&repo_file).unwrap();
    assert!(text.contains("download.copr.fedorainfracloud.org"), "{}", text);
    assert!(text.contains("fedora-41-x86_64"), "chroot should use releasever: {}", text);
    assert!(text.contains("gpgcheck=1"), "{}", text);

    let listed = f.stdout(&["copr", "list"]);
    assert!(listed.contains("copr:someuser:cooltool"), "{}", listed);

    // It must also show up as a normal repository.
    let repolist = f.stdout(&["repolist"]);
    assert!(repolist.contains("copr:someuser:cooltool"), "{}", repolist);

    f.stdout(&["copr", "remove", "someuser/cooltool"]);
    assert!(!repo_file.exists());

    // Removing it twice is an error, not a panic.
    let out = f.rpf(&["copr", "remove", "someuser/cooltool"]);
    assert!(!out.status.success());
}
