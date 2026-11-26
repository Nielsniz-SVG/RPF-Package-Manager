//! Repository metadata formats: `repomd.xml`, metalink/mirrorlist discovery,
//! and `primary.xml` package listings.

use crate::deps::{Depend, DepFlags, RichDep};
use crate::pkg::Package;
use crate::version::Evr;
use crate::xml::{self, Event, Reader};
use crate::{Error, Result};

/// One `<data type="...">` entry in `repomd.xml`.
#[derive(Debug, Clone, Default)]
pub struct RepoMdData {
    pub kind: String,
    /// Path relative to the repository root, e.g. `repodata/primary.xml.zst`.
    pub location: String,
    pub checksum_type: String,
    pub checksum: String,
    /// Checksum of the *decompressed* file, when the repository provides it.
    pub open_checksum: Option<(String, String)>,
    pub size: u64,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Default)]
pub struct RepoMd {
    pub revision: String,
    pub data: Vec<RepoMdData>,
}

impl RepoMd {
    pub fn parse(text: &str) -> Result<RepoMd> {
        let root = xml::parse(text)?;
        let repomd = root
            .child("repomd")
            .ok_or_else(|| Error::new("repomd.xml: missing <repomd> root element"))?;

        let revision = repomd
            .child("revision")
            .map(|n| n.text.trim().to_string())
            .unwrap_or_default();

        let mut data = Vec::new();
        for node in repomd.children_named("data") {
            let kind = node
                .attr("type")
                .ok_or_else(|| Error::new("repomd.xml: <data> without type"))?
                .to_string();

            let location = node
                .find(&["location"])
                .and_then(|l| l.attr("href"))
                .ok_or_else(|| {
                    Error::new(format!("repomd.xml: {} data has no location", kind))
                })?
                .to_string();

            let checksum_node = node.find(&["checksum"]);
            let checksum_type = checksum_node
                .and_then(|c| c.attr("type"))
                .unwrap_or("sha256")
                .to_string();
            let checksum = checksum_node
                .map(|c| c.text.trim().to_string())
                .unwrap_or_default();

            let open = node.find(&["open-checksum"]);
            let open_checksum = open.map(|c| {
                (
                    c.attr("type").unwrap_or("sha256").to_string(),
                    c.text.trim().to_string(),
                )
            });

            let size = node
                .find(&["size"])
                .map(|s| s.text.trim().parse::<u64>().unwrap_or(0))
                .unwrap_or(0);
            let timestamp = node
                .find(&["timestamp"])
                .map(|t| t.text.trim().parse::<u64>().unwrap_or(0))
                .unwrap_or(0);

            data.push(RepoMdData {
                kind,
                location,
                checksum_type,
                checksum,
                open_checksum,
                size,
                timestamp,
            });
        }

        if data.is_empty() {
            return Err(Error::new("repomd.xml: no <data> entries found"));
        }
        Ok(RepoMd { revision, data })
    }

    pub fn get(&self, kind: &str) -> Option<&RepoMdData> {
        self.data.iter().find(|d| d.kind == kind)
    }

    pub fn primary(&self) -> Option<&RepoMdData> {
        self.get("primary")
    }

    pub fn filelists(&self) -> Option<&RepoMdData> {
        self.get("filelists")
    }
}

/// One `<package>` entry from `filelists.xml`: every file the package owns.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FileList {
    pub name: String,
    pub arch: String,
    pub epoch: u32,
    pub version: String,
    pub release: String,
    /// Paths exactly as rpm stores them, directories included.
    pub files: Vec<String>,
}

impl FileList {
    /// The same `name-[epoch:]version-release.arch` form `Package::nevra` uses,
    /// so file lists can be attached to the packages they belong to.
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
}

/// Mirrors advertised by a metalink document.
#[derive(Debug, Clone, Default)]
pub struct Metalink {
    /// Repository base URLs, in preference order.
    pub bases: Vec<String>,
}

impl Metalink {
    pub fn parse(text: &str) -> Result<Metalink> {
        let root = xml::parse(text)?;
        let mut bases = Vec::new();

        // Walk the document for every <url> element; metalink nests them under
        // files/file/resources, but the exact depth varies between repo types.
        fn walk(node: &xml::Node, out: &mut Vec<String>) {
            if node.name == "url" {
                let text = node.text.trim();
                if !text.is_empty() {
                    out.push(normalise_metalink_url(text));
                }
            }
            for child in &node.children {
                walk(child, out);
            }
        }
        walk(&root, &mut bases);

        // Deduplicate while keeping order (mirror lists often repeat).
        let mut seen = std::collections::HashSet::new();
        bases.retain(|b| seen.insert(b.clone()));

        if bases.is_empty() {
            return Err(Error::new("metalink contains no usable URLs"));
        }
        Ok(Metalink { bases })
    }
}

/// Metalink URLs point at `repodata/repomd.xml`; repositories want the root.
fn normalise_metalink_url(url: &str) -> String {
    let trimmed = url.trim();
    for suffix in ["/repodata/repomd.xml", "repodata/repomd.xml"] {
        if let Some(base) = trimmed.strip_suffix(suffix) {
            return base.trim_end_matches('/').to_string();
        }
    }
    trimmed.trim_end_matches('/').to_string()
}

/// Parse a plain-text mirrorlist (one base URL per line).
pub fn parse_mirrorlist(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        // Some mirrorlist servers prefix entries with "=" or whitespace.
        let line = line.trim_start_matches('=').trim();
        if line.starts_with("http://") || line.starts_with("https://") || line.starts_with("ftp://")
        {
            out.push(line.trim_end_matches('/').to_string());
        }
    }
    out
}

/// Strip a namespace prefix (`rpm:entry` -> `entry`).
fn local(name: &str) -> &str {
    match name.rfind(':') {
        Some(i) => &name[i + 1..],
        None => name,
    }
}

fn attr_u32(attrs: &[(&str, &str)], name: &str) -> u32 {
    attrs
        .iter()
        .find(|(k, _)| *k == name)
        .and_then(|(_, v)| v.trim().parse().ok())
        .unwrap_or(0)
}

fn attr_u64(attrs: &[(&str, &str)], name: &str) -> u64 {
    attrs
        .iter()
        .find(|(k, _)| *k == name)
        .and_then(|(_, v)| v.trim().parse().ok())
        .unwrap_or(0)
}

fn attr_str<'a>(attrs: &[(&'a str, &'a str)], name: &str) -> Option<&'a str> {
    attrs
        .iter()
        .find(|(k, _)| *k == name)
        .map(|(_, v)| *v)
}

/// Which dependency list a `<rpm:entry>` belongs to.
#[derive(Clone, Copy, PartialEq, Eq)]
enum DepKind {
    Provides,
    Requires,
    Conflicts,
    Obsoletes,
    Recommends,
    Suggests,
    Supplements,
    Enhances,
}

/// Parse a `primary.xml` document into packages.
///
/// Fedora's primary metadata for a full release is tens of megabytes of XML
/// with tens of thousands of packages, so this consumes the pull parser event
/// stream directly and never builds a DOM.
pub fn parse_primary(text: &str, repo_id: &str) -> Result<Vec<Package>> {
    let mut reader = Reader::new(text);
    let mut packages: Vec<Package> = Vec::new();
    let mut cur: Option<Package> = None;
    let mut target: Option<DepKind> = None;
    let mut in_format = false;

    while let Some(ev) = reader.next()? {
        match ev {
            Event::Start {
                name,
                attrs,
                self_closing,
            } => {
                let tag = local(name).to_string();
                let mut handled = false;

                if let Some(pkg) = cur.as_mut() {
                    if in_format {
                        match tag.as_str() {
                            "provides" => {
                                target = Some(DepKind::Provides);
                                handled = true;
                            }
                            "requires" => {
                                target = Some(DepKind::Requires);
                                handled = true;
                            }
                            "conflicts" => {
                                target = Some(DepKind::Conflicts);
                                handled = true;
                            }
                            "obsoletes" => {
                                target = Some(DepKind::Obsoletes);
                                handled = true;
                            }
                            "recommends" => {
                                target = Some(DepKind::Recommends);
                                handled = true;
                            }
                            "suggests" => {
                                target = Some(DepKind::Suggests);
                                handled = true;
                            }
                            "supplements" => {
                                target = Some(DepKind::Supplements);
                                handled = true;
                            }
                            "enhances" => {
                                target = Some(DepKind::Enhances);
                                handled = true;
                            }
                            "entry" => {
                                let dep = depend_from_attrs(&attrs);
                                if !dep.name.is_empty() {
                                    let list = match target {
                                        Some(DepKind::Provides) => &mut pkg.provides,
                                        Some(DepKind::Requires) => &mut pkg.requires,
                                        Some(DepKind::Conflicts) => &mut pkg.conflicts,
                                        Some(DepKind::Obsoletes) => &mut pkg.obsoletes,
                                        Some(DepKind::Recommends) => &mut pkg.recommends,
                                        Some(DepKind::Suggests) => &mut pkg.suggests,
                                        Some(DepKind::Supplements) => &mut pkg.supplements,
                                        Some(DepKind::Enhances) => &mut pkg.enhances,
                                        _ => &mut pkg.requires,
                                    };
                                    list.push(dep);
                                }
                                handled = true;
                            }
                            "file" => {
                                if !self_closing {
                                    let path = reader.text()?;
                                    if !path.is_empty() {
                                        pkg.files.push(path);
                                    }
                                }
                                handled = true;
                            }
                            "license" => {
                                pkg.license = reader.text()?;
                                handled = true;
                            }
                            "vendor" => {
                                pkg.vendor = reader.text()?;
                                handled = true;
                            }
                            "group" => {
                                pkg.group = reader.text()?;
                                handled = true;
                            }
                            "header-range" => handled = true,
                            _ => {}
                        }
                    } else {
                        match tag.as_str() {
                            "name" => {
                                pkg.name = reader.text()?;
                                handled = true;
                            }
                            "arch" => {
                                pkg.arch = reader.text()?;
                                handled = true;
                            }
                            "summary" => {
                                pkg.summary = reader.text()?.trim().to_string();
                                handled = true;
                            }
                            "description" => {
                                pkg.description = reader.text()?.trim().to_string();
                                handled = true;
                            }
                            "url" => {
                                pkg.url = reader.text()?.trim().to_string();
                                handled = true;
                            }
                            "packager" => {
                                pkg.packager = reader.text()?;
                                handled = true;
                            }
                            "version" => {
                                pkg.epoch = attr_u32(&attrs, "epoch");
                                pkg.version = attr_str(&attrs, "ver").unwrap_or("").to_string();
                                pkg.release = attr_str(&attrs, "rel").unwrap_or("").to_string();
                                handled = true;
                            }
                            "checksum" => {
                                if !self_closing {
                                    let algo = attr_str(&attrs, "type")
                                        .unwrap_or("sha256")
                                        .to_string();
                                    let value = reader.text()?;
                                    pkg.checksum = Some((algo, value.trim().to_string()));
                                }
                                handled = true;
                            }
                            "location" => {
                                pkg.location =
                                    xml::unescape(attr_str(&attrs, "href").unwrap_or(""));
                                handled = true;
                            }
                            "size" => {
                                pkg.download_size = attr_u64(&attrs, "package");
                                pkg.installed_size = attr_u64(&attrs, "installed");
                                handled = true;
                            }
                            "time" => {
                                pkg.buildtime = attr_u64(&attrs, "build");
                                handled = true;
                            }
                            "format" => {
                                in_format = true;
                                handled = true;
                            }
                            _ => {}
                        }
                    }
                }

                if tag == "package" && !in_format {
                    let mut p = Package {
                        repo: repo_id.to_string(),
                        ..Default::default()
                    };
                    // type="rpm" is the only kind RPF handles; "srpm" entries
                    // are skipped by callers via the arch.
                    if let Some(t) = attr_str(&attrs, "type") {
                        if t != "rpm" {
                            cur = None;
                            continue;
                        }
                    }
                    let _ = &mut p;
                    cur = Some(p);
                    handled = true;
                }

                let _ = handled;
            }
            Event::End { name } => {
                let tag = local(name);
                match tag {
                    "format" => {
                        in_format = false;
                        target = None;
                    }
                    "provides" | "requires" | "conflicts" | "obsoletes" | "recommends"
                    | "suggests" | "supplements" | "enhances" => {
                        target = None;
                    }
                    "package" => {
                        if let Some(pkg) = cur.take() {
                            if !pkg.name.is_empty() {
                                packages.push(pkg);
                            }
                        }
                        in_format = false;
                        target = None;
                    }
                    _ => {}
                }
            }
            Event::Text(_) => {}
        }
    }

    Ok(packages)
}

/// Parse `filelists.xml`: the complete file manifest of every package.
///
/// The document is far larger than `primary.xml`, so callers cache the parsed
/// result instead of keeping it in memory for every command.
pub fn parse_filelists(text: &str) -> Result<Vec<FileList>> {
    let mut reader = Reader::new(text);
    let mut out: Vec<FileList> = Vec::new();
    let mut cur: Option<FileList> = None;

    while let Some(ev) = reader.next()? {
        match ev {
            Event::Start {
                name,
                attrs,
                self_closing,
            } => match local(name) {
                "package" => {
                    let mut entry = FileList {
                        name: xml::unescape(attr_str(&attrs, "name").unwrap_or("")),
                        arch: xml::unescape(attr_str(&attrs, "arch").unwrap_or("")),
                        ..FileList::default()
                    };
                    entry.epoch = attr_u32(&attrs, "epoch");
                    cur = Some(entry);
                }
                "version" => {
                    if let Some(entry) = cur.as_mut() {
                        entry.epoch = attr_u32(&attrs, "epoch");
                        entry.version = xml::unescape(attr_str(&attrs, "ver").unwrap_or(""));
                        entry.release = xml::unescape(attr_str(&attrs, "rel").unwrap_or(""));
                    }
                }
                "file" => {
                    if !self_closing {
                        let path = reader.text()?;
                        if let Some(entry) = cur.as_mut() {
                            if !path.is_empty() {
                                entry.files.push(path);
                            }
                        }
                    }
                }
                _ => {}
            },
            Event::End { name } => {
                if local(name) == "package" {
                    if let Some(entry) = cur.take() {
                        if !entry.name.is_empty() {
                            out.push(entry);
                        }
                    }
                }
            }
            Event::Text(_) => {}
        }
    }

    Ok(out)
}

fn depend_from_attrs(attrs: &[(&str, &str)]) -> Depend {
    let name = xml::unescape(attr_str(attrs, "name").unwrap_or(""));
    let flags = DepFlags::parse(attr_str(attrs, "flags").unwrap_or(""));

    let ver = attr_str(attrs, "ver").unwrap_or("");
    let rel = attr_str(attrs, "rel").unwrap_or("");
    let evr = if ver.is_empty() {
        None
    } else {
        Some(Evr {
            epoch: attr_u32(attrs, "epoch"),
            version: ver.to_string(),
            release: if rel.is_empty() {
                None
            } else {
                Some(rel.to_string())
            },
        })
    };

    // Rich dependencies arrive as a name that is a parenthesised expression.
    let rich = if name.starts_with('(') {
        RichDep::parse(&name)
    } else {
        None
    };

    Depend {
        name,
        flags,
        evr,
        rich,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const REPOMD: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<repomd xmlns="http://linux.duke.edu/metadata/repo" xmlns:rpm="http://linux.duke.edu/metadata/rpm">
  <revision>1750000000</revision>
  <data type="primary">
    <checksum type="sha256">3f2a1c9b0d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8</checksum>
    <open-checksum type="sha256">aa11bb22cc33dd44ee55ff66aa77bb88cc99dd00ee11ff22aa33bb44cc55dd66</open-checksum>
    <location href="repodata/primary.xml.zst"/>
    <timestamp>1750000000</timestamp>
    <size>123456</size>
  </data>
  <data type="filelists">
    <checksum type="sha256">99887766554433221100ffeeddccbbaa99887766554433221100ffeeddccbbaa</checksum>
    <location href="repodata/filelists.xml.gz"/>
    <timestamp>1750000000</timestamp>
    <size>999</size>
  </data>
</repomd>"#;

    const PRIMARY: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<metadata xmlns="http://linux.duke.edu/metadata/common" xmlns:rpm="http://linux.duke.edu/metadata/rpm" packages="2">
<package type="rpm">
  <name>bash</name>
  <arch>x86_64</arch>
  <version epoch="0" ver="5.2.21" rel="1.fc41"/>
  <checksum type="sha256" pkgid="YES">deadbeef</checksum>
  <summary>The GNU Bourne Again shell</summary>
  <description>Bash is the default shell.</description>
  <packager>Fedora Project</packager>
  <url>https://www.gnu.org/software/bash/</url>
  <time file="1750000000" build="1740000000"/>
  <size package="1234567" installed="8765432" archive="9000000"/>
  <location href="Packages/b/bash-5.2.21-1.fc41.x86_64.rpm"/>
  <format>
    <rpm:license>GPL-3.0-or-later</rpm:license>
    <rpm:vendor>Fedora Project</rpm:vendor>
    <rpm:group>Unspecified</rpm:group>
    <rpm:header-range start="4504" end="123456"/>
    <rpm:provides>
      <rpm:entry name="bash" flags="EQ" epoch="0" ver="5.2.21" rel="1.fc41"/>
      <rpm:entry name="/bin/sh" flags="EQ" epoch="0" ver="5.2.21" rel="1.fc41"/>
      <rpm:entry name="bash(x86-64)" flags="EQ" epoch="0" ver="5.2.21" rel="1.fc41"/>
    </rpm:provides>
    <rpm:requires>
      <rpm:entry name="libc.so.6(GLIBC_2.38)(64bit)"/>
      <rpm:entry name="libtinfo.so.6()(64bit)"/>
      <rpm:entry name="rpmlib(PayloadIsZstd)" flags="LE" epoch="0" ver="5.4.18" rel="1"/>
      <rpm:entry name="glibc" flags="GE" epoch="0" ver="2.38"/>
      <rpm:entry name="(python3dist(setuptools) or python3dist(pip))"/>
    </rpm:requires>
    <rpm:recommends>
      <rpm:entry name="bash-completion"/>
    </rpm:recommends>
    <file type="dir">/etc/skel</file>
    <file>/usr/bin/bash</file>
  </format>
</package>
<package type="rpm">
  <name>tzdata</name>
  <arch>noarch</arch>
  <version epoch="0" ver="2024a" rel="2.fc41"/>
  <checksum type="sha256" pkgid="YES">cafebabe</checksum>
  <summary>Timezone data</summary>
  <description>World timezone definitions.</description>
  <time file="1750000000" build="1741000000"/>
  <size package="500000" installed="1500000" archive="1600000"/>
  <location href="Packages/t/tzdata-2024a-2.fc41.noarch.rpm"/>
  <format>
    <rpm:license>Public Domain</rpm:license>
    <rpm:provides><rpm:entry name="tzdata" flags="EQ" epoch="0" ver="2024a" rel="2.fc41"/></rpm:provides>
    <rpm:requires><rpm:entry name="rpmlib(CompressedFileNames) &lt;= 3.0.4-1"/></rpm:requires>
  </format>
</package>
</metadata>"#;

    #[test]
    fn parses_repomd() {
        let md = RepoMd::parse(REPOMD).unwrap();
        assert_eq!(md.revision, "1750000000");
        assert_eq!(md.data.len(), 2);

        let primary = md.primary().unwrap();
        assert_eq!(primary.location, "repodata/primary.xml.zst");
        assert_eq!(primary.checksum_type, "sha256");
        assert_eq!(primary.checksum.len(), 64);
        assert_eq!(primary.size, 123456);
        assert!(primary.open_checksum.is_some());
        assert_eq!(primary.timestamp, 1750000000);

        assert_eq!(
            md.filelists().unwrap().location,
            "repodata/filelists.xml.gz"
        );
        assert!(md.get("other").is_none());
    }

    #[test]
    fn parses_filelists() {
        let text = r#"<?xml version="1.0" encoding="UTF-8"?>
<filelists xmlns="http://linux.duke.edu/metadata/filelists" packages="2">
<package pkgid="abc123" name="bash" arch="x86_64">
  <version epoch="0" ver="5.2.21" rel="1.fc41"/>
  <file type="dir">/usr/share/doc/bash</file>
  <file>/usr/bin/bash</file>
  <file>/usr/share/man/man1/bash.1.gz</file>
</package>
<package pkgid="def456" name="kernel" arch="noarch">
  <version epoch="1" ver="6.12" rel="3.fc41"/>
  <file>/boot/vmlinuz</file>
</package>
</filelists>"#;
        let lists = parse_filelists(text).expect("filelists parse");
        assert_eq!(lists.len(), 2);

        assert_eq!(lists[0].name, "bash");
        assert_eq!(lists[0].arch, "x86_64");
        assert_eq!(lists[0].nevra(), "bash-5.2.21-1.fc41.x86_64");
        assert_eq!(
            lists[0].files,
            vec![
                "/usr/share/doc/bash",
                "/usr/bin/bash",
                "/usr/share/man/man1/bash.1.gz"
            ]
        );

        assert_eq!(lists[1].nevra(), "kernel-1:6.12-3.fc41.noarch");
        assert_eq!(lists[1].files, vec!["/boot/vmlinuz"]);
    }

    /// A repo that publishes no file lists must simply report none.
    #[test]
    fn filelists_absence_is_not_an_error() {
        let repomd = RepoMd::parse(REPOMD).expect("repomd");
        assert!(repomd.primary().is_some());
        let filelists = repomd.filelists().expect("fixture advertises filelists");
        assert_eq!(filelists.location, "repodata/filelists.xml.gz");
        assert_eq!(filelists.checksum_type, "sha256");

        let without = RepoMd::parse(
            r#"<repomd><revision>1</revision>
               <data type=\"primary\"><location href=\"repodata/primary.xml\"/></data></repomd>"#,
        )
        .expect("repomd");
        assert!(without.filelists().is_none());
        assert!(parse_filelists("<filelists/>").unwrap().is_empty());
    }

    #[test]
    fn parses_primary_packages() {
        let pkgs = parse_primary(PRIMARY, "fedora").unwrap();
        assert_eq!(pkgs.len(), 2);

        let bash = &pkgs[0];
        assert_eq!(bash.name, "bash");
        assert_eq!(bash.arch, "x86_64");
        assert_eq!(bash.version, "5.2.21");
        assert_eq!(bash.release, "1.fc41");
        assert_eq!(bash.epoch, 0);
        assert_eq!(bash.summary, "The GNU Bourne Again shell");
        assert_eq!(bash.license, "GPL-3.0-or-later");
        assert_eq!(bash.vendor, "Fedora Project");
        assert_eq!(bash.buildtime, 1740000000);
        assert_eq!(bash.download_size, 1234567);
        assert_eq!(bash.installed_size, 8765432);
        assert_eq!(bash.location, "Packages/b/bash-5.2.21-1.fc41.x86_64.rpm");
        assert_eq!(bash.checksum.as_ref().unwrap().0, "sha256");
        assert_eq!(bash.checksum.as_ref().unwrap().1, "deadbeef");
        assert_eq!(bash.repo, "fedora");
        assert_eq!(bash.files, vec!["/etc/skel", "/usr/bin/bash"]);
        assert_eq!(bash.nevra(), "bash-5.2.21-1.fc41.x86_64");

        // Provides, including the file capability.
        assert_eq!(bash.provides.len(), 3);
        assert!(bash.provides.iter().any(|p| p.name == "/bin/sh"));
        assert!(bash
            .provides
            .iter()
            .any(|p| p.name == "bash" && p.is_versioned()));

        // Requires, including the escaped rpmlib version.
        assert_eq!(bash.requires.len(), 5);
        let glibc = bash
            .requires
            .iter()
            .find(|r| r.name == "glibc")
            .expect("glibc requirement");
        assert_eq!(glibc.flags, DepFlags::GE);
        assert_eq!(glibc.evr.as_ref().unwrap().version, "2.38");

        let rpmlib = bash
            .requires
            .iter()
            .find(|r| r.name.starts_with("rpmlib("))
            .unwrap();
        assert_eq!(rpmlib.flags, DepFlags::LE);
        assert_eq!(rpmlib.evr.as_ref().unwrap().version, "5.4.18");
        assert_eq!(rpmlib.evr.as_ref().unwrap().release.as_deref(), Some("1"));

        // The rich dependency is preserved and parsed.
        let rich = bash
            .requires
            .iter()
            .find(|r| r.rich.is_some())
            .expect("rich dependency");
        assert_eq!(
            rich.rich.as_ref().unwrap().to_string(),
            "(python3dist(setuptools) or python3dist(pip))"
        );

        assert_eq!(bash.recommends.len(), 1);

        let tzdata = &pkgs[1];
        assert_eq!(tzdata.arch, "noarch");
        assert_eq!(tzdata.version, "2024a");
        assert!(tzdata.provides.iter().any(|p| p.name == "tzdata"));
    }

    #[test]
    fn ignores_non_rpm_package_types() {
        let xml = r#"<metadata>
<package type="srpm"><name>src</name><arch>src</arch></package>
<package type="rpm"><name>bin</name><arch>x86_64</arch><version epoch="0" ver="1" rel="1"/></package>
</metadata>"#;
        let pkgs = parse_primary(xml, "r").unwrap();
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].name, "bin");
    }

    #[test]
    fn metalink_extracts_bases() {
        let text = r#"<?xml version="1.0" encoding="UTF-8"?>
<metalink version="3.0" xmlns="http://www.metalinker.org/" xmlns:mm0="http://fedoraproject.org/metalink">
 <files>
  <file name="repomd.xml">
   <resources maxconnections="1">
    <url protocol="https" type="https" location="US" preference="100">https://mirror.example.com/fedora/releases/41/Everything/x86_64/os/repodata/repomd.xml</url>
    <url protocol="https" type="https" location="DE" preference="99">https://de.example.org/fedora/41/os/repodata/repomd.xml</url>
   </resources>
  </file>
 </files>
</metalink>"#;
        let ml = Metalink::parse(text).unwrap();
        assert_eq!(
            ml.bases,
            vec![
                "https://mirror.example.com/fedora/releases/41/Everything/x86_64/os",
                "https://de.example.org/fedora/41/os"
            ]
        );
    }

    #[test]
    fn metalink_deduplicates() {
        let text = "<metalink><files><file><resources>\
            <url>https://a/os/repodata/repomd.xml</url>\
            <url>https://a/os/repodata/repomd.xml</url>\
            </resources></file></files></metalink>";
        let ml = Metalink::parse(text).unwrap();
        assert_eq!(ml.bases, vec!["https://a/os"]);
    }

    #[test]
    fn mirrorlist_parsing() {
        let text = "# comment\nhttps://a.example/os/\n\nhttps://b.example/os\n= https://c.example/os\n";
        assert_eq!(
            parse_mirrorlist(text),
            vec![
                "https://a.example/os",
                "https://b.example/os",
                "https://c.example/os"
            ]
        );
    }

    #[test]
    fn repomd_without_data_is_rejected() {
        assert!(RepoMd::parse("<repomd><revision>1</revision></repomd>").is_err());
        assert!(RepoMd::parse("<repomd>").is_err());
    }
}
