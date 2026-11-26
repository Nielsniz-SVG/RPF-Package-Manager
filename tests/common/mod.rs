//! Test helpers: build real RPM files and repositories from scratch.
//!
//! The integration tests need packages whose contents they control (symlinks,
//! hardlinks, `%config(noreplace)`, conflicting paths) and repositories that
//! serve genuine `.rpm` files. This module writes both, following the on-disk
//! RPM format: lead, signature header, main header, cpio payload.

#![allow(dead_code)]

use std::fs;
use std::path::{Path, PathBuf};

use rpf::digest;

// ---------------------------------------------------------------------------
// Tag encoding
// ---------------------------------------------------------------------------

const TAG_TYPE_INT32: u32 = 4;
const TAG_TYPE_STRING: u32 = 6;
const TAG_TYPE_BIN: u32 = 7;
const TAG_TYPE_STRING_ARRAY: u32 = 8;

#[derive(Default)]
pub struct HeaderBuilder {
    entries: Vec<(u32, u32, Vec<u8>, u32)>, // tag, type, store bytes, count
    store: Vec<u8>,
}

impl HeaderBuilder {
    pub fn new() -> Self {
        HeaderBuilder::default()
    }

    fn push(&mut self, tag: u32, typ: u32, bytes: Vec<u8>, count: u32) {
        // Integers must be aligned to their width; strings are byte-packed.
        let align = match typ {
            TAG_TYPE_INT32 => 4,
            _ => 1,
        };
        while self.store.len() % align != 0 {
            self.store.push(0);
        }
        let offset = self.store.len() as u32;
        self.store.extend_from_slice(&bytes);
        self.entries.push((tag, typ, vec![], count));
        // Patch offset into the entry (stored positionally below).
        let idx = self.entries.len() - 1;
        self.entries[idx].2 = offset.to_be_bytes().to_vec();
    }

    pub fn string(mut self, tag: u32, value: &str) -> Self {
        let mut bytes = value.as_bytes().to_vec();
        bytes.push(0);
        self.push(tag, TAG_TYPE_STRING, bytes, 1);
        self
    }

    pub fn strings(mut self, tag: u32, values: &[String]) -> Self {
        let mut bytes = Vec::new();
        for v in values {
            bytes.extend_from_slice(v.as_bytes());
            bytes.push(0);
        }
        self.push(tag, TAG_TYPE_STRING_ARRAY, bytes, values.len() as u32);
        self
    }

    pub fn ints(mut self, tag: u32, values: &[i64]) -> Self {
        let mut bytes = Vec::new();
        for v in values {
            bytes.extend_from_slice(&(*v as i32).to_be_bytes());
        }
        self.push(tag, TAG_TYPE_INT32, bytes, values.len() as u32);
        self
    }

    pub fn int(self, tag: u32, value: i64) -> Self {
        self.ints(tag, &[value])
    }

    pub fn bin(mut self, tag: u32, data: &[u8]) -> Self {
        self.push(tag, TAG_TYPE_BIN, data.to_vec(), data.len() as u32);
        self
    }

    pub fn build(self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&[0x8e, 0xad, 0xe8, 0x01]);
        out.extend_from_slice(&[0, 0, 0, 0]);
        out.extend_from_slice(&(self.entries.len() as u32).to_be_bytes());
        out.extend_from_slice(&(self.store.len() as u32).to_be_bytes());

        for (tag, typ, offset_bytes, count) in &self.entries {
            out.extend_from_slice(&tag.to_be_bytes());
            out.extend_from_slice(&typ.to_be_bytes());
            out.extend_from_slice(offset_bytes);
            out.extend_from_slice(&count.to_be_bytes());
        }
        out.extend_from_slice(&self.store);
        out
    }
}

// ---------------------------------------------------------------------------
// cpio writing
// ---------------------------------------------------------------------------

pub struct CpioBuilder {
    out: Vec<u8>,
    ino: u32,
}

pub struct CpioEntrySpec {
    pub path: String,
    pub data: Vec<u8>,
    pub mode: u32,
    pub mtime: u64,
    pub nlink: u32,
    pub ino: Option<u32>,
}

impl CpioBuilder {
    pub fn new() -> Self {
        CpioBuilder {
            out: Vec::new(),
            ino: 1,
        }
    }

    pub fn add(mut self, mut entry: CpioEntrySpec) -> Self {
        let ino = entry.ino.unwrap_or_else(|| {
            self.ino += 1;
            self.ino
        });
        let name = entry.path.clone();
        let name_bytes = format!("{}\0", name).into_bytes();
        let mut header = String::from("070701");
        for field in [
            ino,
            entry.mode,
            0, // uid
            0, // gid
            entry.nlink,
            entry.mtime as u32,
            entry.data.len() as u32,
            0, // devmajor
            0, // devminor
            0, // rdevmajor
            0, // rdevminor
            name_bytes.len() as u32,
            0, // check
        ] {
            header.push_str(&format!("{:08x}", field));
        }
        self.out.extend_from_slice(header.as_bytes());
        self.out.extend_from_slice(&name_bytes);
        while self.out.len() % 4 != 0 {
            self.out.push(0);
        }
        if entry.mode & 0o170000 != 0o040000 {
            self.out.extend_from_slice(&entry.data);
            while self.out.len() % 4 != 0 {
                self.out.push(0);
            }
        }
        entry.data.clear();
        self
    }

    pub fn build(mut self) -> Vec<u8> {
        let mut header = String::from("070701");
        for field in [0u32, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 11, 0] {
            header.push_str(&format!("{:08x}", field));
        }
        self.out.extend_from_slice(header.as_bytes());
        self.out.extend_from_slice(b"TRAILER!!!\0");
        while self.out.len() % 4 != 0 {
            self.out.push(0);
        }
        self.out
    }
}

// ---------------------------------------------------------------------------
// RPM writing
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct FileSpec {
    pub path: String,
    pub content: Vec<u8>,
    pub mode: u32,
    /// RPMFILE_* flags (1 = %config, 8 = %config(noreplace), 64 = %ghost).
    pub flags: i64,
    pub symlink_target: Option<String>,
    pub hardlink_ino: Option<u32>,
    pub user: String,
    pub group: String,
}

impl FileSpec {
    pub fn new(path: &str, content: &str) -> FileSpec {
        FileSpec {
            path: path.to_string(),
            content: content.as_bytes().to_vec(),
            mode: 0o100644,
            flags: 0,
            symlink_target: None,
            hardlink_ino: None,
            user: "root".to_string(),
            group: "root".to_string(),
        }
    }

    pub fn executable(mut self) -> Self {
        self.mode = 0o100755;
        self
    }

    pub fn dir(path: &str) -> FileSpec {
        FileSpec {
            path: path.to_string(),
            content: Vec::new(),
            mode: 0o040755,
            ..FileSpec::new(path, "")
        }
    }

    pub fn symlink(path: &str, target: &str) -> FileSpec {
        FileSpec {
            path: path.to_string(),
            content: target.as_bytes().to_vec(),
            mode: 0o120777,
            symlink_target: Some(target.to_string()),
            ..FileSpec::new(path, "")
        }
    }

    pub fn config(mut self, noreplace: bool) -> Self {
        self.flags = if noreplace { 1 | 8 } else { 1 };
        self
    }

    pub fn ghost(mut self) -> Self {
        self.flags |= 64;
        self
    }

    pub fn hardlink(mut self, ino: u32) -> Self {
        self.hardlink_ino = Some(ino);
        self
    }
}

#[derive(Clone)]
pub struct PkgSpec {
    pub name: String,
    pub version: String,
    pub release: String,
    pub epoch: i64,
    pub arch: String,
    pub summary: String,
    pub license: String,
    pub files: Vec<FileSpec>,
    pub provides: Vec<String>,
    pub requires: Vec<String>,
    pub compress: bool,
    /// Emit a scriptlet into %post that touches this path (needs root to run).
    pub post_script: Option<String>,
}

impl PkgSpec {
    pub fn new(name: &str, version: &str) -> PkgSpec {
        PkgSpec {
            name: name.to_string(),
            version: version.to_string(),
            release: "1".to_string(),
            epoch: 0,
            arch: "noarch".to_string(),
            summary: format!("Test package {}", name),
            license: "MIT".to_string(),
            files: Vec::new(),
            provides: Vec::new(),
            requires: Vec::new(),
            compress: false,
            post_script: None,
        }
    }

    pub fn with_file(mut self, file: FileSpec) -> Self {
        self.files.push(file);
        self
    }

    pub fn with_requires(mut self, requirement: &str) -> Self {
        self.requires.push(requirement.to_string());
        self
    }

    pub fn with_provides(mut self, capability: &str) -> Self {
        self.provides.push(capability.to_string());
        self
    }

    pub fn compressed(mut self) -> Self {
        self.compress = true;
        self
    }

    pub fn nevra(&self) -> String {
        format!(
            "{}-{}-{}.{}",
            self.name, self.version, self.release, self.arch
        )
    }

    pub fn filename(&self) -> String {
        format!("{}.rpm", self.nevra())
    }
}

/// Build a complete, valid `.rpm` for the given specification.
pub fn build_rpm(spec: &PkgSpec) -> Vec<u8> {
    // --- payload -----------------------------------------------------------
    let mut cpio = CpioBuilder::new();
    let mut basenames: Vec<String> = Vec::new();
    let mut dirnames: Vec<String> = Vec::new();
    let mut dirindexes: Vec<i64> = Vec::new();
    let mut modes: Vec<i64> = Vec::new();
    let mut sizes: Vec<i64> = Vec::new();
    let mut mtimes: Vec<i64> = Vec::new();
    let mut flags: Vec<i64> = Vec::new();
    let mut users: Vec<String> = Vec::new();
    let mut groups: Vec<String> = Vec::new();
    let mut links: Vec<String> = Vec::new();
    let mut digests: Vec<String> = Vec::new();
    let mtime = 1_700_000_000u64;

    for file in &spec.files {
        let (dir, base) = match file.path.rfind('/') {
            Some(i) => (format!("{}/", &file.path[..i]), file.path[i + 1..].to_string()),
            None => ("/".to_string(), file.path.clone()),
        };
        let dir = if dir.is_empty() {
            "/".to_string()
        } else {
            dir
        };
        let dir_index = match dirnames.iter().position(|d| *d == dir) {
            Some(i) => i as i64,
            None => {
                dirnames.push(dir);
                (dirnames.len() - 1) as i64
            }
        };

        basenames.push(base);
        dirindexes.push(dir_index);
        modes.push(file.mode as i64);
        sizes.push(file.content.len() as i64);
        mtimes.push(mtime as i64);
        flags.push(file.flags);
        users.push(file.user.clone());
        groups.push(file.group.clone());
        links.push(file.symlink_target.clone().unwrap_or_default());
        digests.push(if file.mode & 0o170000 == 0o100000 {
            digest::hex(&digest::sha256(&file.content))
        } else {
            String::new()
        });

        // %ghost entries exist in the header but not in the payload.
        if file.flags & 64 != 0 {
            continue;
        }

        let payload_path = format!(".{}", file.path);
        cpio = cpio.add(CpioEntrySpec {
            path: payload_path,
            data: file.content.clone(),
            mode: file.mode,
            mtime,
            nlink: if file.hardlink_ino.is_some() { 2 } else { 1 },
            ino: file.hardlink_ino,
        });
    }
    let cpio_data = cpio.build();

    let (stored, compressor) = if spec.compress {
        (gzip(&cpio_data), "gzip")
    } else {
        (cpio_data.clone(), "")
    };
    let payload_digest = digest::hex(&digest::sha256(&stored));

    // --- main header -------------------------------------------------------
    let mut h = HeaderBuilder::new()
        .string(1000, &spec.name)
        .string(1001, &spec.version)
        .string(1002, &spec.release)
        .string(1022, &spec.arch)
        .string(1004, &spec.summary)
        .string(1005, &format!("{} (test build)", spec.summary))
        .string(1014, &spec.license)
        .string(1016, "Unspecified")
        .string(1020, "https://example.org")
        .string(1124, "cpio")
        .string(5092, &payload_digest)
        .int(5093, 8)
        .int(5011, 8)
        .int(1006, mtime as i64)
        .int(1009, spec.files.iter().map(|f| f.content.len() as i64).sum())
        .strings(1117, &basenames)
        .strings(1118, &dirnames)
        .ints(1116, &dirindexes)
        .ints(1030, &modes)
        .ints(1028, &sizes)
        .ints(1034, &mtimes)
        .ints(1037, &flags)
        .strings(1039, &users)
        .strings(1040, &groups)
        .strings(1036, &links)
        .strings(1035, &digests);

    if !compressor.is_empty() {
        h = h.string(1125, compressor);
    }
    if spec.epoch != 0 {
        h = h.int(1003, spec.epoch);
    }
    if let Some(script) = &spec.post_script {
        h = h.string(1024, script);
    }

    // Dependency tags: names/flags/versions triples.
    let mut provide_names = vec![format!("{}-{}-{}", spec.name, spec.version, spec.release)];
    provide_names.extend(spec.provides.clone());
    let mut provide_flags = vec![8i64]; // EQUAL
    provide_flags.extend(std::iter::repeat(0).take(spec.provides.len()));
    let mut provide_versions = vec![format!("{}-{}", spec.version, spec.release)];
    provide_versions.extend(std::iter::repeat(String::new()).take(spec.provides.len()));

    h = h
        .strings(1047, &provide_names)
        .ints(1112, &provide_flags)
        .strings(1113, &provide_versions);

    if !spec.requires.is_empty() {
        h = h
            .strings(1049, &spec.requires)
            .ints(1048, &vec![0i64; spec.requires.len()])
            .strings(1050, &vec![String::new(); spec.requires.len()]);
    }

    let main_header = h.build();

    // --- signature header --------------------------------------------------
    let signature = HeaderBuilder::new()
        .int(1000, 0) // RPMSIGTAG_SIZE is patched below in a real build
        .bin(1004, &[0u8; 16])
        .build();

    // --- assemble ----------------------------------------------------------
    let mut out = Vec::new();
    // Lead: 96 bytes.
    out.extend_from_slice(&[0xed, 0xab, 0xee, 0xdb]);
    out.push(3); // major
    out.push(0); // minor
    out.extend_from_slice(&0u16.to_be_bytes()); // type: binary
    out.extend_from_slice(&1u16.to_be_bytes()); // archnum
    let mut lead_name = spec.nevra().into_bytes();
    lead_name.truncate(65);
    lead_name.resize(66, 0);
    out.extend_from_slice(&lead_name);
    out.extend_from_slice(&1u16.to_be_bytes()); // osnum: Linux
    out.extend_from_slice(&5u16.to_be_bytes()); // signature type: header+payload
    out.extend_from_slice(&[0u8; 16]); // reserved
    assert_eq!(out.len(), 96);

    out.extend_from_slice(&signature);
    while out.len() % 8 != 0 {
        out.push(0);
    }
    out.extend_from_slice(&main_header);
    out.extend_from_slice(&stored);
    out
}

fn gzip(data: &[u8]) -> Vec<u8> {
    use std::io::Write;
    use std::process::{Command, Stdio};

    let mut child = Command::new("gzip")
        .arg("-c")
        .arg("-n")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("gzip is required to build compressed test packages");
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(data)
        .expect("write to gzip");
    let out = child.wait_with_output().expect("gzip output");
    assert!(out.status.success(), "gzip failed");
    out.stdout
}

// ---------------------------------------------------------------------------
// Repository fixture
// ---------------------------------------------------------------------------

pub struct RepoFixture {
    pub root: PathBuf,
}

impl RepoFixture {
    pub fn new(tag: &str) -> RepoFixture {
        let root = std::env::temp_dir().join(format!("rpf-repo-{}-{}", tag, std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("repo/repodata")).unwrap();
        fs::create_dir_all(root.join("repo/Packages")).unwrap();
        fs::create_dir_all(root.join("repos.d")).unwrap();
        fs::create_dir_all(root.join("cache")).unwrap();
        fs::create_dir_all(root.join("db")).unwrap();
        RepoFixture { root }
    }

    pub fn path(&self, rel: &str) -> PathBuf {
        self.root.join(rel)
    }

    /// Write the given packages and generate metadata for the repository.
    pub fn publish(&self, packages: &[PkgSpec]) -> Vec<PathBuf> {
        let mut written = Vec::new();
        let mut primary = String::from(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
             <metadata xmlns=\"http://linux.duke.edu/metadata/common\" \
             xmlns:rpm=\"http://linux.duke.edu/metadata/rpm\">\n",
        );

        for spec in packages {
            let rpm = build_rpm(spec);
            let file_path = self.path(&format!("repo/Packages/{}", spec.filename()));
            fs::write(&file_path, &rpm).unwrap();
            written.push(file_path);

            let checksum = digest::hex(&digest::sha256(&rpm));
            let provides = std::iter::once(format!(
                "<rpm:entry name=\"{}\" flags=\"EQ\" epoch=\"{}\" ver=\"{}\" rel=\"{}\"/>",
                spec.name, spec.epoch, spec.version, spec.release
            ))
            .chain(spec.provides.iter().map(|p| {
                format!("<rpm:entry name=\"{}\"/>", p)
            }))
            .collect::<String>();
            let requires = spec
                .requires
                .iter()
                .map(|r| format!("<rpm:entry name=\"{}\"/>", r))
                .collect::<String>();

            primary.push_str(&format!(
                r#"<package type="rpm">
  <name>{name}</name><arch>{arch}</arch>
  <version epoch="{epoch}" ver="{version}" rel="{release}"/>
  <checksum type="sha256" pkgid="YES">{checksum}</checksum>
  <summary>{summary}</summary><description>{summary}</description>
  <packager>RPF tests</packager><url>https://example.org</url>
  <time file="{mtime}" build="{mtime}"/>
  <size package="{size}" installed="{size}" archive="{size}"/>
  <location href="Packages/{filename}"/>
  <format>
    <rpm:license>{license}</rpm:license><rpm:vendor>RPF</rpm:vendor>
    <rpm:group>Unspecified</rpm:group>
    <rpm:header-range start="1000" end="2000"/>
    <rpm:provides>{provides}</rpm:provides>
    <rpm:requires>{requires}</rpm:requires>
  </format>
</package>
"#,
                name = spec.name,
                arch = spec.arch,
                epoch = spec.epoch,
                version = spec.version,
                release = spec.release,
                checksum = checksum,
                summary = spec.summary,
                mtime = 1_700_000_000,
                size = rpm.len(),
                filename = spec.filename(),
                license = spec.license,
                provides = provides,
                requires = requires,
            ));
        }
        primary.push_str("</metadata>\n");

        let plain = self.path("repo/repodata/primary.xml");
        fs::write(&plain, &primary).unwrap();
        let compressed = gzip(primary.as_bytes());
        let gz = self.path("repo/repodata/primary.xml.gz");
        fs::write(&gz, &compressed).unwrap();

        let repomd = format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
             <repomd xmlns=\"http://linux.duke.edu/metadata/repo\">\
             <revision>1700000000</revision><data type=\"primary\">\
             <checksum type=\"sha256\">{}</checksum>\
             <open-checksum type=\"sha256\">{}</open-checksum>\
             <location href=\"repodata/primary.xml.gz\"/>\
             <timestamp>1700000000</timestamp><size>{}</size>\
             </data></repomd>\n",
            digest::hex(&digest::sha256(&compressed)),
            digest::hex(&digest::sha256(primary.as_bytes())),
            compressed.len()
        );
        fs::write(self.path("repo/repodata/repomd.xml"), repomd).unwrap();

        let repo_file = self.path("repos.d/test.repo");
        fs::write(
            &repo_file,
            format!(
                "[test]\nname=RPF Test Repo\nbaseurl=file://{}\nenabled=1\ngpgcheck=0\n",
                self.path("repo").display()
            ),
        )
        .unwrap();

        written
    }

    pub fn installroot(&self) -> PathBuf {
        self.path("root")
    }

    pub fn ensure_installroot(&self) -> PathBuf {
        let root = self.installroot();
        fs::create_dir_all(&root).unwrap();
        root
    }

    /// Run the rpf binary against this fixture.
    pub fn rpf(&self, args: &[&str]) -> std::process::Output {
        let bin = env!("CARGO_BIN_EXE_rpf");
        std::process::Command::new(bin)
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

    /// Run rpf with `--installroot` pointed at a scratch root. Cache and
    /// database follow the install root, as they would on a real system, so
    /// each test is fully self-contained.
    pub fn rpf_root(&self, args: &[&str]) -> std::process::Output {
        let root = self.ensure_installroot();
        let mut full: Vec<String> = vec!["--installroot".to_string(), root.display().to_string()];
        full.extend(args.iter().map(|s| s.to_string()));
        let refs: Vec<&str> = full.iter().map(|s| s.as_str()).collect();

        std::process::Command::new(env!("CARGO_BIN_EXE_rpf"))
            .args(&refs)
            .env("RPF_REPOSDIR", self.path("repos.d"))
            .env("RPF_RELEASEVER", "41")
            .env("RPF_BASEARCH", "x86_64")
            .env_remove("RPF_CACHEDIR")
            .env_remove("RPF_DBPATH")
            .env_remove("RPF_INSTALLROOT")
            .output()
            .expect("failed to run rpf")
    }
}

impl Drop for RepoFixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

pub fn text(output: &std::process::Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

pub fn assert_success(output: &std::process::Output, context: &str) {
    assert!(
        output.status.success(),
        "{} failed:\n{}",
        context,
        text(output)
    );
}

pub fn file_exists(path: &Path) -> bool {
    path.symlink_metadata().is_ok()
}

pub fn read(path: &Path) -> String {
    fs::read_to_string(path).unwrap_or_default()
}
