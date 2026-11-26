//! RPM package format: lead, headers, tags and cpio payload.
//!
//! Implemented from the on-disk format rather than by linking `librpm`:
//!
//! ```text
//! ┌──────────────┬───────────────────┬───────────────┬─────────────────────┐
//! │ lead (96 B)  │ signature header  │ main header   │ payload (cpio)      │
//! └──────────────┴───────────────────┴───────────────┴─────────────────────┘
//!                  padded to 8 bytes
//! ```
//!
//! A header is `magic(3) version(1) reserved(4) nindex(4) hsize(4)` followed by
//! `nindex` 16-byte index entries and an `hsize` byte data store. Tag offsets
//! are relative to the start of that store.

use crate::deps::{Depend, DepFlags, RichDep};
use crate::fetch::Compression;
use crate::pkg::Package;
use crate::version::Evr;
use crate::{digest, Error, Result};
use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::path::Path;

pub const LEAD_SIZE: usize = 96;
pub const HEADER_MAGIC: [u8; 3] = [0x8e, 0xad, 0xe8];

/// Tag identifiers RPF uses.
pub mod tag {
    // Main header.
    pub const NAME: u32 = 1000;
    pub const VERSION: u32 = 1001;
    pub const RELEASE: u32 = 1002;
    pub const EPOCH: u32 = 1003;
    pub const SUMMARY: u32 = 1004;
    pub const DESCRIPTION: u32 = 1005;
    pub const BUILDTIME: u32 = 1006;
    pub const SIZE: u32 = 1009;
    pub const VENDOR: u32 = 1011;
    pub const LICENSE: u32 = 1014;
    pub const PACKAGER: u32 = 1015;
    pub const GROUP: u32 = 1016;
    pub const URL: u32 = 1020;
    pub const ARCH: u32 = 1022;
    pub const PREIN: u32 = 1023;
    pub const POSTIN: u32 = 1024;
    pub const PREUN: u32 = 1025;
    pub const POSTUN: u32 = 1026;
    pub const PREINPROG: u32 = 1085;
    pub const POSTINPROG: u32 = 1086;
    pub const PREUNPROG: u32 = 1087;
    pub const POSTUNPROG: u32 = 1088;
    pub const FILESIZES: u32 = 1028;
    pub const FILEMODES: u32 = 1030;
    pub const FILERDEVS: u32 = 1033;
    pub const FILEMTIMES: u32 = 1034;
    pub const FILEDIGESTS: u32 = 1035;
    pub const FILELINKTOS: u32 = 1036;
    pub const FILEFLAGS: u32 = 1037;
    pub const FILEUSERNAME: u32 = 1039;
    pub const FILEGROUPNAME: u32 = 1040;
    pub const SOURCERPM: u32 = 1044;
    pub const PROVIDENAME: u32 = 1047;
    pub const REQUIREFLAGS: u32 = 1048;
    pub const REQUIRENAME: u32 = 1049;
    pub const REQUIREVERSION: u32 = 1050;
    pub const CONFLICTFLAGS: u32 = 1053;
    pub const CONFLICTNAME: u32 = 1054;
    pub const CONFLICTVERSION: u32 = 1055;
    pub const OBSOLETENAME: u32 = 1090;
    pub const PROVIDEFLAGS: u32 = 1112;
    pub const PROVIDEVERSION: u32 = 1113;
    pub const OBSOLETEFLAGS: u32 = 1114;
    pub const OBSOLETEVERSION: u32 = 1115;
    pub const DIRINDEXES: u32 = 1116;
    pub const BASENAMES: u32 = 1117;
    pub const DIRNAMES: u32 = 1118;
    pub const PAYLOADFORMAT: u32 = 1124;
    pub const PAYLOADCOMPRESSOR: u32 = 1125;
    pub const PAYLOADFLAGS: u32 = 1126;
    pub const FILEDIGESTALGO: u32 = 5011;
    pub const RECOMMENDNAME: u32 = 5046;
    pub const RECOMMENDFLAGS: u32 = 5047;
    pub const RECOMMENDVERSION: u32 = 5048;
    pub const SUGGESTNAME: u32 = 5049;
    pub const SUGGESTFLAGS: u32 = 5050;
    pub const SUGGESTVERSION: u32 = 5051;
    pub const SUPPLEMENTNAME: u32 = 5052;
    pub const SUPPLEMENTFLAGS: u32 = 5053;
    pub const SUPPLEMENTVERSION: u32 = 5054;
    pub const ENHANCENAME: u32 = 5055;
    pub const ENHANCEFLAGS: u32 = 5056;
    pub const ENHANCEVERSION: u32 = 5057;
    pub const PAYLOADDIGEST: u32 = 5092;
    pub const PAYLOADDIGESTALGO: u32 = 5093;

    // Signature header.
    pub const SIG_RSA: u32 = 268;
    pub const SIG_DSA: u32 = 267;
    pub const SIG_SHA1: u32 = 269;
    pub const SIG_SHA256: u32 = 273;
    pub const SIG_SIZE: u32 = 1000;
    pub const SIG_MD5: u32 = 1004;
    /// Legacy v3 signature covering header *and* payload.
    pub const SIG_PGP: u32 = 1002;
    pub const SIG_GPG: u32 = 1005;
    pub const SIG_PAYLOADSIZE: u32 = 1007;
    pub const SIG_RESERVEDSPACE: u32 = 1008;
    pub const SIG_LONGSIZE: u32 = 270;
    pub const SIG_LONGARCHIVESIZE: u32 = 271;
}

/// File flags (`RPMFILE_*`) from tag `FILEFLAGS`.
pub mod fileflag {
    pub const CONFIG: i64 = 1 << 0;
    pub const DOC: i64 = 1 << 1;
    pub const MISSINGOK: i64 = 1 << 2;
    pub const NOREPLACE: i64 = 1 << 3;
    // Values match rpm's rpmfileAttrs enum.
    pub const GHOST: i64 = 1 << 6;
    pub const LICENSE: i64 = 1 << 7;
    pub const README: i64 = 1 << 8;
    pub const ARTIFACT: i64 = 1 << 12;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TagType {
    Null,
    Char,
    Int8,
    Int16,
    Int32,
    Int64,
    String,
    Bin,
    StringArray,
    I18nString,
}

impl TagType {
    fn from_u32(v: u32) -> TagType {
        match v {
            0 => TagType::Null,
            1 => TagType::Char,
            2 => TagType::Int8,
            3 => TagType::Int16,
            4 => TagType::Int32,
            5 => TagType::Int64,
            6 => TagType::String,
            7 => TagType::Bin,
            8 => TagType::StringArray,
            9 => TagType::I18nString,
            _ => TagType::Null,
        }
    }
}

#[derive(Debug, Clone)]
struct IndexEntry {
    tag: u32,
    typ: u32,
    offset: u32,
    count: u32,
}

/// A parsed RPM header (either the signature header or the main header).
#[derive(Debug, Clone, Default)]
pub struct Header {
    entries: Vec<IndexEntry>,
    store: Vec<u8>,
}

impl Header {
    fn parse(data: &[u8]) -> Result<(Header, usize)> {
        if data.len() < 16 {
            return Err(Error::new("header: truncated"));
        }
        if data[0..3] != HEADER_MAGIC {
            return Err(Error::new(format!(
                "header: bad magic {:02x?}",
                &data[0..3]
            )));
        }
        let nindex = be32(&data[8..12]) as usize;
        let hsize = be32(&data[12..16]) as usize;

        // Guard against absurd values before allocating.
        if nindex > 100_000 || hsize > 256 * 1024 * 1024 {
            return Err(Error::new("header: implausible index/size"));
        }
        let index_end = 16 + nindex * 16;
        let total = index_end + hsize;
        if data.len() < total {
            return Err(Error::new("header: truncated data store"));
        }

        let mut entries = Vec::with_capacity(nindex);
        for i in 0..nindex {
            let base = 16 + i * 16;
            entries.push(IndexEntry {
                tag: be32(&data[base..base + 4]),
                typ: be32(&data[base + 4..base + 8]),
                offset: be32(&data[base + 8..base + 12]),
                count: be32(&data[base + 12..base + 16]),
            });
        }
        let store = data[index_end..total].to_vec();
        Ok((Header { entries, store }, total))
    }

    pub fn has(&self, tag: u32) -> bool {
        self.entries.iter().any(|e| e.tag == tag)
    }

    fn entry(&self, tag: u32) -> Option<&IndexEntry> {
        self.entries.iter().find(|e| e.tag == tag)
    }

    pub fn tag_type(&self, tag: u32) -> Option<TagType> {
        self.entry(tag).map(|e| TagType::from_u32(e.typ))
    }

    /// Raw bytes of a binary or string tag.
    pub fn bin(&self, tag: u32) -> Option<&[u8]> {
        let e = self.entry(tag)?;
        let start = e.offset as usize;
        if start > self.store.len() {
            return None;
        }
        let len = match TagType::from_u32(e.typ) {
            TagType::Bin => e.count as usize,
            TagType::String => {
                // A STRING with count > 1 is a list of NUL-terminated strings.
                let mut end = start;
                for _ in 0..e.count.max(1) {
                    end = start + self.store[start..].iter().position(|b| *b == 0)?;
                    if end + 1 <= self.store.len() {
                        end += 1;
                    }
                }
                end - start
            }
            _ => return None,
        };
        self.store.get(start..start + len)
    }

    /// All strings of a STRING / STRING_ARRAY / I18NSTRING tag.
    pub fn strings(&self, tag: u32) -> Vec<String> {
        let Some(e) = self.entry(tag) else { return Vec::new() };
        let typ = TagType::from_u32(e.typ);
        let mut out = Vec::new();

        match typ {
            TagType::String | TagType::StringArray | TagType::I18nString => {
                let mut pos = e.offset as usize;
                for _ in 0..e.count {
                    if pos >= self.store.len() {
                        break;
                    }
                    let end = match self.store[pos..].iter().position(|b| *b == 0) {
                        Some(i) => pos + i,
                        None => self.store.len(),
                    };
                    out.push(String::from_utf8_lossy(&self.store[pos..end]).to_string());
                    pos = end + 1;
                }
            }
            TagType::Bin => {
                // Some producers store strings as BIN; take one string.
                if let Some(bytes) = self.bin(tag) {
                    out.push(String::from_utf8_lossy(bytes).to_string());
                }
            }
            _ => {}
        }
        out
    }

    pub fn string(&self, tag: u32) -> Option<String> {
        self.strings(tag).into_iter().next()
    }

    /// Integer tags. rpm uses INT8/16/32/64 and, occasionally, CHAR.
    pub fn ints(&self, tag: u32) -> Vec<i64> {
        let Some(e) = self.entry(tag) else { return Vec::new() };
        let typ = TagType::from_u32(e.typ);
        let size = match typ {
            TagType::Char | TagType::Int8 => 1,
            TagType::Int16 => 2,
            TagType::Int32 => 4,
            TagType::Int64 => 8,
            _ => return Vec::new(),
        };
        let start = e.offset as usize;
        let mut out = Vec::with_capacity(e.count as usize);
        for i in 0..e.count as usize {
            let p = start + i * size;
            if p + size > self.store.len() {
                break;
            }
            let v = match size {
                1 => self.store[p] as i64,
                2 => be16(&self.store[p..p + 2]) as i64,
                4 => be32(&self.store[p..p + 4]) as i64,
                _ => be64(&self.store[p..p + 8]) as i64,
            };
            out.push(v);
        }
        out
    }

    pub fn int(&self, tag: u32) -> Option<i64> {
        self.ints(tag).into_iter().next()
    }
}

struct Lead {
    major: u8,
    signature_type: u16,
}

impl Lead {
    fn parse(data: &[u8]) -> Result<Lead> {
        if data.len() < 4 || data[0..4] != [0xed, 0xab, 0xee, 0xdb] {
            return Err(Error::new(format!(
                "not an RPM package (bad lead magic {:02x?})",
                &data[..data.len().min(4)]
            )));
        }
        if data.len() < LEAD_SIZE {
            return Err(Error::new("not an RPM package (truncated lead)"));
        }
        Ok(Lead {
            major: data[4],
            signature_type: be16(&data[78..80]),
        })
    }
}

/// One entry from an RPM payload (cpio archive).
#[derive(Debug, Clone)]
pub struct CpioEntry<'a> {
    /// Path as stored in the archive, relative (no leading slash).
    pub name: String,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub nlink: u32,
    pub mtime: u64,
    pub size: u64,
    pub rdevmajor: u32,
    pub rdevminor: u32,
    pub ino: u32,
    pub data: &'a [u8],
}

impl CpioEntry<'_> {
    pub fn is_dir(&self) -> bool {
        self.mode & 0o170000 == 0o040000
    }
    pub fn is_symlink(&self) -> bool {
        self.mode & 0o170000 == 0o120000
    }
    pub fn is_regular(&self) -> bool {
        self.mode & 0o170000 == 0o100000
    }
    pub fn is_fifo(&self) -> bool {
        self.mode & 0o170000 == 0o010000
    }
    pub fn is_chardev(&self) -> bool {
        self.mode & 0o170000 == 0o020000
    }
    pub fn is_blockdev(&self) -> bool {
        self.mode & 0o170000 == 0o060000
    }
    pub fn is_socket(&self) -> bool {
        self.mode & 0o170000 == 0o140000
    }
    /// Permission bits only.
    pub fn perms(&self) -> u32 {
        self.mode & 0o7777
    }
}

/// Iterate a `newc`/`crc` cpio archive.
pub struct CpioReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> CpioReader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        CpioReader { data, pos: 0 }
    }

    fn align4(&mut self) {
        let rem = self.pos % 4;
        if rem != 0 {
            self.pos += 4 - rem;
        }
    }

    pub fn next_entry(&mut self) -> Result<Option<CpioEntry<'a>>> {
        if self.pos + 110 > self.data.len() {
            return Ok(None);
        }
        let header = &self.data[self.pos..self.pos + 110];
        let magic = &header[0..6];
        if magic != b"070701" && magic != b"070702" {
            return Err(Error::new(format!(
                "payload: unsupported cpio magic {:?} (expected newc '070701')",
                String::from_utf8_lossy(magic)
            )));
        }

        let field = |i: usize| -> Result<u64> {
            let start = 6 + i * 8;
            let s = std::str::from_utf8(&header[start..start + 8])
                .map_err(|_| Error::new("payload: invalid cpio header field"))?;
            u64::from_str_radix(s, 16)
                .map_err(|_| Error::new(format!("payload: invalid cpio hex field {:?}", s)))
        };

        let ino = field(0)? as u32;
        let mode = field(1)? as u32;
        let uid = field(2)? as u32;
        let gid = field(3)? as u32;
        let nlink = field(4)? as u32;
        let mtime = field(5)?;
        let size = field(6)?;
        let rdevmajor = field(9)? as u32;
        let rdevminor = field(10)? as u32;
        let namesize = field(11)? as usize;

        if namesize == 0 || namesize > 1 << 16 {
            return Err(Error::new("payload: implausible cpio name length"));
        }

        let name_start = self.pos + 110;
        let name_end = name_start + namesize;
        if name_end > self.data.len() {
            return Err(Error::new("payload: truncated cpio name"));
        }
        let raw_name = &self.data[name_start..name_end];
        let name = String::from_utf8_lossy(raw_name)
            .trim_end_matches('\0')
            .to_string();

        // Advance past the header + name, then 4-byte align.
        self.pos = name_end;
        self.align4();

        if name == "TRAILER!!!" {
            return Ok(None);
        }

        let data_start = self.pos;
        let data_end = data_start
            .checked_add(size as usize)
            .ok_or_else(|| Error::new("payload: cpio size overflow"))?;
        if data_end > self.data.len() {
            return Err(Error::new(format!(
                "payload: truncated cpio entry {:?}",
                name
            )));
        }
        let data = &self.data[data_start..data_end];
        self.pos = data_end;
        self.align4();

        Ok(Some(CpioEntry {
            name,
            mode,
            uid,
            gid,
            nlink,
            mtime,
            size,
            rdevmajor,
            rdevminor,
            ino,
            data,
        }))
    }
}

/// Scriptlets carried by a package.
///
/// `prein_prog` and friends are the interpreter the scriptlet asks for. rpm
/// defaults to `/bin/sh`, but packages may specify others, most commonly
/// `%post -p /sbin/ldconfig` with an empty body.
#[derive(Debug, Clone, Default)]
pub struct Scriptlets {
    pub prein: Option<String>,
    pub postin: Option<String>,
    pub preun: Option<String>,
    pub postun: Option<String>,
    pub prein_prog: Option<String>,
    pub postin_prog: Option<String>,
    pub preun_prog: Option<String>,
    pub postun_prog: Option<String>,
}

impl Scriptlets {
    pub fn is_empty(&self) -> bool {
        self.prein.is_none()
            && self.postin.is_none()
            && self.preun.is_none()
            && self.postun.is_none()
    }

    /// The interpreter rpm would use; `/bin/sh` when the package does not say.
    pub fn interpreter(prog: &Option<String>) -> String {
        prog.clone().unwrap_or_else(|| "/bin/sh".to_string())
    }

    /// Embedded interpreters (`%post -p <lua>`) cannot be run by RPF.
    pub fn is_embedded(prog: &str) -> bool {
        prog.starts_with('<') && prog.ends_with('>')
    }
}

/// A fully parsed `.rpm` file.
pub struct Rpm {
    pub path: std::path::PathBuf,
    pub lead_major: u8,
    pub signature_type: u16,
    pub signature: Header,
    pub header: Header,
    /// Byte offset of the main header.
    pub main_header_offset: usize,
    /// Byte offset where the payload begins.
    pub payload_offset: usize,
    data: Vec<u8>,
}

impl Rpm {
    /// Parse an RPM held in memory.
    pub fn parse(data: Vec<u8>) -> Result<Rpm> {
        let lead = Lead::parse(&data)?;

        let (signature, sig_len) = Header::parse(
            data.get(LEAD_SIZE..)
                .ok_or_else(|| Error::new("truncated after lead"))?,
        )?;
        let sig_end = LEAD_SIZE + sig_len;
        // The signature header is padded so the main header is 8-byte aligned.
        let pad = (8 - (sig_len % 8)) % 8;
        let main_start = sig_end + pad;

        let (header, main_len) = Header::parse(
            data.get(main_start..)
                .ok_or_else(|| Error::new("truncated after signature header"))?,
        )?;
        let payload_offset = main_start + main_len;

        Ok(Rpm {
            path: std::path::PathBuf::new(),
            lead_major: lead.major,
            signature_type: lead.signature_type,
            signature,
            header,
            main_header_offset: main_start,
            payload_offset,
            data,
        })
    }

    /// Open and parse an RPM file.
    pub fn open(path: &Path) -> Result<Rpm> {
        let mut file =
            File::open(path).map_err(|e| Error::new(format!("{}: {}", path.display(), e)))?;
        let mut data = Vec::new();
        file.read_to_end(&mut data)
            .map_err(|e| Error::new(format!("{}: {}", path.display(), e)))?;
        let mut rpm = Rpm::parse(data).map_err(|e| e.context(path.display().to_string()))?;
        rpm.path = path.to_path_buf();
        Ok(rpm)
    }

    pub fn lead_name(&self) -> Option<String> {
        let name_end = self.data[10..76].iter().position(|b| *b == 0).unwrap_or(66);
        Some(String::from_utf8_lossy(&self.data[10..10 + name_end]).to_string())
    }

    pub fn payload_compressor(&self) -> Option<String> {
        self.header.string(tag::PAYLOADCOMPRESSOR)
    }

    pub fn payload_format(&self) -> Option<String> {
        self.header.string(tag::PAYLOADFORMAT)
    }

    /// Digest of the payload *as stored in the file* (i.e. still compressed),
    /// as recorded by rpm.
    pub fn payload_digest(&self) -> Option<String> {
        self.header.string(tag::PAYLOADDIGEST)
    }

    /// Digest of the decompressed payload, when present (`PAYLOADDIGESTALT`).
    pub fn payload_digest_alt(&self) -> Option<String> {
        self.header.string(5097)
    }

    /// Digest algorithm for `payload_digest`, defaulting to SHA-256 (8).
    pub fn payload_digest_algo(&self) -> i64 {
        self.header.int(tag::PAYLOADDIGESTALGO).unwrap_or(8)
    }

    pub fn payload_compression(&self) -> Compression {
        match self
            .payload_compressor()
            .unwrap_or_default()
            .to_ascii_lowercase()
            .as_str()
        {
            "gzip" => Compression::Gzip,
            "xz" => Compression::Xz,
            "zstd" => Compression::Zstd,
            "bzip2" => Compression::Bzip2,
            "lzma" => Compression::Lzma,
            _ => Compression::None,
        }
    }

    /// Decompress the payload into a cpio archive in memory.
    pub fn payload(&self) -> Result<Vec<u8>> {
        let raw = &self.data[self.payload_offset..];
        crate::fetch::decompress(raw.to_vec(), self.payload_compression())
            .map_err(|e| e.context(format!("{} payload", self.path.display())))
    }

    /// Verify the payload, then return it decompressed.
    ///
    /// Two checks: the digest of the stored (compressed) bytes from
    /// `PAYLOADDIGEST`, and — when the package records it — the digest of the
    /// decompressed archive from `PAYLOADDIGESTALT`. Together these catch
    /// corruption and tampering independently of signature verification.
    pub fn verify_payload(&self) -> Result<Vec<u8>> {
        let stored = &self.data[self.payload_offset..];

        if let Some(expected) = self.payload_digest() {
            let algo = self.payload_digest_algo();
            if algo != 8 {
                return Err(Error::new(format!(
                    "{}: unsupported payload digest algorithm {} (only SHA-256 is supported)",
                    self.path.display(),
                    algo
                )));
            }
            let got = digest::hex(&digest::sha256(stored));
            if !got.eq_ignore_ascii_case(&expected) {
                return Err(Error::new(format!(
                    "payload digest mismatch for {}: expected {}, got {}",
                    self.path.display(),
                    expected,
                    got
                )));
            }
        }

        let payload = self.payload()?;

        if let Some(expected) = self.payload_digest_alt() {
            let got = digest::hex(&digest::sha256(&payload));
            if !got.eq_ignore_ascii_case(&expected) {
                return Err(Error::new(format!(
                    "uncompressed payload digest mismatch for {}: expected {}, got {}",
                    self.path.display(),
                    expected,
                    got
                )));
            }
        }
        Ok(payload)
    }

    /// All files described by the header, with their metadata.
    pub fn files(&self) -> Vec<RpmFile> {
        let basenames = self.header.strings(tag::BASENAMES);
        let dirnames = self.header.strings(tag::DIRNAMES);
        let dirindexes = self.header.ints(tag::DIRINDEXES);
        let modes = self.header.ints(tag::FILEMODES);
        let sizes = self.header.ints(tag::FILESIZES);
        let mtimes = self.header.ints(tag::FILEMTIMES);
        let users = self.header.strings(tag::FILEUSERNAME);
        let groups = self.header.strings(tag::FILEGROUPNAME);
        let flags = self.header.ints(tag::FILEFLAGS);
        let links = self.header.strings(tag::FILELINKTOS);
        let digests = self.header.strings(tag::FILEDIGESTS);
        let rdevs = self.header.ints(tag::FILERDEVS);

        let mut out = Vec::with_capacity(basenames.len());
        for (i, base) in basenames.iter().enumerate() {
            let dir = dirindexes
                .get(i)
                .and_then(|idx| dirnames.get(*idx as usize))
                .cloned()
                .unwrap_or_else(|| "/".to_string());
            let path = format!("{}{}", dir, base);
            out.push(RpmFile {
                path: normalise_path(&path),
                mode: modes.get(i).copied().unwrap_or(0o644) as u32,
                size: sizes.get(i).copied().unwrap_or(0) as u64,
                mtime: mtimes.get(i).copied().unwrap_or(0) as u64,
                user: users.get(i).cloned().unwrap_or_else(|| "root".into()),
                group: groups.get(i).cloned().unwrap_or_else(|| "root".into()),
                flags: flags.get(i).copied().unwrap_or(0),
                linkto: links.get(i).cloned().unwrap_or_default(),
                digest: digests.get(i).cloned().unwrap_or_default(),
                rdev: rdevs.get(i).copied().unwrap_or(0) as u32,
            });
        }
        out
    }

    pub fn scriptlets(&self) -> Scriptlets {
        Scriptlets {
            prein: self.header.string(tag::PREIN),
            postin: self.header.string(tag::POSTIN),
            preun: self.header.string(tag::PREUN),
            postun: self.header.string(tag::POSTUN),
            prein_prog: self.header.string(tag::PREINPROG),
            postin_prog: self.header.string(tag::POSTINPROG),
            preun_prog: self.header.string(tag::PREUNPROG),
            postun_prog: self.header.string(tag::POSTUNPROG),
        }
    }

    /// Convert the header into RPF's package model.
    pub fn package(&self) -> Package {
        let h = &self.header;
        let mut pkg = Package {
            name: h.string(tag::NAME).unwrap_or_default(),
            epoch: h.int(tag::EPOCH).unwrap_or(0).max(0) as u32,
            version: h.string(tag::VERSION).unwrap_or_default(),
            release: h.string(tag::RELEASE).unwrap_or_default(),
            arch: h.string(tag::ARCH).unwrap_or_default(),
            summary: h.string(tag::SUMMARY).unwrap_or_default().replace('\n', " "),
            description: h.string(tag::DESCRIPTION).unwrap_or_default(),
            url: h.string(tag::URL).unwrap_or_default(),
            license: h.string(tag::LICENSE).unwrap_or_default(),
            vendor: h.string(tag::VENDOR).unwrap_or_default(),
            group: h.string(tag::GROUP).unwrap_or_default(),
            packager: h.string(tag::PACKAGER).unwrap_or_default(),
            buildtime: h.int(tag::BUILDTIME).unwrap_or(0).max(0) as u64,
            download_size: self.data.len() as u64,
            installed_size: h.int(tag::SIZE).unwrap_or(0).max(0) as u64,
            ..Default::default()
        };

        pkg.provides = deps(h, tag::PROVIDENAME, tag::PROVIDEFLAGS, tag::PROVIDEVERSION);
        pkg.requires = deps(h, tag::REQUIRENAME, tag::REQUIREFLAGS, tag::REQUIREVERSION);
        pkg.conflicts = deps(h, tag::CONFLICTNAME, tag::CONFLICTFLAGS, tag::CONFLICTVERSION);
        pkg.obsoletes = deps(h, tag::OBSOLETENAME, tag::OBSOLETEFLAGS, tag::OBSOLETEVERSION);
        pkg.recommends = deps(h, tag::RECOMMENDNAME, tag::RECOMMENDFLAGS, tag::RECOMMENDVERSION);
        pkg.suggests = deps(h, tag::SUGGESTNAME, tag::SUGGESTFLAGS, tag::SUGGESTVERSION);
        pkg.supplements = deps(h, tag::SUPPLEMENTNAME, tag::SUPPLEMENTFLAGS, tag::SUPPLEMENTVERSION);
        pkg.enhances = deps(h, tag::ENHANCENAME, tag::ENHANCEFLAGS, tag::ENHANCEVERSION);
        pkg.files = self.files().into_iter().map(|f| f.path).collect();
        pkg
    }

    /// The signature header's OpenPGP signature packets (RSA or DSA), if the
    /// package is signed.
    pub fn signature_packets(&self) -> Option<&[u8]> {
        self.signature
            .bin(tag::SIG_RSA)
            .or_else(|| self.signature.bin(tag::SIG_DSA))
    }

    /// Status flags stored in the signature header (tag 62).
    pub fn signature_blobs(&self) -> Vec<SignatureBlob<'_>> {
        let mut out = Vec::new();
        for tag in [tag::SIG_DSA, tag::SIG_RSA, tag::SIG_PGP, tag::SIG_GPG] {
            if let Some(bytes) = self.signature.bin(tag) {
                out.push(SignatureBlob { tag, bytes });
            }
        }
        out
    }

    /// The main header exactly as stored: what tag 268/267 signatures cover.
    pub fn header_blob(&self) -> &[u8] {
        let tail = &self.data[self.main_header_offset..];
        if tail.len() < 16 {
            return tail;
        }
        let il = be32(&tail[8..12]) as usize;
        let dl = be32(&tail[12..16]) as usize;
        let len = 16usize
            .checked_add(il.saturating_mul(16))
            .and_then(|v| v.checked_add(dl))
            .unwrap_or(tail.len())
            .min(tail.len());
        &tail[..len]
    }

    /// The exact bytes a legacy signature covers: the main header blob,
    /// followed by the (compressed) payload.
    pub fn signed_payload(&self) -> &[u8] {
        &self.data[self.main_header_offset..]
    }

    pub fn to_bytes(&self) -> &[u8] {
        &self.data
    }

    /// Check every signature in the package against `keyring`.
    ///
    /// Returns the verification result for each signature present, so a caller
    /// can decide whether "one good signature" is enough (rpm's rule for
    /// multi-signed packages) and report the rest.
    pub fn verify_signatures(
        &self,
        keyring: &crate::pgp::Keyring,
    ) -> crate::Result<Vec<SignatureOutcome>> {
        let mut outcomes = Vec::new();
        for blob in self.signature_blobs() {
            let data = if blob.covers_header_only() {
                self.header_blob()
            } else {
                self.signed_payload()
            };
            let parsed = match crate::pgp::parse_signature(blob.bytes) {
                Ok(sig) => sig,
                Err(e) => {
                    outcomes.push(SignatureOutcome::Invalid {
                        description: blob.description(),
                        reason: e.to_string(),
                    });
                    continue;
                }
            };
            let issuer = parsed.issuer;
            let key = keyring.find(issuer);
            let description = blob.description();
            let algorithm = parsed.algorithm_name();
            let hash = parsed.hash_name();
            match key {
                None => outcomes.push(SignatureOutcome::NoKey {
                    description,
                    key_id: issuer.map(|id| format!("{:016X}", id)),
                    algorithm,
                }),
                Some(key) => match crate::pgp::verify(key, &parsed, data) {
                    Ok(()) => outcomes.push(SignatureOutcome::Verified {
                        description,
                        key_id: key.short_id(),
                        algorithm,
                        hash,
                    }),
                    Err(e) => outcomes.push(SignatureOutcome::Invalid {
                        description,
                        reason: e.to_string(),
                    }),
                },
            }
        }
        Ok(outcomes)
    }
}

/// The result of checking one signature in a package.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignatureOutcome {
    Verified {
        description: &'static str,
        key_id: String,
        algorithm: &'static str,
        hash: &'static str,
    },
    NoKey {
        description: &'static str,
        key_id: Option<String>,
        algorithm: &'static str,
    },
    Invalid {
        description: &'static str,
        reason: String,
    },
}

impl SignatureOutcome {
    pub fn is_verified(&self) -> bool {
        matches!(self, SignatureOutcome::Verified { .. })
    }

    /// A package is acceptable when at least one signature verifies and none
    /// is outright invalid, matching rpm's behaviour for multi-signed packages.
    pub fn acceptable(outcomes: &[SignatureOutcome]) -> bool {
        !outcomes.is_empty()
            && outcomes.iter().any(|o| o.is_verified())
            && !outcomes
                .iter()
                .any(|o| matches!(o, SignatureOutcome::Invalid { .. }))
    }
}

/// A signature stored in the RPM's signature header, with the bytes it covers.
#[derive(Debug, Clone, Copy)]
pub struct SignatureBlob<'a> {
    pub tag: u32,
    pub bytes: &'a [u8],
}

impl SignatureBlob<'_> {
    /// Header signatures (267, 268) cover the main header only; the legacy
    /// PGP/GPG tags (1002, 1005) cover header plus payload.
    pub fn covers_header_only(&self) -> bool {
        matches!(self.tag, tag::SIG_RSA | tag::SIG_DSA)
    }

    pub fn description(&self) -> &'static str {
        match self.tag {
            tag::SIG_RSA => "RSA header signature",
            tag::SIG_DSA => "DSA/EdDSA header signature",
            tag::SIG_PGP => "PGP header+payload signature",
            tag::SIG_GPG => "GPG header+payload signature",
            _ => "signature",
        }
    }
}

#[derive(Debug, Clone)]
pub struct RpmFile {
    pub path: String,
    pub mode: u32,
    pub size: u64,
    pub mtime: u64,
    pub user: String,
    pub group: String,
    pub flags: i64,
    pub linkto: String,
    pub digest: String,
    pub rdev: u32,
}

impl RpmFile {
    pub fn is_dir(&self) -> bool {
        self.mode & 0o170000 == 0o040000
    }
    pub fn is_symlink(&self) -> bool {
        self.mode & 0o170000 == 0o120000
    }
    pub fn is_regular(&self) -> bool {
        self.mode & 0o170000 == 0o100000
    }
    pub fn is_ghost(&self) -> bool {
        self.flags & fileflag::GHOST != 0
    }
    pub fn is_config(&self) -> bool {
        self.flags & fileflag::CONFIG != 0
    }
    pub fn is_noreplace(&self) -> bool {
        self.flags & fileflag::NOREPLACE != 0
    }
    pub fn is_missingok(&self) -> bool {
        self.flags & fileflag::MISSINGOK != 0
    }
    pub fn perms(&self) -> u32 {
        self.mode & 0o7777
    }
    pub fn file_type(&self) -> u32 {
        self.mode & 0o170000
    }
}

fn deps(h: &Header, names: u32, flags: u32, versions: u32) -> Vec<Depend> {
    let names = h.strings(names);
    let flags = h.ints(flags);
    let versions = h.strings(versions);
    let mut out = Vec::with_capacity(names.len());
    for (i, name) in names.iter().enumerate() {
        let sense = flags.get(i).copied().unwrap_or(0) as u8;
        let version = versions.get(i).cloned().unwrap_or_default();
        // The low three bits of rpm's sense flags are the same encoding RPF
        // uses for comparison operators; strip the informational bits.
        let cmp_flags = DepFlags(sense & 0b0000_1110);
        let evr = if version.is_empty() {
            None
        } else {
            Some(Evr::parse(&version))
        };
        let rich = if name.starts_with('(') {
            RichDep::parse(name)
        } else {
            None
        };
        out.push(Depend {
            name: name.clone(),
            flags: cmp_flags,
            evr,
            rich,
        });
    }
    out
}

/// Normalise a package path: collapse duplicate slashes, drop trailing slash
/// (except root), and ensure a leading slash.
pub fn normalise_path(path: &str) -> String {
    let mut parts: Vec<&str> = Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => continue,
            ".." => {
                parts.pop();
            }
            p => parts.push(p),
        }
    }
    format!("/{}", parts.join("/"))
}

fn be16(b: &[u8]) -> u16 {
    u16::from_be_bytes([b[0], b[1]])
}
fn be32(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}
fn be64(b: &[u8]) -> u64 {
    u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
}

/// Resolve a user or group name to an id using the target root's databases.
pub fn resolve_id(installroot: &Path, name: &str, group: bool) -> Option<u32> {
    if name.is_empty() {
        return Some(0);
    }
    if let Ok(n) = name.parse::<u32>() {
        return Some(n);
    }
    let file = if group { "etc/group" } else { "etc/passwd" };
    let text = std::fs::read_to_string(installroot.join(file)).ok()?;
    for line in text.lines() {
        let fields: Vec<&str> = line.split(':').collect();
        if fields.first().map(|f| *f == name).unwrap_or(false) {
            let idx = if group { 2 } else { 2 };
            if let Some(v) = fields.get(idx).and_then(|s| s.parse::<u32>().ok()) {
                return Some(v);
            }
        }
    }
    // Common defaults when the target root has no user database yet.
    if name == "root" || name == "wheel" {
        return Some(0);
    }
    None
}

/// Helper for building an in-memory map of hardlink groups.
pub fn hardlink_targets(entries: &[CpioEntry<'_>]) -> HashMap<(u32, u32), Vec<String>> {
    let mut map: HashMap<(u32, u32), Vec<String>> = HashMap::new();
    for e in entries {
        if e.is_regular() && e.nlink > 1 {
            map.entry((e.ino, e.rdevmajor))
                .or_default()
                .push(e.name.clone());
        }
    }
    map
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fetch::Compression;
    use std::path::PathBuf;

    fn fixture(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(name)
    }

    #[test]
    fn parses_basic_package() {
        let rpm = Rpm::open(&fixture("basic-gzip.rpm")).unwrap();
        assert_eq!(rpm.lead_major, 3, "v4 packages use lead major 3");
        assert_eq!(rpm.signature_type, 5);

        let pkg = rpm.package();
        assert_eq!(pkg.name, "rpm-basic");
        assert_eq!(pkg.version, "2.3.4");
        assert_eq!(pkg.release, "5.el9");
        assert_eq!(pkg.epoch, 1);
        assert_eq!(pkg.arch, "noarch");
        assert_eq!(pkg.license, "MPL-2.0");
        assert_eq!(pkg.group, "Development/Tools");
        assert_eq!(pkg.nevra(), "rpm-basic-1:2.3.4-5.el9.noarch");
        assert_eq!(rpm.payload_format().as_deref(), Some("cpio"));
        assert!(rpm.payload_digest().is_some());
        assert_eq!(rpm.payload_digest_algo(), 8, "SHA-256");
    }

    #[test]
    fn file_metadata_is_reconstructed_from_basenames_and_dirindexes() {
        let rpm = Rpm::open(&fixture("basic-gzip.rpm")).unwrap();
        let files = rpm.files();
        assert_eq!(files.len(), 11);

        let config = files
            .iter()
            .find(|f| f.path == "/etc/rpm-basic/example_config.toml")
            .expect("config file");
        assert!(config.is_config(), "FILEFLAGS bit 0 marks %config");
        assert_eq!(config.user, "root");
        assert_eq!(config.perms() & 0o777, 0o644);

        let bin = files
            .iter()
            .find(|f| f.path == "/usr/bin/rpm-basic")
            .expect("binary");
        assert!(bin.is_regular());
        assert_eq!(bin.perms() & 0o777, 0o644, "mode comes from FILEMODES");
        assert!(!bin.digest.is_empty());

        let dir = files
            .iter()
            .find(|f| f.path == "/usr/lib/rpm-basic")
            .unwrap();
        assert!(dir.is_dir(), "directories appear in the file list");
        assert_eq!(dir.perms() & 0o777, 0o755);

        // %ghost files are recorded in the header but carry no payload data.
        let ghost = files
            .iter()
            .find(|f| f.is_ghost())
            .expect("expected a %ghost file");
        assert_eq!(ghost.path, "/var/log/rpm-basic/basic.log");
        assert_eq!(ghost.size, 0);
        assert!(
            files.iter().any(|f| f.is_ghost()),
            "expected a ghost file: {:?}",
            files
                .iter()
                .filter(|f| f.flags != 0)
                .map(|f| (&f.path, f.flags))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn payload_verifies_against_stored_digest() {
        let rpm = Rpm::open(&fixture("basic-gzip.rpm")).unwrap();
        let payload = rpm.verify_payload().expect("payload digest must match");
        assert!(payload.starts_with(b"070701"), "cpio newc archive expected");
    }

    #[test]
    fn tampered_payload_is_detected() {
        let data = std::fs::read(fixture("basic-gzip.rpm")).unwrap();
        let rpm = Rpm::parse(data.clone()).unwrap();
        let mut tampered_data = data;
        // Flip a byte inside the payload region.
        let offset = rpm.payload_offset + 300;
        tampered_data[offset] ^= 0xff;
        let tampered = Rpm::parse(tampered_data).unwrap();
        assert_ne!(
            tampered.payload_digest(),
            None,
            "fixture should carry a payload digest"
        );
        let err = tampered.verify_payload().unwrap_err();
        assert!(
            err.message().contains("payload digest mismatch"),
            "{}",
            err
        );
    }

    #[test]
    fn uncompressed_payload_is_supported() {
        let rpm = Rpm::open(&fixture("basic-uncompressed-signed.rpm")).unwrap();
        assert_eq!(rpm.payload_compression(), Compression::None);
        let payload = rpm.verify_payload().unwrap();
        assert!(payload.starts_with(b"070701"));
    }

    #[test]
    fn cpio_entries_are_extracted() {
        let rpm = Rpm::open(&fixture("basic-gzip.rpm")).unwrap();
        let payload = rpm.payload().unwrap();
        let mut reader = CpioReader::new(&payload);
        let mut names = Vec::new();
        while let Some(entry) = reader.next_entry().unwrap() {
            names.push(entry.name.clone());
        }
        // 10 payload entries: 11 header files minus the %ghost entry.
        assert_eq!(names.len(), 10, "unexpected payload entries: {:?}", names);
        assert!(
            names.iter().all(|n| n.starts_with("./")),
            "rpm prefixes payload paths with ./"
        );
        assert!(names.iter().any(|n| n.contains("rpm-basic")));
        assert!(
            !names.iter().any(|n| n == "TRAILER!!!"),
            "the trailer must not be reported as an entry"
        );
    }

    #[test]
    fn file_digests_match_extracted_content() {
        let rpm = Rpm::open(&fixture("basic-gzip.rpm")).unwrap();
        let payload = rpm.payload().unwrap();
        let files = rpm.files();

        let mut checked = 0;
        let mut reader = CpioReader::new(&payload);
        while let Some(entry) = reader.next_entry().unwrap() {
            if !entry.is_regular() {
                continue;
            }
            let path = normalise_path(&entry.name);
            if let Some(meta) = files.iter().find(|f| f.path == path) {
                if !meta.digest.is_empty() {
                    let got = digest::hex(&digest::sha256(entry.data));
                    assert_eq!(got, meta.digest, "digest mismatch for {}", path);
                    checked += 1;
                }
            }
        }
        assert!(checked >= 3, "expected several files to be verified");
    }

    #[test]
    fn symlinks_and_special_file_flags() {
        // The file-attrs fixture exercises the full flag vocabulary and the
        // symlink/symlink-to-directory cases in the file list.
        let rpm = Rpm::open(&fixture("file-attrs.rpm")).unwrap();
        let files = rpm.files();
        let symlink = files
            .iter()
            .find(|f| f.is_symlink())
            .expect("expected a symlink entry");
        assert!(!symlink.linkto.is_empty(), "symlink target must be recorded");

        assert!(
            files.iter().any(|f| f.is_noreplace()),
            "%config(noreplace) flag"
        );
        assert!(
            files.iter().any(|f| f.flags & fileflag::LICENSE != 0),
            "%license flag"
        );
        assert!(
            files.iter().any(|f| f.flags & fileflag::README != 0),
            "%doc readme flag"
        );
        assert!(
            files.iter().any(|f| f.flags & fileflag::ARTIFACT != 0),
            "artifact flag"
        );
        // Ownership names are preserved verbatim.
        assert!(
            files
                .iter()
                .any(|f| !f.user.is_empty() && !f.group.is_empty()),
            "user/group names must be recorded"
        );
    }

    #[test]
    fn scriptlets_are_read() {
        let rpm = Rpm::open(&fixture("scriptlets.rpm")).unwrap();
        let s = rpm.scriptlets();
        assert!(s.prein.is_some(), "expected %pre");
        assert!(s.postin.is_some(), "expected %post");
        assert!(s.preun.is_some(), "expected %preun");
        assert!(s.postun.is_some(), "expected %postun");
        assert!(!s.is_empty());
    }

    #[test]
    fn rich_dependencies_survive_header_parsing() {
        let rpm = Rpm::open(&fixture("rich-deps.rpm")).unwrap();
        let pkg = rpm.package();
        let all: Vec<&Depend> = pkg
            .requires
            .iter()
            .chain(pkg.recommends.iter())
            .chain(pkg.suggests.iter())
            .chain(pkg.supplements.iter())
            .collect();
        assert!(
            all.iter().any(|d| d.rich.is_some()),
            "expected a parsed rich dependency: {:?}",
            all.iter().map(|d| &d.name).collect::<Vec<_>>()
        );
    }

    #[test]
    fn scriptlets_report_their_interpreter() {
        let rpm = Rpm::open(&fixture("scriptlets.rpm")).unwrap();
        let scriptlets = rpm.scriptlets();
        // rpm defaults to /bin/sh when the package does not name an interpreter.
        assert_eq!(
            Scriptlets::interpreter(&scriptlets.postin_prog),
            "/bin/sh"
        );
        assert!(Scriptlets::is_embedded("<lua>"));
        assert!(Scriptlets::is_embedded("<lua:5.4>"));
        assert!(!Scriptlets::is_embedded("/sbin/ldconfig"));
        assert!(!Scriptlets::is_embedded("/usr/bin/python3"));
    }

    #[test]
    fn verifies_a_real_rpm_signature() {
        let rpm = Rpm::open(&fixture("rpmsig-hello-rsa.rpm")).unwrap();
        let mut ring = crate::pgp::Keyring::new();
        ring.add_armored(
            &std::fs::read_to_string(fixture("keys/rpm.org-rsa-2048-test.pub")).unwrap(),
        )
        .unwrap();

        let outcomes = rpm.verify_signatures(&ring).unwrap();
        assert!(!outcomes.is_empty(), "package has signatures");
        assert!(
            SignatureOutcome::acceptable(&outcomes),
            "signature should verify: {:?}",
            outcomes
        );
        let verified = outcomes.iter().find(|o| o.is_verified()).unwrap();
        match verified {
            SignatureOutcome::Verified { hash, algorithm, .. } => {
                assert_eq!(*algorithm, "RSA");
                assert_eq!(*hash, "SHA-256");
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn verifies_a_sha512_signature_with_a_4096_bit_key() {
        let rpm = Rpm::open(&fixture("basic-uncompressed-signed.rpm")).unwrap();
        let mut ring = crate::pgp::Keyring::new();
        ring.add_armored(
            &std::fs::read_to_string(fixture("keys/rpm-testkey-v4-rsa4096.asc")).unwrap(),
        )
        .unwrap();

        let outcomes = rpm.verify_signatures(&ring).unwrap();
        assert!(
            SignatureOutcome::acceptable(&outcomes),
            "signature should verify: {:?}",
            outcomes
        );
        assert!(outcomes.iter().any(|o| matches!(
            o,
            SignatureOutcome::Verified { hash: "SHA-512", .. }
        )));
    }

    #[test]
    fn tampering_with_the_header_breaks_the_signature() {
        let rpm = Rpm::open(&fixture("rpmsig-hello-rsa.rpm")).unwrap();
        let mut ring = crate::pgp::Keyring::new();
        ring.add_armored(
            &std::fs::read_to_string(fixture("keys/rpm.org-rsa-2048-test.pub")).unwrap(),
        )
        .unwrap();

        // Flip a byte inside the signed header region.
        let mut data = rpm.to_bytes().to_vec();
        let target = rpm.main_header_offset + rpm.header_blob().len() - 8;
        data[target] ^= 0x01;
        let tampered = Rpm::parse(data).unwrap();

        let outcomes = tampered.verify_signatures(&ring).unwrap();
        assert!(
            !SignatureOutcome::acceptable(&outcomes),
            "a modified header must not verify: {:?}",
            outcomes
        );
    }

    #[test]
    fn unknown_key_reports_no_key() {
        let rpm = Rpm::open(&fixture("rpmsig-hello-rsa.rpm")).unwrap();
        let mut ring = crate::pgp::Keyring::new();
        ring.add_armored(
            &std::fs::read_to_string(fixture("keys/rpm-testkey-v4-rsa4096.asc")).unwrap(),
        )
        .unwrap();

        let outcomes = rpm.verify_signatures(&ring).unwrap();
        assert!(!SignatureOutcome::acceptable(&outcomes));
        assert!(outcomes.iter().any(|o| matches!(o, SignatureOutcome::NoKey { .. })));
    }

    #[test]
    fn signed_package_exposes_signature_packets() {
        let rpm = Rpm::open(&fixture("basic-uncompressed-signed.rpm")).unwrap();
        let packets = rpm.signature_packets().expect("RSA signature present");
        assert!(packets.len() > 100);
        assert!(
            packets[0] & 0x80 != 0,
            "not an OpenPGP packet: {:02x}",
            packets[0]
        );
        assert!(rpm.signature.has(tag::SIG_SHA256));
        assert!(rpm.signature.has(tag::SIG_MD5));
    }

    #[test]
    fn non_rpm_input_is_rejected() {
        match Rpm::parse(b"not an rpm at all".to_vec()) {
            Ok(_) => panic!("garbage was accepted as an RPM"),
            Err(err) => assert!(
                err.message().contains("not an RPM package"),
                "{}",
                err
            ),
        }
    }

    #[test]
    fn truncated_rpm_is_rejected_without_panicking() {
        let data = std::fs::read(fixture("basic-gzip.rpm")).unwrap();
        for cut in [50usize, 100, 200, 1000, 5000] {
            assert!(
                Rpm::parse(data[..cut].to_vec()).is_err(),
                "truncating to {} bytes should fail",
                cut
            );
        }
    }

    #[test]
    fn path_normalisation() {
        assert_eq!(normalise_path("/usr//bin//x"), "/usr/bin/x");
        assert_eq!(normalise_path("usr/bin/x"), "/usr/bin/x");
        assert_eq!(normalise_path("/usr/./bin/x"), "/usr/bin/x");
        assert_eq!(normalise_path("/usr/share/../bin/x"), "/usr/bin/x");
        assert_eq!(normalise_path("/"), "/");
    }

    #[test]
    fn id_resolution_from_target_root() {
        let dir = std::env::temp_dir().join(format!("rpf-ids-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("etc")).unwrap();
        std::fs::write(
            dir.join("etc/passwd"),
            "root:x:0:0:root:/root:/bin/bash\nnobody:x:65534:65534::/:/sbin/nologin\n",
        )
        .unwrap();
        std::fs::write(dir.join("etc/group"), "root:x:0:\nusers:x:100:\n").unwrap();

        assert_eq!(resolve_id(&dir, "root", false), Some(0));
        assert_eq!(resolve_id(&dir, "nobody", false), Some(65534));
        assert_eq!(resolve_id(&dir, "users", true), Some(100));
        assert_eq!(resolve_id(&dir, "1234", false), Some(1234));
        assert_eq!(resolve_id(&dir, "ghost", false), None);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
