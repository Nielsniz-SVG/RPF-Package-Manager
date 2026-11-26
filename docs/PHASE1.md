# Phase 1 — foundations

This document records what RPF's first milestone contains, the decisions behind
it, and exactly what is left before the foundation can be called finished.

## Goal

A package manager for Fedora that:

* reads Fedora's real repository metadata (Fedora, updates, RPM Fusion, COPR),
* resolves dependencies correctly, including versioned and rich dependencies,
* verifies everything it downloads,
* and does so from a small, auditable codebase.

## Implemented in milestone 1

### Repository configuration
* `.repo` files in `/etc/rpf/repos.d/` and `/etc/yum.repos.d/`, last definition
  wins per repository id, matching dnf.
* `$releasever`, `${releasever}`, `$releasever_major`, `$basearch`, `$arch`,
  `$uuid` expansion. Unknown variables are left intact so typos are visible.
* `baseurl` (multiple, whitespace separated), `metalink`, `mirrorlist`,
  `enabled`, `gpgcheck`, `repo_gpgcheck`, `gpgkey`, `priority`, `cost`,
  `includepkgs`, `excludepkgs`, `skip_if_unavailable`, `metadata_expire`.
* Built-in Fedora + RPM Fusion free/nonfree defaults used when no repository
  files exist, so RPF works on a bare system.
* COPR: `rpf copr enable OWNER/PROJECT` writes a `.repo` file pointing at
  `download.copr.fedorainfracloud.org`, with the project's `pubkey.gpg`.

### Metadata
* `repomd.xml`, including compressed and decompressed checksums and timestamps.
* Metalink (mirror preference order, `repodata/repomd.xml` normalisation) and
  plain-text mirrorlists, with failover across mirrors.
* Streaming `primary.xml` parser: namespaces, `<file>` entries, all dependency
  kinds (provides, requires, conflicts, obsoletes, recommends, suggests,
  supplements, enhances), and rich dependencies.
* Decompression through the system `gzip`/`xz`/`zstd`, selected from the
  metadata filename.

### Version comparison
`rpmvercmp` implemented from rpm's algorithm, including `~` and `^`, with rpm's
own test vectors in the unit tests. Epochs dominate; releases are ignored for a
dependency that does not name one ("`foo >= 1.0`" matches `1.0-99.fc43`).

### Resolution
* Provides index over implicit `name` and `name(arch)` capabilities plus explicit
  provides, including file capabilities such as `/bin/sh`.
* Breadth-first requirement satisfaction with candidate replacement when a
  better version is selected later.
* Conflicts checked against both installed and selected packages.
* Obsoletes drop the displaced installed package.
* Install ordering is a topological sort over requirements, so dependencies are
  installed before dependants.
* Repository `priority` then `cost` break EVR ties, as in dnf.
* Architecture filtering (`noarch` plus the target `$basearch`).
* All problems are collected and reported together, dnf-style, rather than
  aborting at the first failure.

### Integrity
* SHA-256 of the compressed metadata compared with `repomd.xml`.
* SHA-256 of the decompressed document compared with `open-checksum`.
* SHA-256 of every RPM compared with the checksum in `primary.xml`, verified
  before the package enters the transaction. A previously cached file that fails
  its checksum is deleted and re-downloaded.

### Installation and removal
* RPM format fully parsed: lead, signature header (8-byte aligned), main header
  and cpio `newc` payload, with all v3/v4 tag semantics (`FILEMODES`,
  `FILEDIGESTS`, `FILEFLAGS`, `BASENAMES`/`DIRNAMES`/`DIRINDEXES`,
  `PAYLOADDIGEST`, `PAYLOADDIGESTALT`).
* Payload integrity is checked before anything is written: the digest covers the
  bytes exactly as stored in the file, and `PAYLOADDIGESTALT` covers the
  decompressed stream, so a payload that has been re-compressed after tampering
  is still caught.
* Extraction into `--installroot`: directories, regular files, symlinks,
  hardlinks (deduplicated by payload inode number), modes and mtimes preserved;
  ownership applied when running as root. `%ghost` files are recorded but not
  created. Paths escaping the install root are refused, as are absolute symlink
  targets that resolve outside it.
* `%config` handling: `(noreplace)` keeps the local file and writes `.rpmnew`;
  a plain `%config` is replaced and the original is kept as `.rpmsave`.
* File conflicts are detected before the transaction starts; conflicting paths
  make the whole transaction fail without touching the system. `--replacefiles`
  overrides this deliberately.
* Dependencies are installed before dependants, obsoleted packages are removed
  first, and `--test` prints the transaction without writing anything.
* `remove` deletes the files in the database manifest, prunes directories it
  emptied, and refuses when another installed package requires what is being
  removed.
* The installed database records each package's dependency data, so those
  safety checks still work in later invocations.

### Signature verification
* ASCII-armour decoder (headers, base64, CRC line skipped on purpose), OpenPGP
  packet parser for old and new formats, v4 public keys and v4 detached
  signatures.
* SHA-256, SHA-384 and SHA-512 implemented in this repository, plus SHA-1 for
  key fingerprints only — a SHA-1 *signature* is refused, never trusted.
* RSA verification with hand-written arbitrary-precision arithmetic: CIOS
  Montgomery multiplication and square-and-multiply, with the wide-intermediate
  handling an RSA modulus with its top bit set requires.
* EdDSA (Ed25519, algorithm 22) and ECDSA (NIST P-256, algorithm 19) with a
  prime-field layer over the same arithmetic and projective point formulas.
  Ed25519 is checked against the RFC 8032 §7.1 vectors; both are checked against
  packages rpm signed (`tests/fixtures/rpmsig-eddsa.rpm`, `rpmsig-ecdsa.rpm`)
  with the distribution keys. Signature values arrive as MPIs and are
  left-padded to the curve width, since MPIs drop leading zero octets.
* Curve OIDs are matched explicitly (Ed25519 `2b06010401da470f01`, P-256
  `2a8648ce3d030107`), so a P-384 or Brainpool key is reported as unsupported
  instead of being fed to the wrong curve.
* The v4 signature trailer is hashed as `0x04 0xff || BE32(6 + hashed_len)` —
  the count covers the signature packet's own hashed data, not the document.
  This was established against packages signed by rpm itself
  (`tests/fixtures/rpmsig-hello-rsa.rpm`) and by an independent OpenPGP
  implementation, not guessed.
* Which bytes a signature covers depends on the tag, exactly as rpm does it:
  `RPMSIGTAG_RSA`/`DSA` (267/268) sign the main header blob, the legacy
  `PGP`/`GPG` tags (1002/1005) sign header plus payload.
* Keys come from `gpgkey=` in repositories (fetched once, cached under
  `cachedir/keys/`), or from `--key FILE`. Both armoured and binary key files
  are understood.
* `repo_gpgcheck=1` requires and verifies `repodata/repomd.xml.asc` before the
  metadata is parsed.
* Policy: an invalid signature is always fatal; `gpgcheck=1` refuses packages
  that are unsigned or signed by an unknown key; `gpgcheck=0` warns instead.

### rpmdb interoperability
* Reading: `rpm -qa --xml --files` gives name, EVR, architecture, provides,
  requires, conflicts, obsoletes and file lists in a documented format. RPF
  parses it with its own XML reader, so a system installed by dnf is understood
  well enough to resolve against (`rpf install` sees that glibc is already
  there) and to remove from (`rpf remove` deletes the files rpm recorded).
  Older rpm builds without `--xml` fall back to the `--queryformat` form.
* Writing: deliberately out of scope. rpm's on-disk database is rpm's to
  write; a bug there corrupts the package manager's own view of the system.
  Packages RPF installs are recorded in `installed.rpf`, which `rpm -qa` will
  not show. This is a real limitation and is stated as such instead of being
  papered over.

### Storage
A custom binary cache (`packages.rpf` + `meta` per repository) written
atomically. No SQLite dependency: the format is length-prefixed and loads in a
single pass. Repository ids are sanitised before being used as path components
so a hostile id cannot escape the cache directory.

## Deliberately not implemented yet

| Area | Why it is deferred |
|---|---|
| **Embedded scriptlet interpreters** | `%pre`/`%post`/`%preun`/`%postun` run through the interpreter the package names (`%post -p /sbin/ldconfig` works), inside `chroot` for an `--installroot`, with rpm's `$1` argument. Embedded interpreters such as `<lua>` are reported and skipped: RPF has no Lua. |
| **Other signature curves (P-384, P-521, Brainpool) and DSA** | RSA, Ed25519 and NIST P-256 cover Fedora, RPM Fusion and the packages rpm itself can sign with in practice. Any other algorithm is detected, reported as unsupported and refused — never silently accepted. |
| **Key trust model** | Expiry, revocation and web-of-trust are not evaluated. A key in the keyring is trusted, which matches `rpm --import`. |
| **Writing the rpmdb** | Reading is implemented; writing rpm's own database is not, by choice. Installing with RPF therefore does not make a package visible to `rpm -qa` or to dnf. |
| **`filelists.xml` / `other.xml`** | Only `primary.xml` is parsed. Full file queries (`rpf provides /usr/bin/foo` for non-primary files) need filelists, which is a phase 1.x item. |
| **Modules, comps groups, delta RPMs, `--downloadonly` semantics** | Not part of the foundation. |
| **Parallel downloads** | Downloads are sequential per package. `max_parallel_downloads` is parsed but not yet acted on. |

## Environment note

RPF was developed in a sandbox with no crates.io access and no Rust toolchain,
so the toolchain was bootstrapped from prebuilt components and the crate was
written against `std` alone. That constraint produced a genuinely dependency-free
implementation, which is now a documented design property rather than an
accident.

## Test strategy

* **Unit tests** — parsers against real-shaped metadata, rpm version vectors,
  dependency matching, solver scenarios, cache round-trips, path-traversal
  hardening, SHA-256 against NIST vectors.
* **End-to-end tests** (`tests/integration.rs`) — build a `file://` repository on
  disk with correct checksums, then run the real `rpf` binary against it:
  `makecache`, `list`, `search`, `info`, `provides`, `download`, `clean`,
  `copr enable/remove`, cache-only failures, corrupt checksums and unsatisfiable
  dependencies all assert on real process output and exit codes.
* **Installation tests** (`tests/install.rs`) — `tests/common` writes genuine
  RPM files (lead, headers, cpio payload, optionally gzip-compressed) and a
  matching repository, so the tests cover the whole pipeline rather than a mock:
  install from a repository, dependency pull-in and ordering, `%config` vs
  `%config(noreplace)` behaviour, symlinks and hardlinks (inode equality),
  conflicting paths, tampered payloads, `--test`, removal, directory pruning and
  refusal to remove a package that another one requires.
* The real `basic-gzip.rpm` fixture is also installed into a scratch
  `--installroot` and compared file by file.

`cargo test` runs 170 tests: 122 library unit tests, 4 CLI unit tests, 25
installation tests, 15 end-to-end tests and 4 curve-signature tests. The rpmdb
tests run against a stand-in `rpm` executable that emits genuine `--xml` output,
so the parsing and the fallback paths are exercised without rpm being installed.

## Next steps

1. **`filelists.xml`** — so file queries work for files that are not in
   `primary.xml`.
2. **Polish** — parallel downloads, progress output, shell completion.

Phase 2 (feature parity and beyond) starts only once 1–2 are done and the
foundation installs, upgrades and removes packages cleanly on a real Fedora
system.
