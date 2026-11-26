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

### Storage
A custom binary cache (`packages.rpf` + `meta` per repository) written
atomically. No SQLite dependency: the format is length-prefixed and loads in a
single pass. Repository ids are sanitised before being used as path components
so a hostile id cannot escape the cache directory.

## Deliberately not implemented yet

| Area | Why it is deferred |
|---|---|
| **Scriptlet macro expansion** | `%pre`/`%post`/`%preun`/`%postun` are executed through `/bin/sh` (through `chroot` for an `--installroot`) and receive rpm's `$1` argument. Bodies that contain `%{...}` macros are not expanded yet, and scriptlets are skipped with a warning when RPF is not root. |
| **GPG signature verification** | RPM signatures live inside the RPM's signature header and are parsed, but OpenPGP packet decoding, RSA/EdDSA verification and key import from `gpgkey=` are still to come. Downloads are checksum-verified only, and RPF says so on stderr. |
| **rpmdb interoperability** | Writing rpm's SQLite database is out of scope for now. RPF keeps `installed.rpf` (now including dependency records) and reads `rpm -qa` as a fallback so it can reason about an existing system. |
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

`cargo test` runs 127 tests: 94 library unit tests, 4 CLI unit tests, 14
installation tests and 15 end-to-end tests.

## Next steps

1. **GPG verification** — OpenPGP packet decoding, RSA and Ed25519 signature
   verification of the signed header, key import from `gpgkey=`, and
   `repo_gpgcheck` over `repomd.xml`.
2. **Scriptlet execution** — macro expansion and `chroot` execution inside the
   install root, which removes the last `--noscripts` caveat.
3. **rpmdb** — write rpm's own database so RPF and rpm agree on what is
   installed, or document the incompatibility as a deliberate choice.
4. **Polish** — parallel downloads, progress output, `filelists` for file
   queries, shell completion.

Phase 2 (feature parity and beyond) starts only once 1–3 are done and the
foundation installs, upgrades and removes packages cleanly on a real Fedora
system.
