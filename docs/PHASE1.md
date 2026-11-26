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

### Storage
A custom binary cache (`packages.rpf` + `meta` per repository) written
atomically. No SQLite dependency: the format is length-prefixed and loads in a
single pass. Repository ids are sanitised before being used as path components
so a hostile id cannot escape the cache directory.

## Deliberately not implemented yet

| Area | Why it is deferred |
|---|---|
| **Filesystem installation** | Needs the RPM header parser, cpio payload extraction, scriptlet execution and file conflict handling. Next milestone; `install` plans and downloads only. |
| **GPG signature verification** | RPM signatures live inside the RPM's signature header, so this lands together with the header parser. Downloads are currently checksum-verified only, and RPF says so on stderr. |
| **rpmdb interoperability** | Writing rpm's SQLite database is out of scope for now. RPF keeps `installed.rpf` and reads `rpm -qa` as a fallback so it can reason about an existing system. |
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

`cargo test` runs 94 tests: 75 library unit tests, 4 CLI unit tests, 15
end-to-end tests.

## Next steps

1. **RPM header parser** — lead, signature header, main header, tag model
   (NEVRA, provides/requires, file list, payload digest, payload compactor).
2. **Payload extraction** — `newc` cpio, decompression per payload compactor,
   install into `--installroot` with mode/ownership/symlink handling.
3. **Transaction execution** — file conflict detection, scriptlets, atomic
   rollback on failure, then `remove`.
4. **GPG verification** — signature header extraction and OpenPGP verification
   of the package plus `repo_gpgcheck` for `repomd.xml`.
5. **rpmdb** — read the existing database, then write to it so RPF and rpm agree
   on what is installed.
6. **Polish** — parallel downloads, progress output, `filelists` for file
   queries, shell completion.

Phase 2 (feature parity and beyond) starts only once 1–5 are done and the
foundation installs, upgrades and removes packages cleanly on a real Fedora
system.
