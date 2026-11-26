# RPF — RPM Package Manager

A fast, secure package manager for Fedora, written from scratch in Rust.

RPF is a clean-room reimplementation of the parts of DNF that matter — repository
handling, dependency resolution and RPM transactions — with none of the legacy
C stack underneath. It speaks the same metadata formats Fedora already
publishes, so it works against Fedora, updates, RPM Fusion and COPR repositories
out of the box.

```
$ rpf install firefox
Transaction:
  install  glibc-2.41-1.fc43.x86_64
  install  ncurses-libs-6.5-2.fc43.x86_64
  install  bash-5.2.21-1.fc43.x86_64
  install  firefox-142.0-1.fc43.x86_64
```

## Design principles

**No dependencies, by design.** `Cargo.toml` has an empty `[dependencies]`
table. Everything below is implemented in this repository: the XML parser, the
INI parser, SHA-256, rpm version comparison, the dependency solver, the metadata
cache format and the CLI. There is no `libsolv`, `librpm`, `libcurl` or `libdnf`
in the process. That means no supply chain to audit beyond `std`, and a binary
that is 800 KB instead of 20 MB.

**Verify before you trust.** Three independent layers, all implemented here:

1. **Checksums.** Repository metadata is checked against `repomd.xml` (both the
   compressed and the decompressed form), every downloaded RPM against the
   checksum in the repository metadata, and each package's own header and
   payload digests again immediately before extraction.
2. **OpenPGP signatures.** Package signatures are verified in-process — the
   ASCII-armour decoder, OpenPGP packet parser, SHA-256/384/512, Montgomery
   modular exponentiation and RSA/PKCS#1 v1.5 verification are all in this
   repository, with no `gpg`, `librpm` or crypto library in the loop.
3. **Metadata signatures.** With `repo_gpgcheck=1`, `repomd.xml` must carry a
   valid detached signature before a single byte of it is parsed or cached.

A failed check aborts the transaction; nothing is written on a mismatch. A
signature that is present but invalid is always fatal, even for a repository
that has `gpgcheck=0`.

**Say what you know and what you don't.** Where a piece is not implemented yet,
RPF refuses and tells you, rather than silently doing half the job. See
[Status](#status).

## Status

Milestone 1 is the metadata, resolution, download and transaction foundation.
Installing and removing packages on disk works and is tested end to end. What
remains before the foundation is finished is cryptographic signature
verification and scriptlets — see the table below and
[`docs/PHASE1.md`](docs/PHASE1.md).

| Capability | State |
|---|---|
| `.repo` file parsing, `$releasever`/`$basearch`, `--setopt`, enable/disable | **Working** |
| Built-in Fedora + RPM Fusion free/nonfree repository set | **Working** |
| metalink and mirrorlist discovery, mirror failover | **Working** |
| `repomd.xml` / `primary.xml` parsing incl. rich deps | **Working** |
| SHA-256 verification of metadata and packages | **Working** |
| rpm version comparison (`~`, `^`, epochs, releases) | **Working** |
| Dependency solver: transitive deps, obsoletes, conflicts, ordering | **Working** |
| Local binary metadata cache | **Working** |
| COPR enable / remove / list | **Working** |
| Package download into the cache | **Working** |
| `list`, `search`, `info`, `provides`, `repoquery`, `repolist` | **Working** |
| RPM header and cpio payload parsing | **Working** |
| Installing packages to disk (`--installroot` supported) | **Working** |
| `%config` / `%config(noreplace)` → `.rpmnew` / `.rpmsave` | **Working** |
| Symlinks, hardlinks, modes, mtimes, `%ghost` entries | **Working** |
| File conflict detection before the transaction | **Working** |
| `remove`, directory pruning, "required by" protection | **Working** |
| `--test`, `--nodeps`, `--replacefiles` | **Working** |
| GPG signature verification of RPMs (RSA, SHA-256/384/512) | **Working** |
| `repo_gpgcheck` metadata signatures | **Working** |
| Key import from `gpgkey=`, `rpf verify --key FILE` | **Working** |
| EdDSA (Ed25519) and ECDSA signatures | **Not yet** — reported and refused, never silently accepted |
| Scriptlet execution (`%pre`/`%post`/`%preun`/`%postun`) | **Working** — honours `-p INTERPRETER`, runs inside `chroot` for `--installroot`, passes rpm's `$1` |
| Embedded scriptlet interpreters (`<lua>`) | **Not yet** — reported and skipped, never silently ignored |
| Reading/writing the real rpmdb | **Not yet** — uses its own DB, reads `rpm -qa` as fallback |

Scriptlets only run when RPF has root; when they are skipped, `rpf` says so on
stderr instead of staying quiet. Scriptlets written for an embedded interpreter
(`%post -p <lua>`) are reported and skipped, since RPF has no Lua runtime.

Signature verification covers RSA keys, which is what Fedora signs with. A key
or signature using EdDSA or ECDSA is reported as unsupported and the package is
refused rather than installed unverified. Key expiry, revocation and web of
trust are not evaluated: a key present in the configured keyring is trusted,
the same model `rpm --import` uses.

## Build

```sh
cargo build --release      # -> target/release/rpf
cargo test                 # 162 tests: unit, end-to-end, installation
```

Requirements: a Rust toolchain (1.70+). At runtime on Fedora, RPF uses `curl`
for downloads and `gzip`/`xz`/`zstd` to decompress metadata — all present on a
stock Fedora system.

## Usage

```sh
rpf repolist                          # configured repositories
rpf makecache                         # fetch and verify metadata
rpf search browser                    # search names, summaries, capabilities
rpf info firefox                      # details for a package
rpf provides /bin/sh                  # who provides a file or capability
rpf list --installed                  # installed packages
rpf download firefox                  # resolve + download + verify
rpf install htop                      # resolve, download, verify, install
rpf install ./some-package.rpm        # local package file
rpf verify ./some-package.rpm         # check signatures
rpf verify --key mykey.asc pkg.rpm    # ...against a specific key
rpf copr enable user/project          # add a COPR repository
rpf clean all                         # drop caches
```

Global options include `--releasever`, `--installroot`, `--setopt`,
`--enablerepo`, `--disablerepo`, `--repo`, `-C/--cacheonly`, `--refresh` and
`--nogpgcheck`.

## Repositories

With no configuration present, RPF falls back to the Fedora defaults plus RPM
Fusion, all enabled and signature-checked:

| Repository | Purpose |
|---|---|
| `fedora` | Fedora release packages |
| `updates` | Fedora updates |
| `rpmfusion-free`, `rpmfusion-free-updates` | RPM Fusion free |
| `rpmfusion-nonfree`, `rpmfusion-nonfree-updates` | RPM Fusion nonfree |

Drop your own `.repo` files in `/etc/rpf/repos.d/` (or `/etc/yum.repos.d/`) to
override them; files on disk take precedence over the built-ins.

## Architecture

| Module | Responsibility |
|---|---|
| `src/xml.rs` | Pull parser + small DOM, entity handling, CDATA |
| `src/ini.rs` | Permissive INI reader for `.repo` files |
| `src/config.rs` | Variables, repository discovery, overrides, COPR definitions |
| `src/fetch.rs` | `curl`/`file://` transport, decompression |
| `src/repomd.rs` | `repomd.xml`, metalink, mirrorlist, `primary.xml` |
| `src/version.rs` | `rpmvercmp`, EVR comparison |
| `src/deps.rs` | Dependency flags, capability matching, rich dependencies |
| `src/pkg.rs` | Package model, implicit provides, arch rules |
| `src/cache.rs` | Binary metadata store and repository sync |
| `src/solver.rs` | Resolution, obsoletes, conflicts, install ordering |
| `src/db.rs` | Installed-package database |
| `src/main.rs` | CLI |

`docs/PHASE1.md` covers the design decisions, the metadata formats handled and
the roadmap in more detail.

## License

RPF is intended to be distributed under Apache-2.0 OR MIT, matching the Rust
ecosystem's conventions.
