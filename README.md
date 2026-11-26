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

**Verify before you trust.** Repository metadata is checked against the
checksums in `repomd.xml` (both the compressed and the decompressed form), and
every downloaded RPM is checked against the checksum in the repository metadata
before it is used. A failed check aborts the transaction; nothing is written on
a mismatch.

**Say what you know and what you don't.** Where a piece is not implemented yet,
RPF refuses and tells you, rather than silently doing half the job. See
[Status](#status).

## Status

Milestone 1 (this commit) is the metadata, resolution and download
foundation. It is complete and tested end to end. Filesystem installation is
the remaining piece of the foundation.

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
| GPG signature verification of RPMs | **Not yet** — checksums only |
| Installing to the filesystem, `%post` scripts, admin files | **Not yet** — next milestone |
| `remove` writing to disk | **Not yet** — next milestone |
| Reading/writing the real rpmdb | **Not yet** — uses its own DB for now |

`rpf install` currently resolves the whole transaction, downloads and verifies
every package, then stops and exits non-zero with an explanation instead of
pretending the system was updated. `rpf download` gives you the verified
packages without the install step.

## Build

```sh
cargo build --release      # -> target/release/rpf
cargo test                 # 94 tests: unit + end-to-end
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
rpf install htop                      # resolve + download (see Status)
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
