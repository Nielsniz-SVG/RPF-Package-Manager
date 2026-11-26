//! RPF command-line interface.

use rpf::cache::{self, CachedRepo};
use rpf::config::{Config, Overrides};
use rpf::db::InstalledDb;
use rpf::fetch;
use rpf::install as installer;
use rpf::rpm::Rpm;
use rpf::pkg::Package;
use rpf::solver::{Resolution, Resolver, SolverOptions};
use rpf::{digest, verify, Error, Result};
use std::collections::HashMap;

use std::path::{Path, PathBuf};

const USAGE: &str = "\
RPF — a fast, secure RPM package manager for Fedora

Usage: rpf [OPTIONS] COMMAND [ARGS...]

Package queries:
  list [PATTERN...]          List packages (--installed, --available, --all)
  search PATTERN...          Search names and summaries
  info PATTERN...            Show detailed package information
  provides CAPABILITY...     Find packages providing a file or capability
  repolist                   Show configured repositories
  repoquery PATTERN          Query available packages

Transactions:
  install SPEC...            Resolve, download and install packages
  install ./FILE.rpm         Install a local package (dependencies resolved)
  download SPEC...           Resolve and download packages into the cache
  remove PACKAGE...          Remove installed packages
  copr enable OWNER/PROJECT  Add a COPR repository
  copr remove OWNER/PROJECT  Remove a COPR repository
  copr list                  List COPR repositories

Verification:
  verify FILE.rpm...         Check package signatures against trusted keys

Maintenance:
  makecache                  Download repository metadata
  clean [--all|--metadata|--packages]
  check                      Verify the installed database

Global options:
  -y, --assumeyes            Answer yes to all questions
  -C, --cacheonly            Use only cached metadata (no network)
      --refresh              Force a metadata refresh
      --releasever=VER       Override $releasever
      --installroot=PATH     Operate on an alternative root
      --setopt=KEY=VALUE     Override a configuration option
      --enablerepo=ID        Enable a repository
      --disablerepo=ID       Disable a repository
      --repo=ID              Limit operations to a repository
      --nogpgcheck           Skip GPG signature checks
      --test                 Plan the transaction without touching the system
      --noscripts            Do not run any package scriptlets
      --replacefiles         Allow packages to overwrite conflicting files
      --nodeps               Do not resolve dependencies
      --key FILE             Trust the OpenPGP key in FILE (repeatable)
  -q, --quiet                Reduce output
  -v, --verbose              More output
  -h, --help                 Show this help
  -V, --version              Show the RPF version
";

#[derive(Debug, Default)]
struct Args {
    command: String,
    rest: Vec<String>,
    overrides: Overrides,
    cacheonly: bool,
    refresh: bool,
    quiet: bool,
    verbose: bool,
    repo_filter: Vec<String>,
    list_mode: ListMode,
    test: bool,
    noscripts: bool,
    replacefiles: bool,
    nodeps: bool,
    /// Extra key files given with `--key`.
    keys: Vec<PathBuf>,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
enum ListMode {
    #[default]
    All,
    Installed,
    Available,
}

fn main() {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    match run(&argv) {
        Ok(code) => std::process::exit(code),
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    }
}

fn run(argv: &[String]) -> Result<i32> {
    let args = parse_args(argv)?;

    match args.command.as_str() {
        "" | "help" => {
            if args.command.is_empty() {
                print!("{}", USAGE);
                return Ok(0);
            }
            print!("{}", USAGE);
            Ok(0)
        }
        "version" => {
            println!("{}", version_string());
            Ok(0)
        }
        "repolist" => cmd_repolist(&args),
        "makecache" => cmd_makecache(&args),
        "list" => cmd_list(&args),
        "search" => cmd_search(&args),
        "info" => cmd_info(&args),
        "provides" | "whatprovides" => cmd_provides(&args),
        "repoquery" => cmd_repoquery(&args),
        "download" => cmd_download(&args),
        "install" => cmd_install(&args),
        "verify" | "check-signature" | "checksig" => cmd_verify(&args),
        "remove" | "erase" => cmd_remove(&args),
        "copr" => cmd_copr(&args),
        "clean" => cmd_clean(&args),
        "check" => cmd_check(&args),
        other => Err(Error::new(format!(
            "unknown command '{}'\nRun 'rpf --help' for usage.",
            other
        ))),
    }
}

fn version_string() -> String {
    format!(
        "RPF {} ({} {})",
        rpf::VERSION,
        std::env::consts::OS,
        std::env::consts::ARCH
    )
}

fn parse_args(argv: &[String]) -> Result<Args> {
    let mut args = Args::default();
    let mut it = argv.iter().peekable();

    while let Some(arg) = it.next() {
        let (key, inline) = match arg.split_once('=') {
            Some((k, v)) if k.starts_with("--") => (k, Some(v.to_string())),
            _ => (arg.as_str(), None),
        };

        macro_rules! value {
            () => {
                match inline.clone() {
                    Some(v) => v,
                    None => it
                        .next()
                        .cloned()
                        .ok_or_else(|| Error::new(format!("{} requires a value", key)))?,
                }
            };
        }

        match key {
            "-h" | "--help" | "--usage" => {
                print!("{}", USAGE);
                std::process::exit(0);
            }
            "-V" | "--version" => {
                println!("{}", version_string());
                std::process::exit(0);
            }
            "-y" | "--assumeyes" | "--assume-yes" => args.overrides.assume_yes = true,
            "-C" | "--cacheonly" => args.cacheonly = true,
            "--refresh" => args.refresh = true,
            "-q" | "--quiet" => args.quiet = true,
            "-v" | "--verbose" => args.verbose = true,
            "--nogpgcheck" => args.overrides.no_gpgcheck = true,
            "--best" => args.overrides.best = true,
            "--test" => args.test = true,
            "--noscripts" => args.noscripts = true,
            "--replacefiles" => args.replacefiles = true,
            "--nodeps" => args.nodeps = true,
            "--key" | "--import" => args.keys.push(PathBuf::from(value!())),
            "--releasever" => args.overrides.releasever = Some(value!()),
            "--installroot" => args.overrides.installroot = Some(PathBuf::from(value!())),
            "--cachedir" => args.overrides.cachedir = Some(PathBuf::from(value!())),
            "--setopt" => {
                let kv = value!();
                let (k, v) = kv
                    .split_once('=')
                    .ok_or_else(|| Error::new(format!("--setopt expects KEY=VALUE, got {:?}", kv)))?;
                args.overrides.setopts.push((k.to_string(), v.to_string()));
            }
            "--enablerepo" => args
                .overrides
                .enable
                .extend(value!().split(',').map(|s| s.to_string())),
            "--disablerepo" => args
                .overrides
                .disable
                .extend(value!().split(',').map(|s| s.to_string())),
            "--repo" | "--repoid" => args
                .repo_filter
                .extend(value!().split(',').map(|s| s.to_string())),
            "--installed" => args.list_mode = ListMode::Installed,
            "--available" => args.list_mode = ListMode::Available,
            "--all" => args.list_mode = ListMode::All,
            _ if arg.starts_with('-') => {
                return Err(Error::new(format!(
                    "unknown option '{}'\nRun 'rpf --help' for usage.",
                    arg
                )))
            }
            _ => {
                if args.command.is_empty() {
                    args.command = arg.clone();
                } else {
                    args.rest.push(arg.clone());
                }
            }
        }
    }

    Ok(args)
}

// ---------------------------------------------------------------------------
// Configuration and metadata helpers
// ---------------------------------------------------------------------------

fn load_config(args: &Args) -> Result<Config> {
    let mut config = Config::load(&args.overrides)?;
    if !args.repo_filter.is_empty() {
        let known: Vec<String> = config.repos.iter().map(|r| r.id.clone()).collect();
        for id in &args.repo_filter {
            if !known.contains(id) {
                return Err(Error::new(format!("unknown repository '{}'", id)));
            }
        }
        config.repos.retain(|r| args.repo_filter.contains(&r.id));
    }
    Ok(config)
}

fn load_metadata(config: &Config, args: &Args) -> Result<Vec<CachedRepo>> {
    cache::load_all(config, args.cacheonly, args.refresh)
}

/// Packages from all cached repositories, filtered by the --repo option.
fn available_packages(caches: &[CachedRepo]) -> Vec<Package> {
    let mut out = Vec::new();
    for cached in caches {
        out.extend(cached.packages.iter().cloned());
    }
    out
}

fn installed_packages(config: &Config) -> Vec<Package> {
    let db = InstalledDb::load(&config.conf.dbpath).unwrap_or_default();
    if !db.packages.is_empty() {
        return db.packages;
    }
    // Fall back to the system rpmdb when RPF has not installed anything yet.
    rpf::db::rpmdb_packages(&config.conf.installroot)
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

fn cmd_repolist(args: &Args) -> Result<i32> {
    let config = load_config(args)?;
    let width = config
        .repos
        .iter()
        .map(|r| r.id.len())
        .max()
        .unwrap_or(4)
        .max(7);

    println!("{:<width$}  {:<40}  {}", "repo id", "repo name", "status", width = width);
    for repo in &config.repos {
        let status = if repo.enabled { "enabled" } else { "disabled" };
        let source = match &repo.source {
            Some(p) => p.display().to_string(),
            None => "built-in".to_string(),
        };
        println!(
            "{:<width$}  {:<40}  {}",
            repo.id,
            truncate(&repo.name, 40),
            status,
            width = width
        );
        if args.verbose {
            println!("{:width$}  {}", "", format!("from {}", source), width = width);
        }
    }

    let enabled = config.enabled_repos().count();
    println!();
    println!(
        "{} repositories configured, {} enabled",
        config.repos.len(),
        enabled
    );
    Ok(0)
}

fn cmd_makecache(args: &Args) -> Result<i32> {
    let config = load_config(args)?;
    if config.enabled_repos().count() == 0 {
        println!("No enabled repositories.");
        return Ok(0);
    }

    let mut failures = 0;
    for repo in config.enabled_repos() {
        match cache::sync_repo(&config, repo, true) {
            Ok((cached, outcome)) => {
                let verb = match outcome {
                    cache::SyncOutcome::UpToDate => "up to date",
                    cache::SyncOutcome::Updated => "downloaded",
                };
                if !args.quiet {
                    println!(
                        "{:<28} {:>7} packages  ({})",
                        repo.id,
                        cached.packages.len(),
                        verb
                    );
                }
            }
            Err(e) => {
                failures += 1;
                eprintln!("Error: repository '{}': {}", repo.id, e);
            }
        }
    }
    println!();
    println!("Metadata cache updated.");
    Ok(if failures > 0 { 1 } else { 0 })
}

fn cmd_list(args: &Args) -> Result<i32> {
    let config = load_config(args)?;
    let patterns: Vec<String> = args.rest.clone();
    let mut shown = 0;

    if args.list_mode != ListMode::Available {
        let installed = installed_packages(&config);
        for pkg in &installed {
            if matches_any(pkg, &patterns) {
                println!(
                    "{:<40} {:>20}  {}",
                    format!("{}.{}", pkg.name, pkg.arch),
                    pkg.evr().to_string_full(),
                    if pkg.repo.is_empty() { "@System" } else { &pkg.repo }
                );
                shown += 1;
            }
        }
    }

    if args.list_mode != ListMode::Installed {
        let caches = load_metadata(&config, args)?;
        let available = available_packages(&caches);
        for pkg in &available {
            if matches_any(pkg, &patterns) {
                println!(
                    "{:<40} {:>20}  {}",
                    format!("{}.{}", pkg.name, pkg.arch),
                    pkg.evr().to_string_full(),
                    pkg.repo
                );
                shown += 1;
            }
        }
    }

    if shown == 0 && !patterns.is_empty() {
        return Err(Error::new(format!(
            "no packages matched: {}",
            patterns.join(" ")
        )));
    }
    Ok(0)
}

fn cmd_search(args: &Args) -> Result<i32> {
    if args.rest.is_empty() {
        return Err(Error::new("search requires at least one pattern"));
    }
    let config = load_config(args)?;
    let caches = load_metadata(&config, args)?;
    let available = available_packages(&caches);

    // dnf searches name, summary and provides; we do the same, case-insensitively.
    let needles: Vec<String> = args.rest.iter().map(|s| s.to_lowercase()).collect();
    let mut hits = Vec::new();
    for pkg in &available {
        let haystack = format!(
            "{} {} {}",
            pkg.name,
            pkg.summary,
            pkg.provides
                .iter()
                .map(|p| p.name.as_str())
                .collect::<Vec<_>>()
                .join(" ")
        )
        .to_lowercase();
        if needles.iter().all(|n| haystack.contains(n)) {
            hits.push(pkg);
        }
    }

    if hits.is_empty() {
        println!("No matches found.");
        return Ok(0);
    }
    for pkg in &hits {
        println!("{}.{} : {}", pkg.name, pkg.arch, pkg.summary);
    }
    println!();
    println!("{} package(s) matched", hits.len());
    Ok(0)
}

fn cmd_info(args: &Args) -> Result<i32> {
    if args.rest.is_empty() {
        return Err(Error::new("info requires at least one package name"));
    }
    let config = load_config(args)?;
    let caches = load_metadata(&config, args)?;
    let available = available_packages(&caches);
    let installed = installed_packages(&config);

    let mut found = 0;
    for spec in &args.rest {
        for pkg in available.iter().filter(|p| spec_matches(p, spec)) {
            print_package_info(pkg, &installed);
            found += 1;
        }
        for pkg in installed.iter().filter(|p| spec_matches(p, spec)) {
            if !available.iter().any(|a| a.nevra() == pkg.nevra()) {
                print_package_info(pkg, &installed);
                found += 1;
            }
        }
    }
    if found == 0 {
        return Err(Error::new(format!(
            "no packages matched: {}",
            args.rest.join(" ")
        )));
    }
    Ok(0)
}

fn print_package_info(pkg: &Package, installed: &[Package]) {
    let state = if installed.iter().any(|i| i.name == pkg.name) {
        "installed"
    } else {
        "available"
    };
    println!("Name         : {}", pkg.name);
    println!("Version      : {}", pkg.evr().to_string_full());
    println!("Architecture : {}", pkg.arch);
    println!("Size         : {}", human_size(pkg.download_size));
    if pkg.installed_size > 0 {
        println!("Installed    : {}", human_size(pkg.installed_size));
    }
    println!("Repository   : {}", if pkg.repo.is_empty() { "@System" } else { &pkg.repo });
    println!("State        : {}", state);
    if !pkg.license.is_empty() {
        println!("License      : {}", pkg.license);
    }
    if !pkg.url.is_empty() {
        println!("URL          : {}", pkg.url);
    }
    println!("Summary      : {}", pkg.summary);
    if !pkg.description.is_empty() {
        println!("Description  : {}", pkg.description.replace('\n', "\n               "));
    }
    if !pkg.provides.is_empty() {
        let list: Vec<String> = pkg.provides.iter().take(8).map(|p| p.to_string()).collect();
        println!("Provides     : {}", list.join(", "));
    }
    if !pkg.requires.is_empty() {
        let list: Vec<String> = pkg
            .requires
            .iter()
            .filter(|r| !r.name.starts_with("rpmlib("))
            .take(8)
            .map(|r| r.to_string())
            .collect();
        println!("Requires     : {}", list.join(", "));
    }
    println!();
}

fn cmd_provides(args: &Args) -> Result<i32> {
    if args.rest.is_empty() {
        return Err(Error::new("provides requires a capability"));
    }
    let config = load_config(args)?;
    let caches = load_metadata(&config, args)?;
    let available = available_packages(&caches);

    let mut hits = 0;
    for needle in &args.rest {
        for pkg in &available {
            let owner = pkg.provides.iter().any(|p| p.name == *needle)
                || needle.contains('/') && pkg.owns_file(needle);
            if owner || spec_matches(pkg, needle) {
                println!("{:<28} {} : {}", needle, pkg.nevra(), pkg.summary);
                hits += 1;
            }
        }
    }
    if hits == 0 {
        println!("No package provides the requested capability.");
    }
    Ok(0)
}

fn cmd_repoquery(args: &Args) -> Result<i32> {
    if args.rest.is_empty() {
        return Err(Error::new("repoquery requires a pattern"));
    }
    let config = load_config(args)?;
    let caches = load_metadata(&config, args)?;
    let available = available_packages(&caches);

    for pkg in available.iter().filter(|p| matches_any(p, &args.rest)) {
        println!("{}", pkg.nevra());
    }
    Ok(0)
}

fn cmd_download(args: &Args) -> Result<i32> {
    if args.rest.is_empty() {
        return Err(Error::new("download requires at least one package"));
    }
    let config = load_config(args)?;
    let caches = load_metadata(&config, args)?;
    let available = available_packages(&caches);
    let installed = installed_packages(&config);

    let resolution = resolve(&config, available, installed, &args.rest);
    report_resolution(&resolution);
    if !resolution.is_ok() {
        return Ok(1);
    }
    let dir = config.conf.cachedir.join("packages");
    std::fs::create_dir_all(&dir).map_err(|e| Error::new(format!("{}: {}", dir.display(), e)))?;

    for pkg in &resolution.install {
        if pkg.repo == "@commandline" {
            println!("  {} (local file, not downloaded)", pkg.location);
            continue;
        }
        let path = download_package(&config, pkg, &dir)?;
        println!("  {}", path.display());
    }
    Ok(0)
}

fn cmd_install(args: &Args) -> Result<i32> {
    if args.rest.is_empty() {
        return Err(Error::new("install requires at least one package"));
    }
    let config = load_config(args)?;

    // Split the request into local .rpm files and repository specs.
    let mut local: HashMap<String, PathBuf> = HashMap::new();
    let mut specs: Vec<String> = Vec::new();
    for arg in &args.rest {
        let looks_like_file = arg.ends_with(".rpm") || arg.starts_with('/') || arg.starts_with("./");
        if looks_like_file {
            let path = PathBuf::from(arg);
            if !path.exists() {
                return Err(Error::new(format!("no such file: {}", path.display())));
            }
            let rpm = Rpm::open(&path)?;
            let mut pkg = rpm.package();
            if pkg.name.is_empty() {
                return Err(Error::new(format!(
                    "{}: package has no name in its header",
                    path.display()
                )));
            }
            let absolute = std::fs::canonicalize(&path).unwrap_or(path.clone());
            pkg.repo = "@commandline".to_string();
            pkg.location = absolute.display().to_string();
            pkg.download_size = std::fs::metadata(&absolute).map(|m| m.len()).unwrap_or(0);
            local.insert(pkg.nevra(), absolute);
            specs.push(pkg.nevra());
        } else {
            specs.push(arg.clone());
        }
    }

    // Repository metadata is only required for dependencies. When every
    // request is a local file and the repositories are unreachable, resolve
    // against what we have instead of failing outright.
    let all_local = specs
        .iter()
        .all(|spec| available_local_spec(&local, spec));
    let caches = match load_metadata(&config, args) {
        Ok(c) => c,
        Err(e) if all_local => {
            eprintln!("warning: repository metadata unavailable ({}); resolving local packages only", e);
            Vec::new()
        }
        Err(e) => return Err(e),
    };
    let mut available = available_packages(&caches);
    for pkg in local_rpm_packages(&local)? {
        available.push(pkg);
    }
    let installed = installed_packages(&config);

    let resolution = resolve_with(&config, available, installed, &specs, args.nodeps);
    report_resolution(&resolution);
    if !resolution.is_ok() {
        return Ok(1);
    }
    if resolution.is_empty() {
        println!("Nothing to do.");
        return Ok(0);
    }

    if config.conf.installroot == Path::new("/") && !installer::is_root() && !args.test {
        return Err(Error::new(
            "installing to / requires root; use --installroot to install elsewhere",
        ));
    }

    if args.test {
        println!("Test mode: no changes were made.");
        return Ok(0);
    }

    // Fetch every non-local package and verify it before touching the system.
    let dir = config.conf.cachedir.join("packages");
    std::fs::create_dir_all(&dir).map_err(|e| Error::new(format!("{}: {}", dir.display(), e)))?;
    if !args.quiet && resolution.install.iter().any(|p| !local.contains_key(&p.nevra())) {
        println!("\nDownloading packages:");
    }
    for pkg in &resolution.install {
        if local.contains_key(&pkg.nevra()) {
            continue;
        }
        download_package(&config, pkg, &dir)?;
        if !args.quiet {
            println!("  {}  ({})", pkg.nevra(), human_size(pkg.download_size));
        }
    }

    // Signature policy. Every package is checked; what happens on failure
    // depends on the repository's gpgcheck setting.
    if !args.overrides.no_gpgcheck {
        check_signatures(&config, args, &resolution.install, &local)?;
    }

    // Remove obsoleted packages first, then install in dependency order.
    let opts = installer::Options {
        installroot: config.conf.installroot.clone(),
        test: args.test,
        noscripts: args.noscripts,
        verbose: args.verbose,
        replacefiles: args.replacefiles,
    };

    if !resolution.remove.is_empty() {
        let names: Vec<String> = resolution.remove.iter().map(|p| p.name.clone()).collect();
        installer::remove(&config, &names, &opts)?;
        for pkg in &resolution.remove {
            println!("  removed  {}", pkg.nevra());
        }
    }

    let report = installer::install(&config, &resolution.install, &local, &opts)?;

    println!();
    for pkg in &report.installed {
        println!("  Complete! {}", pkg.nevra());
    }
    if report.installed.is_empty() {
        println!("Nothing to do.");
    } else {
        println!(
            "Installed {} package(s), {} file(s), {} written.",
            report.installed.len(),
            report.files_written,
            human_size(report.bytes_written)
        );
    }
    for path in &report.rpmnew {
        println!("  saved new config as {}", path);
    }
    for path in &report.rpmsave {
        println!("  saved original config as {}", path);
    }
    for warning in &report.warnings {
        eprintln!("warning: {}", warning);
    }
    Ok(0)
}

/// Enforce the signature policy for every package in the transaction.
///
/// Returns an error (aborting the transaction before anything is written) when
/// a signature is invalid, or when a `gpgcheck=1` repository's package cannot
/// be verified. Softer cases produce warnings.
fn check_signatures(
    config: &Config,
    args: &Args,
    packages: &[Package],
    local: &HashMap<String, PathBuf>,
) -> Result<()> {
    let mut keyring = verify::keyring_from_files(&args.keys)?;

    // Only the repositories actually involved need their keys loaded.
    let mut repo_ids: Vec<String> = packages.iter().map(|p| p.repo.clone()).collect();
    repo_ids.sort();
    repo_ids.dedup();
    for id in &repo_ids {
        if id == "@commandline" {
            continue;
        }
        if let Some(repo) = config.repo(id) {
            match verify::keys_for_repo(config, repo) {
                Ok(keys) => keyring.add_keys(keys.keys),
                Err(e) => {
                    if repo.gpgcheck {
                        return Err(Error::new(format!(
                            "repository '{}' has gpgcheck=1 but its keys are unavailable: {}",
                            repo.id, e
                        )));
                    }
                }
            }
        }
    }

    let dir = config.conf.cachedir.join("packages");
    for pkg in packages {
        let path = match local.get(&pkg.nevra()) {
            Some(path) => path.clone(),
            None => dir.join(pkg.filename()),
        };
        let is_local = pkg.repo == "@commandline";
        let gpgcheck = if is_local {
            // Local files are verified when a key is known, as dnf's
            // localpkg_gpgcheck=1 would, but we do not refuse to install an
            // unsigned local file unless the user asked for keys.
            !args.keys.is_empty()
        } else {
            config.repo(&pkg.repo).map(|r| r.gpgcheck).unwrap_or(false)
        };

        let verdict = match verify::check_package(&path, &keyring) {
            Ok(v) => v,
            Err(e) => {
                if gpgcheck {
                    return Err(Error::new(format!("{}: {}", pkg.nevra(), e)));
                }
                eprintln!("warning: {}: {}", pkg.nevra(), e);
                continue;
            }
        };

        if args.verbose {
            println!("  signatures: {} — {}", pkg.nevra(), verdict.describe());
        }

        match &verdict {
            verify::Verdict::Signed { .. } => {}
            verify::Verdict::Invalid { reasons } => {
                // A broken signature is tampering, never a relaxed setting.
                return Err(Error::new(format!(
                    "{}: signature is invalid ({}); refusing to install",
                    pkg.nevra(),
                    reasons.join("; ")
                )));
            }
            _ if gpgcheck && is_local => {
                return Err(Error::new(format!(
                    "{}: {}; refusing to install a local package that cannot be verified with the supplied keys",
                    pkg.nevra(),
                    verdict.describe()
                )))
            }
            _ if gpgcheck => {
                return Err(Error::new(format!(
                    "{}: {} and gpgcheck is enabled for repository '{}'",
                    pkg.nevra(),
                    verdict.describe(),
                    pkg.repo
                )))
            }
            _ => {
                eprintln!(
                    "warning: {} is not signature-verified ({})",
                    pkg.nevra(),
                    verdict.describe()
                );
            }
        }
    }
    Ok(())
}

fn available_local_spec(local: &HashMap<String, PathBuf>, spec: &str) -> bool {
    local.keys().any(|k| k == spec)
}

/// Parse the local `.rpm` files listed on the command line into packages.
fn local_rpm_packages(local: &HashMap<String, PathBuf>) -> Result<Vec<Package>> {
    let mut out = Vec::new();
    for (nevra, path) in local {
        let rpm = Rpm::open(path)?;
        let mut pkg = rpm.package();
        pkg.repo = "@commandline".to_string();
        pkg.location = path.display().to_string();
        pkg.download_size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
        debug_assert_eq!(&pkg.nevra(), nevra);
        out.push(pkg);
    }
    Ok(out)
}

fn cmd_remove(args: &Args) -> Result<i32> {
    if args.rest.is_empty() {
        return Err(Error::new("remove requires at least one package"));
    }
    let config = load_config(args)?;
    let db = InstalledDb::load(&config.conf.dbpath)?;

    let mut missing = Vec::new();
    let mut present = Vec::new();
    for name in &args.rest {
        if db.is_installed(name) {
            present.push(name.clone());
        } else {
            missing.push(name.clone());
        }
    }
    if !missing.is_empty() {
        return Err(Error::new(format!(
            "not installed: {}",
            missing.join(", ")
        )));
    }

    if config.conf.installroot == Path::new("/") && !installer::is_root() && !args.test {
        return Err(Error::new(
            "removing from / requires root; use --installroot to operate elsewhere",
        ));
    }

    let opts = installer::Options {
        installroot: config.conf.installroot.clone(),
        test: args.test,
        noscripts: args.noscripts,
        verbose: args.verbose,
        replacefiles: false,
    };

    if args.test {
        for name in &present {
            println!("Would remove: {}", name);
        }
        println!("Test mode: no changes were made.");
        return Ok(0);
    }

    let report = installer::remove(&config, &present, &opts)?;
    for pkg in &report.removed {
        println!("  removed  {}", pkg.nevra());
    }
    println!();
    println!("Removed {} package(s).", report.removed.len());
    for warning in &report.warnings {
        eprintln!("warning: {}", warning);
    }
    Ok(0)
}

fn cmd_clean(args: &Args) -> Result<i32> {
    let config = load_config(args)?;
    let mode = args.rest.first().map(|s| s.as_str()).unwrap_or("all");
    let cachedir = &config.conf.cachedir;

    let metadata = mode == "all" || mode == "metadata" || mode == "dbcache";
    let packages = mode == "all" || mode == "packages";

    if !metadata && !packages {
        return Err(Error::new(format!(
            "unknown clean target '{}' (expected metadata, packages or all)",
            mode
        )));
    }

    let mut removed = 0;
    if let Ok(entries) = std::fs::read_dir(cachedir) {
        for entry in entries.flatten() {
            let path = entry.path();
            let is_packages_dir = path.file_name().map(|n| n == "packages").unwrap_or(false);
            let should_remove = (is_packages_dir && packages) || (!is_packages_dir && metadata);
            if should_remove {
                if std::fs::remove_dir_all(&path).is_ok() {
                    removed += 1;
                }
            }
        }
    }
    println!("Removed {} cache entr{}.", removed, if removed == 1 { "y" } else { "ies" });
    Ok(0)
}

fn cmd_verify(args: &Args) -> Result<i32> {
    if args.rest.is_empty() {
        return Err(Error::new("verify requires at least one .rpm file"));
    }
    let config = load_config(args)?;

    // Trust: explicit keys first, then every enabled repository's gpgkey.
    let mut keyring = verify::keyring_from_files(&args.keys)?;
    let repos: Vec<&rpf::config::Repo> = config.repos.iter().filter(|r| r.enabled).collect();
    match verify::keyring_for_repos(&config, &repos) {
        Ok(repo_keys) => keyring.add_keys(repo_keys.keys),
        Err(e) if !keyring.is_empty() => {
            if args.verbose {
                eprintln!("note: no repository keys available ({})", e);
            }
        }
        Err(e) => return Err(e),
    }

    if keyring.is_empty() {
        return Err(Error::new(
            "no trusted keys: pass --key FILE, or configure gpgkey= in a repository",
        ));
    }
    if args.verbose {
        println!("Trusted keys: {}", keyring.describe().join(", "));
    }

    let mut failures = 0;
    for file in &args.rest {
        let path = PathBuf::from(file);
        match verify::check_package(&path, &keyring) {
            Ok(verdict) => {
                let status = if verdict.is_trusted() { "OK" } else { "FAILED" };
                println!("{:<40} {}  ({})", file, status, verdict.describe());
                if !verdict.is_trusted() {
                    failures += 1;
                }
            }
            Err(e) => {
                println!("{:<40} ERROR  ({})", file, e);
                failures += 1;
            }
        }
    }
    Ok(if failures > 0 { 1 } else { 0 })
}

fn cmd_check(args: &Args) -> Result<i32> {
    let config = load_config(args)?;
    let db = InstalledDb::load(&config.conf.dbpath)?;
    println!("Installed database: {}", InstalledDb::path(&config.conf.dbpath).display());
    println!("Packages recorded : {}", db.packages.len());

    let mut problems = 0;
    for pkg in &db.packages {
        if pkg.name.is_empty() || pkg.version.is_empty() {
            println!("  corrupt record: {:?}", pkg.nevra());
            problems += 1;
        }
    }
    if problems == 0 {
        println!("No problems found.");
    }
    Ok(if problems > 0 { 1 } else { 0 })
}

// ---------------------------------------------------------------------------
// Resolution and downloads
// ---------------------------------------------------------------------------

fn resolve(
    config: &Config,
    available: Vec<Package>,
    installed: Vec<Package>,
    specs: &[String],
) -> Resolution {
    resolve_with(config, available, installed, specs, false)
}

fn resolve_with(
    config: &Config,
    available: Vec<Package>,
    installed: Vec<Package>,
    specs: &[String],
    nodeps: bool,
) -> Resolution {
    let prefs: Vec<(String, i32, i32)> = config
        .repos
        .iter()
        .map(|r| (r.id.clone(), r.priority, r.cost))
        .collect();
    let mut arches = vec![config.conf.vars.basearch.clone()];
    if !arches.contains(&"noarch".to_string()) {
        arches.push("noarch".to_string());
    }
    let opts = SolverOptions {
        arches,
        best: config.conf.best,
        install_weak_deps: false,
        ignore_deps: nodeps,
    };
    Resolver::new(available, installed, opts)
        .with_repo_prefs(&prefs)
        .resolve_install(specs)
}

fn report_resolution(resolution: &Resolution) {
    if resolution.is_empty() && resolution.is_ok() {
        println!("Nothing to do.");
        return;
    }
    println!("Transaction:");
    for pkg in &resolution.install {
        println!(
            "  install  {}  ({})",
            pkg.nevra(),
            human_size(pkg.install_size_or_download())
        );
    }
    for pkg in &resolution.remove {
        println!("  remove   {}  (obsoleted)", pkg.nevra());
    }
    if !resolution.problems.is_empty() {
        println!();
        println!("Problems:");
        for problem in &resolution.problems {
            for (i, line) in problem.lines().enumerate() {
                if i == 0 {
                    println!("  - {}", line);
                } else {
                    println!("    {}", line);
                }
            }
        }
    }
    println!();
}

trait SizeExt {
    fn install_size_or_download(&self) -> u64;
}

impl SizeExt for Package {
    fn install_size_or_download(&self) -> u64 {
        if self.download_size > 0 {
            self.download_size
        } else {
            self.installed_size
        }
    }
}

/// Download one package, verifying its checksum against repository metadata.
fn download_package(config: &Config, pkg: &Package, dir: &Path) -> Result<PathBuf> {
    let dest = dir.join(pkg.filename());

    if dest.exists() {
        if let Some((algo, expected)) = &pkg.checksum {
            if digest::verify_file(&dest, algo, expected).is_ok() {
                return Ok(dest);
            }
        }
        let _ = std::fs::remove_file(&dest);
    }

    let repo = config
        .repo(&pkg.repo)
        .ok_or_else(|| Error::new(format!("package {} is from unknown repo '{}'", pkg.nevra(), pkg.repo)))?;
    let bases = cache::resolve_bases(repo)?;

    let mut last_error = None;
    for base in &bases {
        let url = fetch::join_url(base, &pkg.location);
        match fetch::fetch_to_file(&url, &dest) {
            Ok(()) => {
                last_error = None;
                break;
            }
            Err(e) => last_error = Some(e),
        }
    }
    if let Some(e) = last_error {
        return Err(e.context(format!("failed to download {}", pkg.nevra())));
    }

    if let Some((algo, expected)) = &pkg.checksum {
        digest::verify_file(&dest, algo, expected).map_err(|e| {
            let _ = std::fs::remove_file(&dest);
            e.context(format!("verifying {}", pkg.nevra()))
        })?;
    }

    if repo.gpgcheck && config.conf.gpgcheck {
        // RPM signature verification needs the header parser (next milestone);
        // say so loudly instead of pretending the package was verified.
        if std::env::var_os("RPF_QUIET_GPG_WARNING").is_none() {
            eprintln!(
                "warning: GPG signature verification of {} is not implemented yet \
                 (checksum verified against repository metadata)",
                pkg.nevra()
            );
        }
    }
    Ok(dest)
}

fn cmd_copr(args: &Args) -> Result<i32> {
    let action = args.rest.first().map(|s| s.as_str()).unwrap_or("");
    let config = load_config(args)?;

    match action {
        "enable" => {
            let spec = args
                .rest
                .get(1)
                .ok_or_else(|| Error::new("copr enable expects OWNER/PROJECT"))?;
            let repo = rpf::config::copr_repo(spec, &config.conf.vars, None)?;
            let dir = config
                .conf
                .reposdirs
                .first()
                .cloned()
                .ok_or_else(|| Error::new("no repository directory configured"))?;
            std::fs::create_dir_all(&dir)
                .map_err(|e| Error::new(format!("{}: {}", dir.display(), e)))?;
            let filename = format!("{}.repo", repo.id);
            let path = dir.join(filename);
            let text = format!(
                "[{id}]\nname={name}\nbaseurl={base}\ngpgcheck=1\nrepo_gpgcheck=0\n\
                 gpgkey={key}\nenabled=1\ntype=rpm-md\nskip_if_unavailable=True\n",
                id = repo.id,
                name = repo.name,
                base = repo.baseurls.first().cloned().unwrap_or_default(),
                key = repo.gpgkeys.first().cloned().unwrap_or_default(),
            );
            std::fs::write(&path, text)
                .map_err(|e| Error::new(format!("{}: {}", path.display(), e)))?;
            println!("Added repository '{}'", repo.id);
            println!("  {}", path.display());
            println!("Run 'rpf makecache' to fetch its metadata.");
            Ok(0)
        }
        "remove" | "disable" => {
            let spec = args
                .rest
                .get(1)
                .ok_or_else(|| Error::new("copr remove expects OWNER/PROJECT"))?;
            let repo = rpf::config::copr_repo(spec, &config.conf.vars, None)?;
            let mut removed = 0;
            for dir in &config.conf.reposdirs {
                let path = dir.join(format!("{}.repo", repo.id));
                if std::fs::remove_file(&path).is_ok() {
                    println!("Removed {}", path.display());
                    removed += 1;
                }
            }
            if removed == 0 {
                return Err(Error::new(format!("COPR repository '{}' is not configured", repo.id)));
            }
            Ok(0)
        }
        "list" => {
            let coprs: Vec<_> = config
                .repos
                .iter()
                .filter(|r| r.id.starts_with("copr:"))
                .collect();
            if coprs.is_empty() {
                println!("No COPR repositories configured.");
                return Ok(0);
            }
            for repo in coprs {
                println!(
                    "{:<40} {:<10} {}",
                    repo.id,
                    if repo.enabled { "enabled" } else { "disabled" },
                    repo.baseurls.first().cloned().unwrap_or_default()
                );
            }
            Ok(0)
        }
        other => Err(Error::new(format!(
            "unknown copr action '{}' (expected enable, remove or list)",
            other
        ))),
    }
}

// ---------------------------------------------------------------------------
// Formatting helpers
// ---------------------------------------------------------------------------

fn human_size(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{} {}", bytes, UNITS[0])
    } else {
        format!("{:.1} {}", value, UNITS[unit])
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let mut out: String = s.chars().take(max.saturating_sub(1)).collect();
    out.push('…');
    out
}

/// Match `name` and `name.arch` against a shell-style pattern.
fn spec_matches(pkg: &Package, pattern: &str) -> bool {
    let name_arch = format!("{}.{}", pkg.name, pkg.arch);
    glob_match(pattern, &pkg.name)
        || glob_match(pattern, &name_arch)
        || glob_match(pattern, &pkg.nevra())
}

fn matches_any(pkg: &Package, patterns: &[String]) -> bool {
    patterns.is_empty() || patterns.iter().any(|p| spec_matches(pkg, p))
}

/// Shell-style glob with `*` and `?`, implemented without a dependency.
fn glob_match(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    let (mut pi, mut ti) = (0usize, 0usize);
    let (mut star, mut match_at) = (None, 0usize);

    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            match_at = ti;
            pi += 1;
        } else if let Some(s) = star {
            pi = s + 1;
            match_at += 1;
            ti = match_at;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn glob_semantics() {
        assert!(glob_match("bash", "bash"));
        assert!(!glob_match("bash", "zsh"));
        assert!(glob_match("ba*", "bash"));
        assert!(glob_match("*sh", "bash"));
        assert!(glob_match("*as*", "bash"));
        assert!(glob_match("b?sh", "bash"));
        assert!(!glob_match("b?sh", "bsh"));
        assert!(glob_match("*", "anything"));
        assert!(glob_match("gnome-*", "gnome-shell"));
        assert!(!glob_match("gnome-*", "kde-plasma"));
        assert!(glob_match("*", ""));
        assert!(glob_match("", ""));
        assert!(!glob_match("", "x"));
        // Unicode must not panic or split a char.
        assert!(glob_match("fé*", "fédora"));
    }

    #[test]
    fn human_sizes() {
        assert_eq!(human_size(0), "0 B");
        assert_eq!(human_size(999), "999 B");
        assert_eq!(human_size(1024), "1.0 KiB");
        assert_eq!(human_size(1536), "1.5 KiB");
        assert_eq!(human_size(1024 * 1024), "1.0 MiB");
    }

    #[test]
    fn argument_parsing() {
        let argv: Vec<String> = ["--refresh", "--releasever=41", "install", "bash", "vim"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let args = parse_args(&argv).unwrap();
        assert_eq!(args.command, "install");
        assert_eq!(args.rest, vec!["bash", "vim"]);
        assert!(args.refresh);
        assert_eq!(args.overrides.releasever.as_deref(), Some("41"));

        let argv: Vec<String> = ["--setopt=fedora.enabled=0", "-y", "list"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let args = parse_args(&argv).unwrap();
        assert_eq!(args.command, "list");
        assert!(args.overrides.assume_yes);
        assert_eq!(
            args.overrides.setopts,
            vec![("fedora.enabled".to_string(), "0".to_string())]
        );

        let argv: Vec<String> = ["--bogus"].iter().map(|s| s.to_string()).collect();
        assert!(parse_args(&argv).is_err());
    }

    #[test]
    fn spec_matching_includes_nevra() {
        let pkg = Package {
            name: "bash".into(),
            version: "5.2.21".into(),
            release: "1.fc41".into(),
            arch: "x86_64".into(),
            ..Default::default()
        };
        assert!(spec_matches(&pkg, "bash"));
        assert!(spec_matches(&pkg, "bash.x86_64"));
        assert!(spec_matches(&pkg, "bash-5.2.21-1.fc41.x86_64"));
        assert!(spec_matches(&pkg, "ba*"));
        assert!(!spec_matches(&pkg, "zsh"));
    }
}
