//! Repository configuration: `$releasever`/`$basearch` expansion, `.repo`
//! discovery, command-line overrides, and the built-in Fedora + RPM Fusion
//! repository set.

use crate::ini::Ini;
use crate::{Error, Result};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Fallback when the release version cannot be detected (e.g. RPF is being
/// exercised on a non-Fedora host or against a chroot).
pub const DEFAULT_RELEASEVER: &str = "43";

/// Fedora and RPM Fusion checked in as text, so they go through exactly the
/// same parser as any user-supplied `.repo` file.
const DEFAULT_REPOS: &str = r#"
[fedora]
name=Fedora $releasever - $basearch
metalink=https://mirrors.fedoraproject.org/metalink?repo=fedora-$releasever&arch=$basearch
enabled=1
gpgcheck=1
repo_gpgcheck=0
type=rpm
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-fedora-$releasever-$basearch
skip_if_unavailable=False

[updates]
name=Fedora $releasever - $basearch - Updates
metalink=https://mirrors.fedoraproject.org/metalink?repo=updates-released-f$releasever&arch=$basearch
enabled=1
gpgcheck=1
repo_gpgcheck=0
type=rpm
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-fedora-$releasever-$basearch
skip_if_unavailable=False

[rpmfusion-free]
name=RPM Fusion for Fedora $releasever - Free
metalink=https://mirrors.rpmfusion.org/metalink?repo=free-fedora-$releasever&arch=$basearch
enabled=1
gpgcheck=1
repo_gpgcheck=0
type=rpm-md
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-rpmfusion-free-fedora-$releasever

[rpmfusion-free-updates]
name=RPM Fusion for Fedora $releasever - Free - Updates
metalink=https://mirrors.rpmfusion.org/metalink?repo=free-fedora-updates-released-$releasever&arch=$basearch
enabled=1
gpgcheck=1
repo_gpgcheck=0
type=rpm-md
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-rpmfusion-free-fedora-$releasever

[rpmfusion-nonfree]
name=RPM Fusion for Fedora $releasever - Nonfree
metalink=https://mirrors.rpmfusion.org/metalink?repo=nonfree-fedora-$releasever&arch=$basearch
enabled=1
gpgcheck=1
repo_gpgcheck=0
type=rpm-md
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-rpmfusion-nonfree-fedora-$releasever

[rpmfusion-nonfree-updates]
name=RPM Fusion for Fedora $releasever - Nonfree - Updates
metalink=https://mirrors.rpmfusion.org/metalink?repo=nonfree-fedora-updates-released-$releasever&arch=$basearch
enabled=1
gpgcheck=1
repo_gpgcheck=0
type=rpm-md
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-rpmfusion-nonfree-fedora-$releasever
"#;

/// Variables substituted into repository URLs and names.
#[derive(Debug, Clone)]
pub struct Vars {
    pub releasever: String,
    pub basearch: String,
    pub arch: String,
    pub uuid: String,
}

impl Vars {
    pub fn detect() -> Vars {
        Vars {
            releasever: detect_releasever().unwrap_or_else(|| DEFAULT_RELEASEVER.to_string()),
            basearch: detect_basearch(),
            arch: detect_basearch(),
            uuid: detect_machine_id(),
        }
    }

    /// Expand `$var` and `${var}` occurrences. Unknown variables are left
    /// untouched so a typo is visible rather than silently blanked.
    pub fn substitute(&self, s: &str) -> String {
        if !s.contains('$') {
            return s.to_string();
        }
        let mut out = String::with_capacity(s.len());
        let bytes = s.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] != b'$' {
                out.push(bytes[i] as char);
                i += 1;
                continue;
            }
            let (name, next) = if i + 1 < bytes.len() && bytes[i + 1] == b'{' {
                match s[i + 2..].find('}') {
                    Some(end) => (&s[i + 2..i + 2 + end], i + 2 + end + 1),
                    None => {
                        out.push('$');
                        i += 1;
                        continue;
                    }
                }
            } else {
                let start = i + 1;
                let mut end = start;
                while end < bytes.len()
                    && (bytes[end].is_ascii_alphanumeric() || bytes[end] == b'_')
                {
                    end += 1;
                }
                (&s[start..end], end)
            };

            match self.lookup(name) {
                Some(value) => out.push_str(&value),
                None => {
                    out.push_str(&s[i..next]);
                }
            }
            i = next;
        }
        out
    }

    fn lookup(&self, name: &str) -> Option<String> {
        match name {
            "releasever" => Some(self.releasever.clone()),
            "releasever_major" => Some(
                self.releasever
                    .split('.')
                    .next()
                    .unwrap_or(&self.releasever)
                    .to_string(),
            ),
            "basearch" => Some(self.basearch.clone()),
            "arch" => Some(self.arch.clone()),
            "uuid" => Some(self.uuid.clone()),
            _ => None,
        }
    }
}

fn detect_releasever() -> Option<String> {
    if let Ok(v) = std::env::var("RPF_RELEASEVER") {
        if !v.is_empty() {
            return Some(v);
        }
    }
    let text = std::fs::read_to_string("/etc/os-release").ok()?;
    let mut version = None;
    let mut id = None;
    for line in text.lines() {
        if let Some(v) = line.strip_prefix("VERSION_ID=") {
            version = Some(v.trim().trim_matches('"').to_string());
        }
        if let Some(v) = line.strip_prefix("ID=") {
            id = Some(v.trim().trim_matches('"').to_string());
        }
    }
    // Only trust VERSION_ID on an rpm-based distribution; on Debian "12" would
    // be nonsense as a Fedora release.
    let id = id.unwrap_or_default();
    if matches!(id.as_str(), "fedora" | "rhel" | "centos" | "rocky" | "almalinux") {
        version
    } else {
        None
    }
}

/// Map the build architecture onto rpm's `$basearch`.
pub fn detect_basearch() -> String {
    if let Ok(v) = std::env::var("RPF_BASEARCH") {
        if !v.is_empty() {
            return v;
        }
    }
    let arch = std::env::consts::ARCH;
    match arch {
        "x86" | "i386" | "i586" | "i686" => "i686",
        "arm" => "armhfp",
        "powerpc64" => "ppc64le",
        "mips" => "mips",
        other => other,
    }
    .to_string()
}

fn detect_machine_id() -> String {
    std::fs::read_to_string("/etc/machine-id")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "rpf".to_string())
}

/// One configured repository.
#[derive(Debug, Clone)]
pub struct Repo {
    pub id: String,
    pub name: String,
    pub enabled: bool,
    pub baseurls: Vec<String>,
    pub metalink: Option<String>,
    pub mirrorlist: Option<String>,
    pub gpgcheck: bool,
    pub repo_gpgcheck: bool,
    pub gpgkeys: Vec<String>,
    pub priority: i32,
    pub cost: i32,
    pub includepkgs: Vec<String>,
    pub excludepkgs: Vec<String>,
    pub skip_if_unavailable: bool,
    /// Seconds before metadata is considered stale.
    pub metadata_expire: u64,
    /// File this came from; `None` means RPF's built-in defaults.
    pub source: Option<PathBuf>,
}

impl Repo {
    pub fn from_section(
        section: &crate::ini::Section,
        vars: &Vars,
        source: Option<PathBuf>,
    ) -> Result<Repo> {
        let id = section.name.trim().to_string();
        if id.is_empty() {
            return Err(Error::new("repository with empty id"));
        }

        let baseurls: Vec<String> = section
            .get_list("baseurl")
            .into_iter()
            .map(|u| vars.substitute(&u))
            .collect();
        let metalink = section.get("metalink").map(|m| vars.substitute(m));
        let mirrorlist = section.get("mirrorlist").map(|m| vars.substitute(m));

        if baseurls.is_empty() && metalink.is_none() && mirrorlist.is_none() {
            return Err(Error::new(format!(
                "repository '{}' has no baseurl, metalink or mirrorlist",
                id
            )));
        }

        Ok(Repo {
            name: section
                .get("name")
                .map(|n| vars.substitute(n))
                .unwrap_or_else(|| id.clone()),
            enabled: section.get_bool_or("enabled", true),
            baseurls,
            metalink,
            mirrorlist,
            gpgcheck: section.get_bool_or("gpgcheck", true),
            repo_gpgcheck: section.get_bool_or("repo_gpgcheck", false),
            gpgkeys: section
                .get_list("gpgkey")
                .into_iter()
                .map(|k| vars.substitute(&k))
                .collect(),
            priority: section.get_i64_or("priority", 99) as i32,
            cost: section.get_i64_or("cost", 1000) as i32,
            includepkgs: section.get_list("includepkgs"),
            excludepkgs: section.get_list("excludepkgs"),
            skip_if_unavailable: section.get_bool_or("skip_if_unavailable", false),
            metadata_expire: section
                .get("metadata_expire")
                .map(parse_duration)
                .unwrap_or(48 * 3600) as u64,
            source,
            id,
        })
    }

    /// A repo is either URL-based or local-file based; both are supported.
    pub fn has_remote_url(&self) -> bool {
        self.baseurls.iter().any(|u| !u.starts_with("file:"))
            || self.metalink.is_some()
            || self.mirrorlist.is_some()
    }
}

/// Parse dnf-style durations: `7d`, `48h`, `30m`, `3600` (seconds).
pub fn parse_duration(s: &str) -> i64 {
    let s = s.trim();
    if s.is_empty() {
        return 0;
    }
    let (num, mult) = match s.chars().last().unwrap() {
        's' | 'S' => (&s[..s.len() - 1], 1),
        'm' | 'M' => (&s[..s.len() - 1], 60),
        'h' | 'H' => (&s[..s.len() - 1], 3600),
        'd' | 'D' => (&s[..s.len() - 1], 86400),
        _ => (s, 1),
    };
    num.trim().parse::<i64>().unwrap_or(0).saturating_mul(mult)
}

/// Global configuration, as derived from defaults plus user input.
#[derive(Debug, Clone)]
pub struct Conf {
    pub installroot: PathBuf,
    pub reposdirs: Vec<PathBuf>,
    pub cachedir: PathBuf,
    pub dbpath: PathBuf,
    pub logdir: PathBuf,
    pub gpgcheck: bool,
    pub assume_yes: bool,
    /// Prefer the newest candidate instead of dnf's default of "first found".
    pub best: bool,
    pub keepcache: bool,
    pub metadata_expire: u64,
    pub max_parallel_downloads: usize,
    pub vars: Vars,
}

/// Everything the CLI can override before configuration is materialised.
#[derive(Debug, Clone, Default)]
pub struct Overrides {
    pub installroot: Option<PathBuf>,
    pub releasever: Option<String>,
    pub basearch: Option<String>,
    pub reposdirs: Vec<PathBuf>,
    pub cachedir: Option<PathBuf>,
    pub dbpath: Option<PathBuf>,
    pub enable: Vec<String>,
    pub disable: Vec<String>,
    /// `--setopt=key=value`, where key may be `repoid.option` or a global one.
    pub setopts: Vec<(String, String)>,
    pub no_gpgcheck: bool,
    pub assume_yes: bool,
    pub best: bool,
    /// Ignore repository files entirely and use RPF's built-ins.
    pub use_defaults_only: bool,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub conf: Conf,
    pub repos: Vec<Repo>,
    /// Repos that were skipped because their metadata is not cached and
    /// networking was disabled.
    pub notes: Vec<String>,
}

impl Config {
    pub fn load(ov: &Overrides) -> Result<Config> {
        let mut vars = Vars::detect();
        if let Some(rv) = &ov.releasever {
            vars.releasever = rv.clone();
        }
        if let Some(ba) = &ov.basearch {
            vars.basearch = ba.clone();
            vars.arch = ba.clone();
        }

        let installroot = ov
            .installroot
            .clone()
            .or_else(|| std::env::var_os("RPF_INSTALLROOT").map(PathBuf::from))
            .unwrap_or_else(|| PathBuf::from("/"));

        let reposdirs = if !ov.reposdirs.is_empty() {
            ov.reposdirs.clone()
        } else if let Some(dir) = std::env::var_os("RPF_REPOSDIR") {
            vec![PathBuf::from(dir)]
        } else {
            vec![
                installroot.join("etc/yum.repos.d"),
                installroot.join("etc/rpf/repos.d"),
            ]
        };

        let cachedir = ov
            .cachedir
            .clone()
            .or_else(|| std::env::var_os("RPF_CACHEDIR").map(PathBuf::from))
            .unwrap_or_else(|| installroot.join("var/cache/rpf"));
        let dbpath = ov
            .dbpath
            .clone()
            .or_else(|| std::env::var_os("RPF_DBPATH").map(PathBuf::from))
            .unwrap_or_else(|| installroot.join("var/lib/rpf"));

        let conf = Conf {
            installroot: installroot.clone(),
            reposdirs: reposdirs.clone(),
            cachedir,
            dbpath,
            logdir: installroot.join("var/log"),
            gpgcheck: !ov.no_gpgcheck,
            assume_yes: ov.assume_yes,
            best: ov.best,
            keepcache: false,
            metadata_expire: 48 * 3600,
            max_parallel_downloads: 3,
            vars: vars.clone(),
        };

        // Load every .repo file; later files override earlier ones by id, and
        // the built-ins are the fallback when nothing is configured.
        let mut repos: BTreeMap<String, Repo> = BTreeMap::new();
        if !ov.use_defaults_only {
            for dir in &reposdirs {
                for (path, text) in read_repo_files(dir) {
                    let ini = Ini::parse(&text)
                        .map_err(|e| e.context(format!("{}", path.display())))?;
                    for section in &ini.sections {
                        let repo = Repo::from_section(section, &vars, Some(path.clone()))
                            .map_err(|e| e.context(format!("{}", path.display())))?;
                        repos.insert(repo.id.clone(), repo);
                    }
                }
            }
        }

        if repos.is_empty() {
            let ini = Ini::parse(DEFAULT_REPOS)?;
            for section in &ini.sections {
                let repo = Repo::from_section(section, &vars, None)?;
                repos.insert(repo.id.clone(), repo);
            }
        }

        let mut config = Config {
            conf,
            repos: repos.into_values().collect(),
            notes: Vec::new(),
        };
        config.apply_overrides(ov)?;
        Ok(config)
    }

    fn apply_overrides(&mut self, ov: &Overrides) -> Result<()> {
        for id in &ov.enable {
            let repo = self
                .repo_mut(id)
                .ok_or_else(|| Error::new(format!("unknown repository '{}'", id)))?;
            repo.enabled = true;
        }
        for id in &ov.disable {
            let repo = self
                .repo_mut(id)
                .ok_or_else(|| Error::new(format!("unknown repository '{}'", id)))?;
            repo.enabled = false;
        }

        for (key, value) in &ov.setopts {
            match key.split_once('.') {
                Some((repo_id, option)) => {
                    let repo = self.repo_mut(repo_id).ok_or_else(|| {
                        Error::new(format!("--setopt: unknown repository '{}'", repo_id))
                    })?;
                    apply_repo_option(repo, option, value)?;
                }
                None => apply_global_option(self, key, value)?,
            }
        }

        if ov.no_gpgcheck {
            self.conf.gpgcheck = false;
            for repo in &mut self.repos {
                repo.gpgcheck = false;
            }
        }
        Ok(())
    }

    pub fn enabled_repos(&self) -> impl Iterator<Item = &Repo> {
        self.repos.iter().filter(|r| r.enabled)
    }

    pub fn repo(&self, id: &str) -> Option<&Repo> {
        self.repos.iter().find(|r| r.id == id)
    }

    pub fn repo_mut(&mut self, id: &str) -> Option<&mut Repo> {
        self.repos.iter_mut().find(|r| r.id == id)
    }

    /// Directory holding one subdirectory per repository.
    pub fn repo_cachedir(&self, repo_id: &str) -> PathBuf {
        self.conf.cachedir.join(sanitise_repo_id(repo_id))
    }

    pub fn installed_root(&self) -> &Path {
        &self.conf.installroot
    }
}

fn apply_repo_option(repo: &mut Repo, option: &str, value: &str) -> Result<()> {
    match option {
        "enabled" => repo.enabled = parse_bool_strict(value)?,
        "gpgcheck" => repo.gpgcheck = parse_bool_strict(value)?,
        "repo_gpgcheck" => repo.repo_gpgcheck = parse_bool_strict(value)?,
        "skip_if_unavailable" => repo.skip_if_unavailable = parse_bool_strict(value)?,
        "priority" => {
            repo.priority = value
                .parse()
                .map_err(|_| Error::new(format!("invalid priority {:?}", value)))?
        }
        "cost" => {
            repo.cost = value
                .parse()
                .map_err(|_| Error::new(format!("invalid cost {:?}", value)))?
        }
        "metadata_expire" => repo.metadata_expire = parse_duration(value) as u64,
        "baseurl" => {
            repo.baseurls = value.split_whitespace().map(|s| s.to_string()).collect()
        }
        "gpgkey" => repo.gpgkeys = value.split_whitespace().map(|s| s.to_string()).collect(),
        other => {
            return Err(Error::new(format!(
                "unknown repository option '{}' in --setopt",
                other
            )))
        }
    }
    Ok(())
}

fn apply_global_option(config: &mut Config, key: &str, value: &str) -> Result<()> {
    match key {
        "gpgcheck" => config.conf.gpgcheck = parse_bool_strict(value)?,
        "keepcache" => config.conf.keepcache = parse_bool_strict(value)?,
        "best" => config.conf.best = parse_bool_strict(value)?,
        "metadata_expire" => config.conf.metadata_expire = parse_duration(value) as u64,
        "max_parallel_downloads" => {
            config.conf.max_parallel_downloads = value
                .parse()
                .map_err(|_| Error::new(format!("invalid max_parallel_downloads {:?}", value)))?
        }
        other => {
            return Err(Error::new(format!(
                "unknown option '{}' in --setopt",
                other
            )))
        }
    }
    Ok(())
}

fn parse_bool_strict(v: &str) -> Result<bool> {
    match v.trim().to_ascii_lowercase().as_str() {
        "1" | "yes" | "true" | "on" => Ok(true),
        "0" | "no" | "false" | "off" => Ok(false),
        other => Err(Error::new(format!("invalid boolean {:?}", other))),
    }
}

fn sanitise_repo_id(id: &str) -> String {
    let cleaned: String = id
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' {
                c
            } else {
                '_'
            }
        })
        .collect();
    // A repo id of "." or ".." would turn into a path traversal component.
    if cleaned == "." || cleaned == ".." || cleaned.is_empty() {
        format!("_{}", cleaned)
    } else {
        cleaned
    }
}

fn read_repo_files(dir: &Path) -> Vec<(PathBuf, String)> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return out;
    };
    let mut paths: Vec<PathBuf> = entries
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().map(|e| e == "repo").unwrap_or(false))
        .collect();
    paths.sort();
    for path in paths {
        if let Ok(text) = std::fs::read_to_string(&path) {
            out.push((path, text));
        }
    }
    out
}

/// Build a COPR repository definition, e.g. `rpf copr enable user/project`.
pub fn copr_repo(spec: &str, vars: &Vars, chroot_override: Option<&str>) -> Result<Repo> {
    let (owner, project) = spec
        .split_once('/')
        .ok_or_else(|| Error::new(format!("invalid COPR project '{}', expected owner/project", spec)))?;
    if owner.is_empty() || project.is_empty() {
        return Err(Error::new(format!(
            "invalid COPR project '{}', expected owner/project",
            spec
        )));
    }
    let chroot = chroot_override
        .map(|s| s.to_string())
        .unwrap_or_else(|| format!("fedora-{}-{}", vars.releasever, vars.basearch));

    let text = format!(
        "[copr:{owner}:{project}]\n\
         name=Copr repo for {project} owned by {owner}\n\
         baseurl=https://download.copr.fedorainfracloud.org/results/{owner}/{project}/{chroot}/\n\
         type=rpm-md\n\
         skip_if_unavailable=True\n\
         gpgcheck=1\n\
         gpgkey=https://download.copr.fedorainfracloud.org/results/{owner}/{project}/pubkey.gpg\n\
         repo_gpgcheck=0\n\
         enabled=1\n\
         enabled_metadata=1\n",
        owner = owner,
        project = project,
        chroot = chroot
    );
    let ini = Ini::parse(&text)?;
    let section = ini
        .sections
        .first()
        .ok_or_else(|| Error::new("internal error building COPR repo"))?;
    Repo::from_section(section, vars, None)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vars() -> Vars {
        Vars {
            releasever: "41".to_string(),
            basearch: "x86_64".to_string(),
            arch: "x86_64".to_string(),
            uuid: "uuid-1".to_string(),
        }
    }

    #[test]
    fn substitutes_variables() {
        let v = vars();
        assert_eq!(
            v.substitute("https://example/f$releasever/$basearch/"),
            "https://example/f41/x86_64/"
        );
        assert_eq!(v.substitute("${releasever}-${basearch}"), "41-x86_64");
        assert_eq!(v.substitute("$releasever_major"), "41");
        assert_eq!(v.substitute("$releasever.$releasever_major"), "41.41");
        // Unknown variables survive untouched.
        assert_eq!(v.substitute("$nonsense/x"), "$nonsense/x");
        assert_eq!(v.substitute("no vars"), "no vars");
        assert_eq!(v.substitute("cost: $5"), "cost: $5");
    }

    #[test]
    fn durations() {
        assert_eq!(parse_duration("7d"), 7 * 86400);
        assert_eq!(parse_duration("48h"), 48 * 3600);
        assert_eq!(parse_duration("90m"), 90 * 60);
        assert_eq!(parse_duration("3600"), 3600);
        assert_eq!(parse_duration("garbage"), 0);
    }

    #[test]
    fn builtin_defaults_cover_fedora_and_rpmfusion() {
        let ini = Ini::parse(DEFAULT_REPOS).unwrap();
        let ids: Vec<String> = ini.sections.iter().map(|s| s.name.clone()).collect();
        assert_eq!(
            ids,
            vec![
                "fedora",
                "updates",
                "rpmfusion-free",
                "rpmfusion-free-updates",
                "rpmfusion-nonfree",
                "rpmfusion-nonfree-updates"
            ]
        );

        for section in &ini.sections {
            let repo = Repo::from_section(section, &vars(), None).unwrap();
            assert!(repo.enabled, "{} should be enabled by default", repo.id);
            assert!(repo.gpgcheck, "{} must verify signatures", repo.id);
            assert!(
                repo.metalink.is_some(),
                "{} should use a metalink",
                repo.id
            );
            assert!(!repo.gpgkeys.is_empty(), "{} needs a GPG key", repo.id);
            // No unexpanded variables may survive into the URL.
            assert!(!repo.metalink.as_ref().unwrap().contains("$releasever"));
        }
    }

    #[test]
    fn section_parsing_and_overrides() {
        let text = "\
[myrepo]
name=My Repo
baseurl=https://example.org/f$releasever/$basearch/
enabled=1
gpgcheck=0
priority=10
includepkgs=foo* bar
excludepkgs=baz
metadata_expire=12h
";
        let ini = Ini::parse(text).unwrap();
        let repo = Repo::from_section(&ini.sections[0], &vars(), None).unwrap();
        assert_eq!(repo.id, "myrepo");
        assert_eq!(repo.baseurls, vec!["https://example.org/f41/x86_64/"]);
        assert!(!repo.gpgcheck);
        assert_eq!(repo.priority, 10);
        assert_eq!(repo.includepkgs, vec!["foo*", "bar"]);
        assert_eq!(repo.excludepkgs, vec!["baz"]);
        assert_eq!(repo.metadata_expire, 12 * 3600);
    }

    #[test]
    fn repo_without_location_is_rejected() {
        let ini = Ini::parse("[broken]\nname=Broken\n").unwrap();
        let err = Repo::from_section(&ini.sections[0], &vars(), None).unwrap_err();
        assert!(err.message().contains("no baseurl"));
    }

    #[test]
    fn copr_repo_builds_download_url() {
        let repo = copr_repo("someuser/cooltool", &vars(), None).unwrap();
        assert_eq!(repo.id, "copr:someuser:cooltool");
        assert_eq!(
            repo.baseurls,
            vec!["https://download.copr.fedorainfracloud.org/results/someuser/cooltool/fedora-41-x86_64/"]
        );
        assert!(repo.gpgcheck);
        assert!(repo
            .gpgkeys
            .iter()
            .any(|k| k.ends_with("/someuser/cooltool/pubkey.gpg")));

        assert!(copr_repo("no-slash", &vars(), None).is_err());
        assert!(copr_repo("/x", &vars(), None).is_err());
    }

    #[test]
    fn load_with_defaults_only_and_overrides() {
        let tmp = std::env::temp_dir().join(format!("rpf-cfg-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();

        let ov = Overrides {
            installroot: Some(tmp.clone()),
            reposdirs: vec![tmp.join("no-such-dir")],
            cachedir: Some(tmp.join("cache")),
            releasever: Some("41".into()),
            disable: vec!["rpmfusion-nonfree".into(), "rpmfusion-nonfree-updates".into()],
            setopts: vec![("fedora.enabled".to_string(), "0".to_string())],
            ..Default::default()
        };
        let cfg = Config::load(&ov).unwrap();
        assert_eq!(cfg.repos.len(), 6);
        assert!(!cfg.repo("fedora").unwrap().enabled, "setopt should disable");
        assert!(!cfg.repo("rpmfusion-nonfree").unwrap().enabled);
        assert!(cfg.repo("updates").unwrap().enabled);
        assert!(cfg.repo("rpmfusion-free").unwrap().enabled);
        assert_eq!(
            cfg.enabled_repos().count(),
            3,
            "updates, rpmfusion-free, rpmfusion-free-updates"
        );
        assert!(cfg.repo("rpmfusion-free").unwrap().name.contains("41"));

        // Unknown repo in --enablerepo is a hard error, like dnf.
        let bad = Overrides {
            enable: vec!["nope".into()],
            ..ov.clone()
        };
        assert!(Config::load(&bad).is_err());
    }

    #[test]
    fn repo_files_on_disk_override_builtins() {
        let tmp = std::env::temp_dir().join(format!("rpf-cfg2-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let reposdir = tmp.join("repos.d");
        std::fs::create_dir_all(&reposdir).unwrap();
        std::fs::write(
            reposdir.join("local.repo"),
            "[local]\nname=Local\nbaseurl=file:///srv/repo/\nenabled=1\ngpgcheck=0\n",
        )
        .unwrap();

        let ov = Overrides {
            installroot: Some(tmp.clone()),
            reposdirs: vec![reposdir],
            cachedir: Some(tmp.join("cache")),
            releasever: Some("41".into()),
            ..Default::default()
        };
        let cfg = Config::load(&ov).unwrap();
        assert_eq!(cfg.repos.len(), 1);
        assert_eq!(cfg.repos[0].id, "local");
        assert_eq!(cfg.repo_cachedir("local"), tmp.join("cache/local"));
    }
}
