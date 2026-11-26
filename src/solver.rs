//! Dependency resolution.
//!
//! The solver is a greedy, provides-indexed resolver with backtracking over
//! candidate choice, which is the same shape dnf/libsolv use in practice:
//!
//!   1. index every package's capabilities (including implicit `name` and
//!      `name(arch)` provides) into a hash map,
//!   2. resolve the user's requests to concrete candidates,
//!   3. walk the requirement graph breadth-first, satisfying each unmet
//!      requirement with the best provider that does not introduce a conflict,
//!   4. drop packages obsoleted by the selection and order the rest so that
//!      dependencies install first.
//!
//! Every failure is recorded as a problem string rather than aborting, so the
//! CLI can report *all* unsatisfiable dependencies at once the way dnf does.

use crate::deps::{Depend, RichDep, RichOp};
use crate::pkg::Package;
use std::cmp::Ordering;
use std::collections::{HashMap, HashSet, VecDeque};

#[derive(Debug, Clone)]
pub struct SolverOptions {
    /// Architectures installable on the target.
    pub arches: Vec<String>,
    /// Prefer the newest package instead of dnf's "best available" heuristics.
    pub best: bool,
    /// Weak dependencies (Recommends/Suggests) are resolved when harmless.
    pub install_weak_deps: bool,
    /// Skip requirement traversal entirely (`--nodeps`).
    pub ignore_deps: bool,
}

impl Default for SolverOptions {
    fn default() -> Self {
        SolverOptions {
            arches: vec!["x86_64".to_string(), "noarch".to_string()],
            best: true,
            install_weak_deps: false,
            ignore_deps: false,
        }
    }
}

#[derive(Debug, Default, Clone)]
pub struct Resolution {
    /// Packages to install, ordered so dependencies come first.
    pub install: Vec<Package>,
    /// Installed packages replaced by an obsoleting package.
    pub remove: Vec<Package>,
    /// Human-readable reasons the transaction cannot proceed.
    pub problems: Vec<String>,
}

impl Resolution {
    pub fn is_empty(&self) -> bool {
        self.install.is_empty() && self.remove.is_empty()
    }
    pub fn is_ok(&self) -> bool {
        self.problems.is_empty()
    }
}

pub struct Resolver {
    available: Vec<Package>,
    installed: Vec<Package>,
    /// capability name -> indices into `available`
    index: HashMap<String, Vec<usize>>,
    /// capability name -> indices into `installed`
    installed_index: HashMap<String, Vec<usize>>,
    selected: Vec<usize>,
    selected_set: HashSet<usize>,
    /// Selected package per name, to avoid two versions of one package.
    selected_by_name: HashMap<String, usize>,
    problems: Vec<String>,
    /// Installed packages displaced by an obsolete.
    removed: Vec<Package>,
    opts: SolverOptions,
    /// Lower number = higher priority (dnf semantics).
    repo_priority: HashMap<String, i32>,
    repo_cost: HashMap<String, i32>,
}

impl Resolver {
    pub fn new(
        available: Vec<Package>,
        installed: Vec<Package>,
        opts: SolverOptions,
    ) -> Resolver {
        let mut index: HashMap<String, Vec<usize>> = HashMap::new();
        for (i, pkg) in available.iter().enumerate() {
            for cap in pkg.all_provides() {
                index.entry(cap.name).or_default().push(i);
            }
        }
        let mut installed_index: HashMap<String, Vec<usize>> = HashMap::new();
        for (i, pkg) in installed.iter().enumerate() {
            for cap in pkg.all_provides() {
                installed_index.entry(cap.name).or_default().push(i);
            }
        }
        Resolver {
            available,
            installed,
            index,
            installed_index,
            selected: Vec::new(),
            selected_set: HashSet::new(),
            selected_by_name: HashMap::new(),
            problems: Vec::new(),
            removed: Vec::new(),
            opts,
            repo_priority: HashMap::new(),
            repo_cost: HashMap::new(),
        }
    }

    /// Record repository preferences so ties break like dnf: lower `priority`
    /// wins, then lower `cost`.
    pub fn with_repo_prefs(mut self, prefs: &[(String, i32, i32)]) -> Resolver {
        for (id, priority, cost) in prefs {
            self.repo_priority.insert(id.clone(), *priority);
            self.repo_cost.insert(id.clone(), *cost);
        }
        self
    }

    pub fn available(&self) -> &[Package] {
        &self.available
    }

    pub fn installed(&self) -> &[Package] {
        &self.installed
    }

    /// Resolve an install transaction for the given specifications.
    pub fn resolve_install(mut self, specs: &[String]) -> Resolution {
        let mut roots = Vec::new();
        for spec in specs {
            match self.resolve_spec(spec) {
                Some(Ok(idx)) => roots.push(idx),
                Some(Err(already)) => {
                    let _ = already;
                }
                None => self.problems.push(format!(
                    "no match for argument: {}\n  (try 'rpf search {}')",
                    spec, spec
                )),
            }
        }

        // Select the requested packages, then walk requirements.
        let mut queue: VecDeque<(Depend, String)> = VecDeque::new();
        for idx in roots {
            if self.selected_set.contains(&idx) {
                continue;
            }
            if let Err(reason) = self.select(idx) {
                self.problems.push(reason);
                continue;
            }
            if self.opts.ignore_deps {
                continue;
            }
            let pkg = &self.available[idx];
            let name = pkg.nevra();
            for dep in pkg.requires.clone() {
                queue.push_back((dep, name.clone()));
            }
        }

        // Breadth-first requirement satisfaction.
        let mut guard = 0usize;
        while let Some((dep, needed_by)) = queue.pop_front() {
            guard += 1;
            if guard > 200_000 {
                self.problems
                    .push("dependency resolution exceeded work limit".to_string());
                break;
            }
            if self.dep_satisfied(&dep) {
                continue;
            }
            match self.satisfy(&dep, &needed_by) {
                Ok(Some(idx)) => {
                    let pkg = &self.available[idx];
                    let mut new_reqs = Vec::new();
                    for req in &pkg.requires {
                        new_reqs.push(req.clone());
                    }
                    let name = pkg.nevra();
                    for req in new_reqs {
                        queue.push_back((req, name.clone()));
                    }
                }
                Ok(None) => {}
                Err(msg) => self.problems.push(msg),
            }
        }

        self.apply_obsoletes();
        self.check_conflicts();

        let install = self.order_install();
        let remove = std::mem::take(&mut self.removed);
        let mut resolution = Resolution {
            install,
            remove,
            problems: std::mem::take(&mut self.problems),
        };
        resolution.problems.dedup();
        resolution
    }

    // -- requirement handling ------------------------------------------------

    /// Is this requirement already met by something installed or selected?
    fn dep_satisfied(&self, dep: &Depend) -> bool {
        // rpm's internal dependencies are always satisfied by the package
        // manager itself.
        if dep.name.starts_with("rpmlib(") || dep.name.starts_with("rpmlib2(") {
            return true;
        }
        if let Some(rich) = &dep.rich {
            return self.rich_satisfied(rich);
        }
        // Indexed lookup: only installed packages that provide this capability
        // need to be considered.
        if let Some(indices) = self.installed_index.get(&dep.name) {
            if indices
                .iter()
                .any(|&i| self.installed[i].satisfies(dep))
            {
                return true;
            }
        }
        self.selected
            .iter()
            .any(|i| self.available[*i].satisfies(dep))
    }

    fn rich_satisfied(&self, rich: &RichDep) -> bool {
        match rich {
            RichDep::Term(term) => self.dep_satisfied(term),
            RichDep::Expr(op, left, right) => match op {
                RichOp::And | RichOp::With => {
                    self.rich_satisfied(left) && self.rich_satisfied(right)
                }
                RichOp::Or => self.rich_satisfied(left) || self.rich_satisfied(right),
                RichOp::If => !self.rich_satisfied(right) || self.rich_satisfied(left),
                RichOp::Unless => self.rich_satisfied(right) || self.rich_satisfied(left),
                RichOp::Without => self.rich_satisfied(left) && !self.rich_satisfied(right),
            },
        }
    }

    /// Try to satisfy a requirement, selecting a provider when needed.
    fn satisfy(&mut self, dep: &Depend, needed_by: &str) -> Result<Option<usize>, String> {
        if dep.name.starts_with("rpmlib(") || dep.name.starts_with("rpmlib2(") {
            return Ok(None);
        }

        // Rich dependencies: satisfy the meaningful branch.
        if let Some(rich) = dep.rich.clone() {
            return self.satisfy_rich(&rich, needed_by);
        }

        match self.best_provider(dep, None) {
            Some(idx) => {
                if self.selected_set.contains(&idx) {
                    return Ok(Some(idx));
                }
                match self.select(idx) {
                    Ok(()) => Ok(Some(idx)),
                    Err(reason) => Err(reason),
                }
            }
            None => Err(format!(
                "nothing provides {} needed by {}",
                dep, needed_by
            )),
        }
    }

    fn satisfy_rich(
        &mut self,
        rich: &RichDep,
        needed_by: &str,
    ) -> Result<Option<usize>, String> {
        match rich {
            RichDep::Term(term) => self.satisfy(term, needed_by),
            RichDep::Expr(op, left, right) => match op {
                RichOp::Or => {
                    if let Ok(Some(idx)) = self.satisfy_rich(left, needed_by) {
                        return Ok(Some(idx));
                    }
                    self.satisfy_rich(right, needed_by)
                }
                RichOp::And | RichOp::With => {
                    let l = self.satisfy_rich(left, needed_by)?;
                    let r = self.satisfy_rich(right, needed_by)?;
                    Ok(r.or(l))
                }
                RichOp::If => {
                    // "(A if B)": only require A when B is present.
                    if self.rich_satisfied(right) {
                        self.satisfy_rich(left, needed_by)
                    } else {
                        Ok(None)
                    }
                }
                RichOp::Unless => {
                    // "(A unless B)": require A unless B is present.
                    if self.rich_satisfied(right) {
                        Ok(None)
                    } else {
                        self.satisfy_rich(left, needed_by)
                    }
                }
                RichOp::Without => {
                    // "(A without B)": A must be present, B must not be.
                    if self.rich_satisfied(right) {
                        return Err(format!(
                            "rich dependency ({}) cannot be satisfied: {} is present",
                            rich, right
                        ));
                    }
                    self.satisfy_rich(left, needed_by)
                }
            },
        }
    }

    /// Pick the best available provider of a dependency.
    fn best_provider(&self, dep: &Depend, exclude: Option<&HashSet<usize>>) -> Option<usize> {
        let indices = self.index.get(&dep.name)?;
        let mut best: Option<usize> = None;
        for &idx in indices {
            if let Some(ex) = exclude {
                if ex.contains(&idx) {
                    continue;
                }
            }
            let pkg = &self.available[idx];
            if !pkg.arch_matches(&self.opts.arches) {
                continue;
            }
            if !pkg.satisfies(dep) {
                continue;
            }
            best = match best {
                None => Some(idx),
                Some(current) => {
                    if self.better_candidate(idx, current) {
                        Some(idx)
                    } else {
                        Some(current)
                    }
                }
            };
        }
        best
    }

    /// Candidate comparison: newer EVR wins; on a tie, repository priority
    /// (lower number first), then cost, then architecture preference.
    fn better_candidate(&self, a: usize, b: usize) -> bool {
        let pa = &self.available[a];
        let pb = &self.available[b];
        match pa.cmp_evr(pb) {
            Ordering::Greater => return true,
            Ordering::Less => return false,
            Ordering::Equal => {}
        }
        let pri_a = *self.repo_priority.get(&pa.repo).unwrap_or(&99);
        let pri_b = *self.repo_priority.get(&pb.repo).unwrap_or(&99);
        if pri_a != pri_b {
            return pri_a < pri_b;
        }
        let cost_a = *self.repo_cost.get(&pa.repo).unwrap_or(&1000);
        let cost_b = *self.repo_cost.get(&pb.repo).unwrap_or(&1000);
        if cost_a != cost_b {
            return cost_a < cost_b;
        }
        // Prefer a concrete architecture over noarch for identical EVR.
        (pa.arch != "noarch") && (pb.arch == "noarch")
    }

    /// Add a package to the selection, replacing an older selection of the
    /// same name and refusing to introduce conflicts.
    fn select(&mut self, idx: usize) -> Result<(), String> {
        let pkg = self.available[idx].clone();

        if let Some(&existing) = self.selected_by_name.get(&pkg.name) {
            let existing_pkg = self.available[existing].clone();
            match existing_pkg.cmp_evr(&pkg) {
                Ordering::Less => {
                    self.deselect(existing);
                }
                Ordering::Greater => return Ok(()),
                Ordering::Equal => {
                    // Same version from another repo: keep the first, unless
                    // this one wins on repo priority.
                    if !self.better_candidate(idx, existing) {
                        return Ok(());
                    }
                    self.deselect(existing);
                }
            }
        }

        // Conflicts against the installed set.
        for inst in &self.installed {
            if pkg.name == inst.name {
                // Upgrading/replacing the same package is fine.
                continue;
            }
            if pkg.conflicts.iter().any(|c| inst.satisfies(c)) {
                return Err(format!(
                    "package {} conflicts with installed {}",
                    pkg.nevra(),
                    inst.nevra()
                ));
            }
            if inst.conflicts.iter().any(|c| pkg.satisfies(c)) {
                return Err(format!(
                    "installed {} conflicts with package {}",
                    inst.nevra(),
                    pkg.nevra()
                ));
            }
        }

        // Conflicts against what we have already selected.
        for &other in &self.selected {
            let op = &self.available[other];
            if op.name == pkg.name {
                continue;
            }
            if pkg.conflicts.iter().any(|c| op.satisfies(c))
                || op.conflicts.iter().any(|c| pkg.satisfies(c))
            {
                return Err(format!(
                    "package {} conflicts with {}",
                    pkg.nevra(),
                    op.nevra()
                ));
            }
        }

        self.selected.push(idx);
        self.selected_set.insert(idx);
        self.selected_by_name.insert(pkg.name.clone(), idx);
        Ok(())
    }

    fn deselect(&mut self, idx: usize) {
        self.selected.retain(|i| *i != idx);
        self.selected_set.remove(&idx);
        let name = self.available[idx].name.clone();
        if self.selected_by_name.get(&name) == Some(&idx) {
            self.selected_by_name.remove(&name);
        }
    }

    // -- obsoletes and conflicts --------------------------------------------

    fn apply_obsoletes(&mut self) {
        let selected = self.selected.clone();
        let mut victims: Vec<usize> = Vec::new();
        let mut removals: Vec<Package> = Vec::new();

        for &idx in &selected {
            let pkg = &self.available[idx];
            for obs in &pkg.obsoletes {
                for inst in &self.installed {
                    if inst.name == pkg.name {
                        continue;
                    }
                    if inst.satisfies(obs) {
                        removals.push(inst.clone());
                    }
                }
                for &other in &selected {
                    if other == idx {
                        continue;
                    }
                    if self.available[other].satisfies(obs) {
                        victims.push(other);
                    }
                }
            }
        }

        for victim in victims {
            self.deselect(victim);
        }
        for pkg in removals {
            if !self.removed.iter().any(|p| p.nevra() == pkg.nevra()) {
                self.removed.push(pkg);
            }
        }
    }

    fn check_conflicts(&mut self) {
        let selected = self.selected.clone();
        let mut conflict_msgs = Vec::new();
        for (i, &a) in selected.iter().enumerate() {
            for &b in selected.iter().skip(i + 1) {
                let pa = &self.available[a];
                let pb = &self.available[b];
                if pa.conflicts.iter().any(|c| pb.satisfies(c)) {
                    conflict_msgs.push(format!(
                        "package {} conflicts with {}",
                        pa.nevra(),
                        pb.nevra()
                    ));
                }
                if pb.conflicts.iter().any(|c| pa.satisfies(c)) {
                    conflict_msgs.push(format!(
                        "package {} conflicts with {}",
                        pb.nevra(),
                        pa.nevra()
                    ));
                }
            }
        }
        self.problems.extend(conflict_msgs);
    }

    // -- ordering -----------------------------------------------------------

    /// Topologically order the selection: dependencies first.
    fn order_install(&self) -> Vec<Package> {
        let selected: HashSet<usize> = self.selected_set.iter().copied().collect();
        let mut ordered: Vec<usize> = Vec::with_capacity(selected.len());
        let mut state: HashMap<usize, u8> = HashMap::new(); // 1 = visiting, 2 = done

        fn visit(
            idx: usize,
            resolver: &Resolver,
            selected: &HashSet<usize>,
            state: &mut HashMap<usize, u8>,
            ordered: &mut Vec<usize>,
        ) {
            match state.get(&idx) {
                Some(2) => return,
                Some(1) => return, // dependency cycle: rpm handles these at runtime
                _ => {}
            }
            state.insert(idx, 1);
            let pkg = &resolver.available[idx];
            for dep in &pkg.requires {
                for cand in resolver.selected.iter().copied() {
                    if !selected.contains(&cand) {
                        continue;
                    }
                    if resolver.available[cand].satisfies(dep) {
                        visit(cand, resolver, selected, state, ordered);
                    }
                }
            }
            state.insert(idx, 2);
            ordered.push(idx);
        }

        let mut roots: Vec<usize> = selected.iter().copied().collect();
        roots.sort_unstable();
        for idx in roots {
            visit(idx, self, &selected, &mut state, &mut ordered);
        }
        ordered.into_iter().map(|i| self.available[i].clone()).collect()
    }

    // -- request parsing ----------------------------------------------------

    /// Turn a user request into a package index.
    ///
    /// Accepts `name`, `name.arch`, `name-version-release.arch` and
    /// `name-version-release`. Returns:
    ///   * `Some(Ok(idx))`   — a package to install,
    ///   * `Some(Err(pkg))`  — already installed at that version,
    ///   * `None`            — no match.
    fn resolve_spec(&self, spec: &str) -> Option<Result<usize, String>> {
        let spec = spec.trim();
        if spec.is_empty() {
            return None;
        }

        // name.arch
        let (name_part, arch_part) = match spec.rsplit_once('.') {
            Some((n, a)) if is_arch(a) => (n, Some(a)),
            _ => (spec, None),
        };

        // Exact NEVRA / NEVR match.
        let mut candidates: Vec<usize> = Vec::new();
        for (i, pkg) in self.available.iter().enumerate() {
            if !pkg.arch_matches(&self.opts.arches) {
                continue;
            }
            if let Some(a) = arch_part {
                if pkg.arch != a && pkg.arch != "noarch" {
                    continue;
                }
            }
            if pkg.nevra() == spec
                || pkg.nevr() == spec
                || pkg.nevra() == name_part
                || pkg.nevr() == name_part
            {
                candidates.push(i);
            }
        }

        // Plain name or capability.
        if candidates.is_empty() {
            if let Some(indices) = self.index.get(name_part) {
                for &i in indices {
                    let pkg = &self.available[i];
                    if !pkg.arch_matches(&self.opts.arches) {
                        continue;
                    }
                    if let Some(a) = arch_part {
                        if pkg.arch != a && pkg.arch != "noarch" {
                            continue;
                        }
                    }
                    candidates.push(i);
                }
            }
        }

        if candidates.is_empty() {
            return None;
        }

        // Already satisfied by an installed package of the same name?
        let name = self.available[candidates[0]].name.clone();
        if let Some(installed) = self.installed.iter().find(|p| p.name == name) {
            let best = candidates
                .iter()
                .copied()
                .max_by(|a, b| self.available[*a].cmp_evr(&self.available[*b]))
                .unwrap();
            if installed.cmp_evr(&self.available[best]) != Ordering::Less {
                return Some(Err(installed.nevra()));
            }
        }

        let best = candidates
            .iter()
            .copied()
            .max_by(|a, b| {
                let pa = &self.available[*a];
                let pb = &self.available[*b];
                match pa.cmp_evr(pb) {
                    Ordering::Equal => {
                        let pri_a = *self.repo_priority.get(&pa.repo).unwrap_or(&99);
                        let pri_b = *self.repo_priority.get(&pb.repo).unwrap_or(&99);
                        pri_b.cmp(&pri_a) // lower priority number is better
                    }
                    ord => ord,
                }
            })
            .unwrap();
        Some(Ok(best))
    }
}

fn is_arch(s: &str) -> bool {
    matches!(
        s,
        "x86_64" | "i686" | "i586" | "i386" | "aarch64" | "armv7hl" | "ppc64le" | "s390x"
            | "noarch" | "src"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deps::DepFlags;
    use crate::version::Evr;

    fn pkg(name: &str, ver: &str, arch: &str) -> Package {
        Package {
            name: name.to_string(),
            version: ver.to_string(),
            release: "1".to_string(),
            arch: arch.to_string(),
            repo: "fedora".to_string(),
            ..Default::default()
        }
    }

    fn with_requires(mut p: Package, deps: &[(&str, Option<(&str, &str)>)]) -> Package {
        for (name, ver) in deps {
            let d = match ver {
                Some((op, v)) => {
                    Depend::versioned(*name, DepFlags::parse(op), Evr::parse(v))
                }
                None => Depend::simple(*name),
            };
            p.requires.push(d);
        }
        p
    }

    fn resolve(specs: &[&str], available: Vec<Package>, installed: Vec<Package>) -> Resolution {
        let specs: Vec<String> = specs.iter().map(|s| s.to_string()).collect();
        Resolver::new(available, installed, SolverOptions::default()).resolve_install(&specs)
    }

    #[test]
    fn resolves_transitive_dependencies_in_order() {
        let bash = with_requires(
            pkg("bash", "5.2.21", "x86_64"),
            &[("glibc", None), ("ncurses-libs", None)],
        );
        let glibc = with_requires(pkg("glibc", "2.40", "x86_64"), &[]);
        let ncurses = with_requires(pkg("ncurses-libs", "6.5", "x86_64"), &[("glibc", None)]);

        let r = resolve(&["bash"], vec![bash, glibc, ncurses], vec![]);
        assert!(r.is_ok(), "problems: {:?}", r.problems);
        let names: Vec<&str> = r.install.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names.len(), 3);
        // glibc must precede both ncurses-libs and bash.
        let pos = |n: &str| names.iter().position(|x| *x == n).unwrap();
        assert!(pos("glibc") < pos("ncurses-libs"), "{:?}", names);
        assert!(pos("ncurses-libs") < pos("bash"), "{:?}", names);
    }

    #[test]
    fn picks_newest_satisfying_version() {
        let app = with_requires(
            pkg("app", "1.0", "x86_64"),
            &[("libfoo", Some((">=", "2.0")))],
        );
        let lib1 = pkg("libfoo", "1.0", "x86_64");
        let lib2 = pkg("libfoo", "2.5", "x86_64");
        let lib3 = pkg("libfoo", "3.0", "x86_64");

        let r = resolve(&["app"], vec![app, lib1, lib2, lib3], vec![]);
        assert!(r.is_ok());
        let lib = r.install.iter().find(|p| p.name == "libfoo").unwrap();
        assert_eq!(lib.version, "3.0", "newest satisfying candidate wins");
    }

    #[test]
    fn satisfied_requirement_is_not_reinstalled() {
        let app = with_requires(pkg("app", "1.0", "x86_64"), &[("glibc", None)]);
        let glibc = pkg("glibc", "2.40", "x86_64");
        let installed = vec![pkg("glibc", "2.39", "x86_64")];

        let r = resolve(&["app"], vec![app, glibc], installed);
        assert!(r.is_ok());
        assert_eq!(r.install.len(), 1);
        assert_eq!(r.install[0].name, "app");
    }

    #[test]
    fn already_installed_request_is_a_noop() {
        let installed = vec![pkg("bash", "5.2.21", "x86_64")];
        let r = resolve(&["bash"], vec![pkg("bash", "5.2.21", "x86_64")], installed);
        assert!(r.is_ok());
        assert!(r.is_empty(), "nothing to do: {:?}", r.install);
    }

    #[test]
    fn unsatisfiable_dependency_reports_nothing_provides() {
        let app = with_requires(pkg("app", "1.0", "x86_64"), &[("missing-lib", None)]);
        let r = resolve(&["app"], vec![app], vec![]);
        assert!(!r.is_ok());
        assert!(
            r.problems.iter().any(|p| p.contains("nothing provides missing-lib")),
            "{:?}",
            r.problems
        );
    }

    #[test]
    fn unknown_spec_is_reported() {
        let r = resolve(&["does-not-exist"], vec![pkg("bash", "1", "x86_64")], vec![]);
        assert!(!r.is_ok());
        assert!(r.problems[0].contains("no match for argument"));
    }

    #[test]
    fn obsoletes_remove_installed_package() {
        let mut newpkg = pkg("newthing", "2.0", "x86_64");
        newpkg.obsoletes.push(Depend::simple("oldthing"));
        let installed = vec![pkg("oldthing", "1.0", "x86_64")];

        let r = resolve(&["newthing"], vec![newpkg], installed);
        assert!(r.is_ok(), "{:?}", r.problems);
        assert_eq!(r.remove.len(), 1);
        assert_eq!(r.remove[0].name, "oldthing");
    }

    #[test]
    fn conflicts_are_detected() {
        let mut a = pkg("a", "1.0", "x86_64");
        a.conflicts.push(Depend::simple("b"));
        let b = pkg("b", "1.0", "x86_64");
        let r = resolve(&["a", "b"], vec![a, b], vec![]);
        assert!(!r.is_ok());
        assert!(
            r.problems.iter().any(|p| p.contains("conflicts")),
            "{:?}",
            r.problems
        );
    }

    #[test]
    fn arch_filtering() {
        let opts = SolverOptions::default();
        let src = pkg("thing", "1.0", "src");
        let noarch = pkg("thing", "1.0", "noarch");
        let r = Resolver::new(vec![src, noarch], vec![], opts).resolve_install(&["thing".into()]);
        assert!(r.is_ok());
        assert_eq!(r.install.len(), 1);
        assert_eq!(r.install[0].arch, "noarch");
    }

    #[test]
    fn versioned_provides_satisfy_dependencies() {
        // A dependency on a file capability provided by a package.
        let mut provider = pkg("bash", "5.2.21", "x86_64");
        provider.provides.push(Depend::simple("/bin/sh"));
        let app = with_requires(pkg("app", "1.0", "x86_64"), &[("/bin/sh", None)]);

        let r = resolve(&["app"], vec![app, provider], vec![]);
        assert!(r.is_ok(), "{:?}", r.problems);
        assert!(r.install.iter().any(|p| p.name == "bash"));
    }

    #[test]
    fn rpmlib_requirements_are_ignored() {
        let app = with_requires(
            pkg("app", "1.0", "x86_64"),
            &[("rpmlib(PayloadIsZstd)", Some(("<=", "5.4.18-1")))],
        );
        let r = resolve(&["app"], vec![app], vec![]);
        assert!(r.is_ok(), "{:?}", r.problems);
    }

    #[test]
    fn rich_or_dependency_resolves_one_branch() {
        let app = with_requires(pkg("app", "1.0", "x86_64"), &[]);
        let mut app = app;
        app.requires.push(Depend {
            name: "(python3dist(setuptools) or python3dist(pip))".to_string(),
            flags: DepFlags::NONE,
            evr: None,
            rich: RichDep::parse("(python3dist(setuptools) or python3dist(pip))"),
        });
        let mut pip = pkg("python3-pip", "24.0", "noarch");
        pip.provides.push(Depend::simple("python3dist(pip)"));

        let r = resolve(&["app"], vec![app, pip], vec![]);
        assert!(r.is_ok(), "{:?}", r.problems);
        assert_eq!(r.install.len(), 2);
    }

    #[test]
    fn rich_if_condition_respected() {
        // "(A if B)" must not pull A when B is absent.
        let mut app = pkg("app", "1.0", "x86_64");
        app.requires.push(Depend {
            name: "(foo if bar)".to_string(),
            flags: DepFlags::NONE,
            evr: None,
            rich: RichDep::parse("(foo if bar)"),
        });
        let foo = pkg("foo", "1.0", "noarch");
        let r = resolve(&["app"], vec![app, foo], vec![]);
        assert!(r.is_ok(), "{:?}", r.problems);
        assert_eq!(r.install.len(), 1, "foo should not be pulled in");
    }

    #[test]
    fn duplicate_package_across_repos_prefers_priority() {
        let mut from_updates = pkg("bash", "5.2.21", "x86_64");
        from_updates.repo = "updates".to_string();
        let mut from_fedora = pkg("bash", "5.2.21", "x86_64");
        from_fedora.repo = "fedora".to_string();

        let r = Resolver::new(
            vec![from_fedora, from_updates],
            vec![],
            SolverOptions::default(),
        )
        .with_repo_prefs(&[
            ("fedora".to_string(), 99, 1000),
            ("updates".to_string(), 50, 1000),
        ])
        .resolve_install(&["bash".into()]);
        assert!(r.is_ok());
        assert_eq!(r.install.len(), 1);
        assert_eq!(r.install[0].repo, "updates", "lower priority number wins");
    }

    #[test]
    fn name_arch_spec() {
        let a = pkg("tool", "1.0", "x86_64");
        let b = pkg("tool", "2.0", "i686");
        let r = resolve(&["tool.x86_64"], vec![a, b], vec![]);
        assert!(r.is_ok());
        assert_eq!(r.install.len(), 1);
        assert_eq!(r.install[0].arch, "x86_64");
    }
}
