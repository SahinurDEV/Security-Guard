//! The always-on watcher (port of watcher.py's Watcher). Native file events
//! (guard_core's FsWatcher: inotify / FSEvents / ReadDirectoryChangesW) say
//! which paths changed; every changed path still goes through the SQLite
//! snapshot diff, which stays the source of truth. A full snapshot pass runs
//! at start, when the OS drops events and every full_rescan_sec; without
//! native events it polls the snapshot every poll_interval_sec.
//!
//!   new .git directory            -> repo cloned   -> full repo scan
//!   .git/HEAD, refs, FETCH_HEAD   -> pull / fetch  -> rescan the repo
//!   new directory                 -> rescan its repo, if any
//!   new file outside a repo       -> single-file scan (any file type gets
//!                                    the antivirus engine; the scan_new_files_ext
//!                                    types also get the supply-chain checks)
//!
//! The first start scans everything already in the watch roots, so a machine
//! that was infected before Guard was installed is cleaned too; the
//! initial-scan.done marker in the guard home records that it ran.
//!
//! Critical findings go to alerts.jsonl and, by default, are cleaned (backed
//! up first; `guard restore` undoes it).

use std::collections::{HashMap, HashSet};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Component, Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use guard_core::watch::FsWatcher;
use serde_json::{json, Map, Value};

use super::memguard::MemoryGuard;
use super::store::Store;
use crate::av::pystr;
use crate::pyjson;
use crate::pyrepr;
use crate::scan::remediate::Remediator;
use crate::scan::scanner::{self, Scanner};
use crate::scan::workflow::Baseline;
use crate::scan::DEPS_DIR;

/// Cleared by SIGTERM / SIGINT (Ctrl+C on Windows).
pub static RUNNING: AtomicBool = AtomicBool::new(true);

/// What package managers write when an install finishes.
const LOCKFILES: &[&str] = &[
    "package-lock.json",
    "npm-shrinkwrap.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "bun.lock",
    "bun.lockb",
];

const BINARY_MASK_EXTS: &[&str] = &[
    ".woff2", ".woff", ".ttf", ".otf", ".png", ".jpg", ".jpeg", ".ico", ".gif", ".webp",
];

fn now() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

/// os.stat().st_mtime exactly as CPython computes it (sec + nsec * 1e-9), so a
/// snapshot one build wrote compares equal in the other.
fn mtime(md: &fs::Metadata) -> f64 {
    match md.modified().map(|t| t.duration_since(UNIX_EPOCH)) {
        Ok(Ok(d)) => d.as_secs() as f64 + d.subsec_nanos() as f64 * 1e-9,
        Ok(Err(e)) => {
            let d = e.duration();
            -(d.as_secs() as f64 + d.subsec_nanos() as f64 * 1e-9)
        }
        Err(_) => 0.0,
    }
}

/// str() of a Python float.
pub fn py_float(f: f64) -> String {
    if f.is_nan() {
        "nan".into()
    } else if f.is_infinite() {
        if f > 0.0 { "inf" } else { "-inf" }.into()
    } else {
        pyjson::float_repr(f)
    }
}

/// float(x) of a config value; None where Python would raise.
pub fn as_float(v: Option<&Value>) -> Option<f64> {
    match v? {
        Value::Number(n) => n.as_f64(),
        Value::Bool(b) => Some(f64::from(u8::from(*b))),
        Value::String(s) => super::parse_float(s),
        _ => None,
    }
}

/// int(x) of a config value.
fn as_int(v: Option<&Value>) -> Option<i64> {
    match v? {
        Value::Number(n) => n.as_i64().or_else(|| n.as_f64().map(|f| f.trunc() as i64)),
        Value::Bool(b) => Some(i64::from(*b)),
        Value::String(s) => s.trim().parse().ok(),
        _ => None,
    }
}

fn str_list(v: Option<&Value>) -> Vec<String> {
    match v {
        Some(Value::Array(a)) => a.iter().map(pystr::py_str).collect(),
        Some(Value::String(s)) => s.chars().map(String::from).collect(),
        Some(Value::Object(o)) => o.keys().cloned().collect(),
        _ => vec![],
    }
}

/// Path(p).parts as strings (the anchor first).
fn parts(p: &Path) -> Vec<String> {
    p.components()
        .filter(|c| !matches!(c, Component::CurDir))
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
        .collect()
}

fn is_relative_to(p: &Path, root: &Path) -> bool {
    p.strip_prefix(root).is_ok()
}

/// Every real user profile under C:\Users: the Windows task runs as SYSTEM,
/// whose ~ is the systemprofile folder.
fn windows_user_profiles() -> Vec<PathBuf> {
    let drive = std::env::var("SystemDrive")
        .ok()
        .filter(|d| !d.is_empty())
        .unwrap_or_else(|| "C:".into());
    let base = PathBuf::from(format!("{drive}\\Users"));
    const SKIP: &[&str] = &[
        "default",
        "default user",
        "public",
        "all users",
        "defaultapppool",
        "wdagutilityaccount",
        "systemprofile",
        "localservice",
        "networkservice",
    ];
    let mut out = vec![];
    if let Ok(rd) = fs::read_dir(&base) {
        for e in rd.flatten() {
            let p = e.path();
            let name = e.file_name().to_string_lossy().to_lowercase();
            if p.is_dir() && !SKIP.contains(&name.as_str()) {
                out.push(p);
            }
        }
    }
    out
}

/// os.path.expanduser for "~" and "~/..." (and "~user" on Unix).
fn expanduser(r: &str) -> PathBuf {
    let Some(rest) = r.strip_prefix('~') else {
        return PathBuf::from(r);
    };
    let cut = rest
        .find(|c| c == '/' || (cfg!(windows) && c == '\\'))
        .unwrap_or(rest.len());
    let (user, tail) = rest.split_at(cut);
    let home = if user.is_empty() {
        Some(crate::util::user_home())
    } else {
        crate::util::home_of(user)
    };
    match home {
        Some(h) => {
            let h = h.to_string_lossy().into_owned();
            let h = if h.len() > 1 {
                h.trim_end_matches('/')
            } else {
                &h
            };
            PathBuf::from(format!("{h}{tail}"))
        }
        None => PathBuf::from(r),
    }
}

fn resolve(p: &Path) -> PathBuf {
    PathBuf::from(crate::scan::py::resolve(&p.to_string_lossy()))
}

#[derive(PartialEq, Eq, Debug)]
enum Kind {
    Clone,
    GitChange,
    NewDir,
    NewFile,
    /// a file of a type outside scan_new_files_ext: antivirus engine only
    OtherFile,
    /// a node_modules directory, new or with entries added or removed (an
    /// install): scanned whole, never walked into the snapshot
    Deps,
}

struct Event {
    kind: Kind,
    path: String,
    detail: String,
}

/// Repos (insertion-ordered, first reason wins) and loose files to scan.
#[derive(Default)]
struct Work {
    repos: Vec<(String, String)>,
    files: Vec<String>,
}

impl Work {
    fn add_repo(&mut self, repo: String, reason: &str) {
        if !self.repos.iter().any(|(r, _)| *r == repo) {
            self.repos.push((repo, reason.to_string()));
        }
    }
}

pub struct Watcher {
    pub home: PathBuf,
    cfg: Map<String, Value>,
    roots: Vec<PathBuf>,
    exclude: HashSet<String>,
    exclude_sorted: Vec<String>,
    scan_exts: HashSet<String>,
    git_trigger: HashSet<String>,
    max_depth: usize,
    interval: f64,
    home_real: PathBuf,
    native: Option<FsWatcher>,
    alert_path: PathBuf,
    log_path: PathBuf,
    scanner: Scanner,
    repo_debounce_sec: f64,
    repo_scan_times: HashMap<String, f64>,
    repo_dirty: Vec<(String, String)>,
    perm_blocked: HashSet<String>,
    notify_times: HashMap<String, f64>,
    remediate: bool,
    batch_size: usize,
    max_changes_per_pass: usize,
    memguard: MemoryGuard,
    store: Store,
}

/// Appends a timestamped line to stdout and <home>/watcher.log.
pub fn log_to(log_path: &Path, msg: &str) {
    let line = format!("{}  {msg}", crate::util::now_iso());
    {
        let mut out = std::io::stdout().lock();
        let _ = writeln!(out, "{line}");
        let _ = out.flush();
    }
    if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(log_path) {
        let _ = f.write_all(crate::scan::py::text_bytes(&format!("{line}\n")).as_slice());
    }
}

impl Watcher {
    pub fn new(cfg: Map<String, Value>, home: PathBuf) -> Result<Watcher, String> {
        fs::create_dir_all(&home).map_err(|e| pystr::os_error(&e, &home.to_string_lossy()))?;
        let get = |k: &str| cfg.get(k);
        let bad = |k: &str| format!("watcher config: bad value for {k:?}");
        let roots = expand_roots(&str_list(get("watch_roots")));
        let exclude: HashSet<String> = str_list(get("exclude_dir_names")).into_iter().collect();
        let mut exclude_sorted: Vec<String> = exclude.iter().cloned().collect();
        exclude_sorted.sort();
        let max_depth = as_int(get("max_depth")).ok_or_else(|| bad("max_depth"))?;
        let interval =
            as_float(get("poll_interval_sec")).ok_or_else(|| bad("poll_interval_sec"))?;
        let home_real = resolve(&home);
        let log_path = home.join("watcher.log");

        let sig = crate::scan::sigs::load(None)?;
        let mut scanner = Scanner::new(&sig, true)?;
        // repo scans leave node_modules out: an install there is a Deps
        // event, scanned on its own, so editing a project file doesn't rescan
        // every dependency
        scanner.skip_deps = true;
        let num = |k: &str, d: f64| match get(k) {
            None => Ok(d),
            v => as_float(v).ok_or_else(|| bad(k)),
        };
        let int = |k: &str, d: i64| match get(k) {
            None => Ok(d),
            v => as_int(v).ok_or_else(|| bad(k)),
        };
        let lp = log_path.clone();
        crate::util::set_log_sink(Box::new(move |m: &str| log_to(&lp, m)));
        let memguard = MemoryGuard::new(num("mem_budget_fraction", 0.10)?);
        if pyjson::truthy(get("hard_memory_ceiling")) {
            memguard.install_hard_ceiling();
        }
        let db = home.join("watcher.snapshot.db");
        let store = Store::open(&db).map_err(|e| format!("{}: {e}", db.display()))?;
        Ok(Watcher {
            alert_path: home.join("alerts.jsonl"),
            scan_exts: str_list(get("scan_new_files_ext")).into_iter().collect(),
            git_trigger: str_list(get("git_trigger_files")).into_iter().collect(),
            max_depth: max_depth.max(0) as usize,
            interval,
            repo_debounce_sec: num("repo_debounce_sec", 30.0)?,
            remediate: get("remediate").is_none() || pyjson::truthy(get("remediate")),
            batch_size: int("batch_size", 2000)?.max(1) as usize,
            max_changes_per_pass: int("max_changes_per_pass", 2000)?.max(0) as usize,
            roots,
            exclude,
            exclude_sorted,
            home_real,
            native: None,
            log_path,
            scanner,
            repo_scan_times: HashMap::new(),
            repo_dirty: vec![],
            perm_blocked: HashSet::new(),
            notify_times: HashMap::new(),
            memguard,
            store,
            home,
            cfg,
        })
    }

    fn cfg_truthy(&self, k: &str, default: bool) -> bool {
        match self.cfg.get(k) {
            None => default,
            v => pyjson::truthy(v),
        }
    }

    // ------------------------------------------------------------ logging
    pub fn log(&self, msg: &str) {
        log_to(&self.log_path, msg);
    }

    fn throttle(&mut self) {
        let lp = self.log_path.clone();
        self.memguard.check_and_throttle(&|m| log_to(&lp, m));
    }

    fn alert(&mut self, kind: &str, path: &str, findings: Vec<Value>) {
        let n = findings.len();
        let rec =
            json!({"ts": crate::util::now_iso(), "kind": kind, "path": path, "findings": findings});
        if let Ok(mut f) = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.alert_path)
        {
            let line = format!("{}\n", pyjson::dumps(&rec, None, false));
            let _ = f.write_all(&crate::scan::py::text_bytes(&line));
        }
        self.log(&format!("ALERT [{kind}] {path} \u{2014} {n} finding(s)"));
        // in remediate mode the caller pops one "neutralized" alert after cleaning
        if !self.remediate {
            self.maybe_notify(path, n);
        }
        if let Some(Value::Array(cmd)) = self.cfg.get("quarantine_cmd") {
            if let Err(e) = run_hook(cmd, path) {
                self.log(&format!("quarantine hook failed: {e}"));
            }
        }
    }

    fn remediator(&self) -> Remediator {
        Remediator::new(&self.home)
    }

    fn remediate_repo(&mut self, repo: &str) {
        let summary = match self.remediator().clean_repo(repo) {
            Ok(s) => s,
            Err(e) => {
                self.log(&format!("remediate error {repo}: {e}"));
                self.maybe_notify(repo, 1);
                return;
            }
        };
        let len = |k: &str| summary[k].as_array().map_or(0, Vec::len);
        let (n, q, c) = (
            len("neutralized"),
            len("quarantined"),
            len("config_cleaned"),
        );
        if n + q + c > 0 {
            self.log(&format!(
                "remediated {repo}: {n} neutralized, {q} quarantined, {c} config-cleaned"
            ));
            self.notify_neutralized(repo, n + q + c);
        } else {
            self.maybe_notify(repo, 1);
        }
    }

    fn remediate_file(&mut self, path: &str, n_findings: usize, is_dropper: bool) {
        let dropper =
            is_dropper || BINARY_MASK_EXTS.contains(&pystr::suffix(path).to_lowercase().as_str());
        let res = match self.remediator().remediate_file(path, dropper) {
            Ok(r) => r,
            Err(e) => {
                self.log(&format!("remediate error {path}: {e}"));
                self.maybe_notify(path, n_findings);
                return;
            }
        };
        match res.get("action").and_then(Value::as_str) {
            Some("quarantine" | "neutralize" | "clean-settings" | "clean-tasks") => {
                self.notify_neutralized(path, 1)
            }
            _ => self.maybe_notify(path, n_findings),
        }
    }

    /// Per-target throttle: one popup a minute.
    fn may_pop(&mut self, target: &str) -> bool {
        if !self.cfg_truthy("notify", true) {
            return false;
        }
        let t = now();
        if t - self.notify_times.get(target).copied().unwrap_or(0.0) < 60.0 {
            return false;
        }
        self.notify_times.insert(target.to_string(), t);
        true
    }

    fn notify_neutralized(&mut self, target: &str, n: usize) {
        if !self.may_pop(target) {
            return;
        }
        crate::notify::notify(
            "Guard - Threat neutralized",
            &format!(
                "Removed injected malware from '{}'. {n} file(s) cleaned/quarantined; \
                 originals backed up (run 'guard restore' to undo).\n{target}",
                display_name(target)
            ),
        );
    }

    fn maybe_notify(&mut self, path: &str, n: usize) {
        if !self.may_pop(path) {
            return;
        }
        crate::notify::notify(
            "Guard - Threat detected",
            &format!(
                "Malicious code found in '{}'. {n} critical finding(s). \
                 Do NOT open this folder.\n{path}",
                display_name(path)
            ),
        );
    }

    // ------------------------------------------------------------ walk
    /// os.walk swallows errors: surface permission blocks (macOS TCC,
    /// Windows legacy junctions) so Guard is never silently blind.
    fn walk_error(&mut self, dir: &Path, e: &std::io::Error) {
        if e.kind() != std::io::ErrorKind::PermissionDenied {
            return;
        }
        let fname = dir.to_string_lossy().into_owned();
        if !self.perm_blocked.insert(fname.clone()) || self.perm_blocked.len() > 50 {
            return;
        }
        let hint = if cfg!(target_os = "macos") {
            "grant access: run 'guard permissions request' in your login session, \
             or enable Full Disk Access for guard"
        } else {
            "skipped (access denied)"
        };
        self.log(&format!("WARNING: cannot read {fname} \u{2014} {hint}"));
    }

    /// (path, is_dir, mtime) for everything under `root` up to max_depth,
    /// excluded directories pruned (.git is kept), in os.walk order with each
    /// directory's entries sorted by name, so a pass that hits
    /// max_changes_per_pass stops at the same place on every filesystem.
    fn iter_paths(
        &mut self,
        root: &Path,
        base: Option<&Path>,
        out: &mut dyn FnMut(&mut Self, String, bool, f64),
    ) {
        if !root.exists() {
            return;
        }
        let root_depth = parts(base.unwrap_or(root)).len();
        let mut stack = vec![root.to_path_buf()];
        while let Some(d) = stack.pop() {
            let rd = match fs::read_dir(&d) {
                Ok(rd) => rd,
                Err(e) => {
                    self.walk_error(&d, &e);
                    continue;
                }
            };
            let (mut dirs, mut files) = (vec![], vec![]);
            let mut failed = None;
            for e in rd {
                let e = match e {
                    Ok(e) => e,
                    Err(err) => {
                        failed = Some(err);
                        break;
                    }
                };
                let name = e.file_name().to_string_lossy().into_owned();
                let (is_dir, is_link) = match e.file_type() {
                    Ok(t) if t.is_symlink() => (
                        fs::metadata(e.path()).map(|m| m.is_dir()).unwrap_or(false),
                        true,
                    ),
                    Ok(t) => (t.is_dir(), false),
                    Err(_) => (false, false),
                };
                if is_dir {
                    dirs.push((name, is_link));
                } else {
                    files.push(name);
                }
            }
            if let Some(err) = failed {
                self.walk_error(&d, &err);
                continue;
            }
            dirs.sort();
            files.sort();
            let depth = parts(&d).len().saturating_sub(root_depth);
            if depth >= self.max_depth {
                dirs.clear();
            }
            // an excluded node_modules is still reported (its mtime moves on
            // every install), only not walked
            let deps: Vec<PathBuf> = dirs
                .iter()
                .filter(|(n, link)| n == DEPS_DIR && !link && self.exclude.contains(n))
                .map(|(n, _)| d.join(n))
                .collect();
            dirs.retain(|(n, _)| !self.exclude.contains(n));
            for p in deps {
                if let Ok(md) = fs::metadata(&p) {
                    out(self, p.to_string_lossy().into_owned(), true, mtime(&md));
                }
            }
            for (n, _) in &dirs {
                let p = d.join(n);
                if let Ok(md) = fs::metadata(&p) {
                    out(self, p.to_string_lossy().into_owned(), true, mtime(&md));
                }
            }
            for n in &files {
                let p = d.join(n);
                if let Ok(md) = fs::metadata(&p) {
                    out(self, p.to_string_lossy().into_owned(), false, mtime(&md));
                }
            }
            // descend in listing order, never into links
            for (n, is_link) in dirs.iter().rev() {
                if !is_link {
                    stack.push(d.join(n));
                }
            }
        }
    }

    // ------------------------------------------------------------ detect
    fn classify(&self, path: &str, is_dir: bool) -> Option<Event> {
        let base = pystr::name(path);
        let p = Path::new(path);
        if is_dir {
            if base == ".git" {
                let parent = p
                    .parent()
                    .map(|x| x.to_string_lossy().into_owned())
                    .unwrap_or_default();
                return Some(Event {
                    kind: Kind::Clone,
                    path: if parent.is_empty() {
                        ".".into()
                    } else {
                        parent
                    },
                    detail: "new .git directory".into(),
                });
            }
            if base == DEPS_DIR {
                return Some(Event {
                    kind: Kind::Deps,
                    path: path.into(),
                    detail: "dependencies changed".into(),
                });
            }
            return Some(Event {
                kind: Kind::NewDir,
                path: path.into(),
                detail: "new directory".into(),
            });
        }
        let comps: Vec<Component> = p
            .components()
            .filter(|c| !matches!(c, Component::CurDir))
            .collect();
        if let Some(idx) = comps.iter().position(|c| c.as_os_str() == ".git") {
            if !self.git_trigger.contains(base) {
                return None;
            }
            let repo: PathBuf = comps[..idx].iter().collect();
            return Some(Event {
                kind: Kind::GitChange,
                path: repo.to_string_lossy().into_owned(),
                detail: format!(".git/{base} changed"),
            });
        }
        let ext = pystr::suffix(path).to_lowercase();
        if self.scan_exts.contains(&ext) {
            return Some(Event {
                kind: Kind::NewFile,
                path: path.into(),
                detail: format!("new {ext} file"),
            });
        }
        Some(Event {
            kind: Kind::OtherFile,
            path: path.into(),
            detail: "new file".into(),
        })
    }

    /// Nearest ancestor holding .git, never above the watch root containing
    /// `path` (a watch root inside a huge repo such as ~ must not scan it).
    fn repo_root(&self, path: &str) -> Option<String> {
        let p = resolve(Path::new(path));
        let ceiling = self.roots.iter().filter(|r| is_relative_to(&p, r)).fold(
            None::<&PathBuf>,
            |best, r| match best {
                Some(b) if parts(r).len() <= parts(b).len() => Some(b),
                _ => Some(r),
            },
        )?;
        for cand in p.ancestors() {
            if cand.join(".git").exists() {
                return Some(cand.to_string_lossy().into_owned());
            }
            if cand == ceiling.as_path() {
                break;
            }
        }
        None
    }

    fn debounced(&self, repo: &str) -> bool {
        now() - self.repo_scan_times.get(repo).copied().unwrap_or(0.0) < self.repo_debounce_sec
    }

    fn scan_repo(&mut self, repo: &str) -> Result<(), String> {
        // 1) pre-open guard (highest priority)
        let (_, vf) = self.scanner.vscode.is_safe_to_open(repo);
        let crit: Vec<Value> = vf
            .iter()
            .filter(|f| matches!(f.severity, "critical" | "high"))
            .map(|f| Value::String(f.to_string()))
            .collect();
        let any_vs = !crit.is_empty();
        if any_vs {
            self.alert("vscode-autorun", repo, crit);
        }
        // 2) tree scan
        let results = self.scanner.scan_tree(repo);
        let tree_crit: Vec<Value> = ["magic", "fingerprint", "av"]
            .iter()
            .flat_map(|b| results[*b].as_array().cloned().unwrap_or_default())
            .filter(crate::scan::remediate::crit)
            .collect();
        let any_tree = !tree_crit.is_empty();
        if any_tree {
            self.alert("tree", repo, tree_crit);
        }
        // 3) workflow baseline diff
        let wf: Vec<Value> = Baseline::new(&self.scanner.matcher)
            .diff(repo)
            .iter()
            .filter(|f| f.severity == "critical")
            .map(|f| Value::String(f.to_string()))
            .collect();
        let any_wf = !wf.is_empty();
        if any_wf {
            self.alert("workflow-baseline", repo, wf);
        }
        if any_vs || any_tree || any_wf {
            if self.remediate {
                self.remediate_repo(repo);
            }
        } else {
            self.log(&format!("scan clean: {repo}"));
        }
        Ok(())
    }

    fn scan_file(&mut self, path: &str) {
        let ext = pystr::suffix(path).to_lowercase();
        let mut findings: Vec<Value> = if !self.scan_exts.contains(&ext) {
            vec![] // antivirus engine only (below)
        } else if scanner::BINARY_EXTS.contains(&ext.as_str()) {
            self.scanner
                .magic
                .check_file(path)
                .iter()
                .filter(|f| matches!(f.severity, "critical" | "high"))
                .map(|f| Value::String(f.to_string()))
                .collect()
        } else {
            let Some(content) = scanner::read_text_capped(Path::new(path)) else {
                return;
            };
            self.scanner
                .matcher
                .scan_content(path, &content)
                .iter()
                .filter(|f| {
                    matches!(f.severity.as_str(), "critical" | "high") && f.sig_id != "wf.name"
                })
                .map(|f| Value::String(f.to_string()))
                .collect()
        };
        if let Some(hit) = self.scanner.av_scan_file(path, path) {
            // malicious or suspicious: either way it is quarantined
            {
                findings.push(Value::String(format!(
                    "[{}] {path}: {} ({})",
                    pystr::py_str(&hit["severity"]).to_uppercase(),
                    pystr::py_str(&hit["threat"]),
                    pystr::py_str(&hit["sig_id"])
                )));
                // a script gets the excise attempt below; anything else goes whole
                if hit["action"] == "quarantine"
                    && self.remediate
                    && !crate::scan::remediate::SCRIPT_EXTS.contains(&ext.as_str())
                {
                    let n = findings.len();
                    self.alert("new-file", path, findings);
                    self.remediate_file(path, n, true);
                    return;
                }
            }
        }
        if !findings.is_empty() {
            let n = findings.len();
            self.alert("new-file", path, findings);
            if self.remediate {
                self.remediate_file(path, n, false);
            }
        }
    }

    // ------------------------------------------------------------ loop
    /// Sorts a batch of changed paths into repo and file scans, stopping at
    /// `cap` (max_changes_per_pass) so a mass change can't grow them without
    /// limit.
    fn handle_changes(
        &self,
        changes: &[(String, &str)],
        work: &mut Work,
        is_dir: &HashSet<String>,
        cap: usize,
    ) {
        for (path, _status) in changes {
            if work.repos.len() + work.files.len() >= cap {
                return;
            }
            let Some(ev) = self.classify(path, is_dir.contains(path)) else {
                continue;
            };
            if !is_dir.contains(path) && LOCKFILES.contains(&pystr::name(path)) {
                // written once an install is done: scan what it installed
                let nm = Path::new(path).with_file_name(DEPS_DIR);
                if nm.is_dir() {
                    work.add_repo(nm.to_string_lossy().into_owned(), "lockfile changed");
                }
            }
            match ev.kind {
                Kind::Clone | Kind::GitChange | Kind::Deps => work.add_repo(ev.path, &ev.detail),
                Kind::NewDir => {
                    if let Some(repo) = self.repo_root(&ev.path) {
                        work.add_repo(repo, "new dir in repo");
                    }
                }
                Kind::NewFile => {
                    if let Some(repo) = self.repo_root(path) {
                        work.add_repo(repo, "new file in repo");
                    } else if work.files.len() < cap {
                        work.files.push(path.clone());
                    }
                }
                // inside a repo only the scan_new_files_ext types (and git
                // activity) trigger a repo scan; editing other files must not
                Kind::OtherFile => {
                    if work.files.len() < cap && self.repo_root(path).is_none() {
                        work.files.push(path.clone());
                    }
                }
            }
        }
    }

    fn flush(
        &mut self,
        batch: &mut Vec<(String, f64)>,
        is_dir: &mut HashSet<String>,
        gen: i64,
        prime: bool,
        work: &mut Work,
    ) -> Result<(), String> {
        if batch.is_empty() {
            return Ok(());
        }
        let r = if prime {
            self.store
                .touch_batch(batch, gen)
                .map_err(|e| e.to_string())
        } else {
            match self.store.upsert_batch(batch, gen) {
                Ok(changes) => {
                    if !changes.is_empty() {
                        self.handle_changes(&changes, work, is_dir, self.max_changes_per_pass);
                    }
                    Ok(())
                }
                Err(e) => Err(e.to_string()),
            }
        };
        batch.clear();
        is_dir.clear();
        self.throttle();
        r
    }

    /// One full pass: stream every watched path through the snapshot in
    /// batches (never the whole tree in memory) and scan what changed.
    /// `prime` records the tree without scanning (first run).
    pub fn poll_once(&mut self, prime: bool) -> Result<usize, String> {
        let gen = self.store.next_generation().map_err(|e| e.to_string())?;
        let mut batch: Vec<(String, f64)> = vec![];
        let mut is_dir: HashSet<String> = HashSet::new();
        let mut work = Work::default();
        let mut err: Option<String> = None;
        for root in self.roots.clone() {
            self.iter_paths(&root, None, &mut |me, path, dir, mt| {
                if err.is_some() {
                    return;
                }
                if dir {
                    is_dir.insert(path.clone());
                }
                batch.push((path, mt));
                if batch.len() >= me.batch_size {
                    if let Err(e) = me.flush(&mut batch, &mut is_dir, gen, prime, &mut work) {
                        err = Some(e);
                    }
                }
            });
            if let Some(e) = err.take() {
                return Err(e);
            }
        }
        self.flush(&mut batch, &mut is_dir, gen, prime, &mut work)?;
        // files removed since the last pass
        if let Err(e) = self.store.sweep_deleted(gen) {
            self.log(&format!("sweep error: {e}"));
        }
        if prime {
            return Ok(0);
        }
        Ok(self.run_scans(work))
    }

    /// The first start's pass: records every watched path like `poll_once`
    /// and scans all of them, not only what changed, with no
    /// max_changes_per_pass cap, so malware that was already on the machine
    /// before Guard was installed is found. Loose files are scanned batch by
    /// batch (memory stays bounded); each repo is scanned once, at the end.
    pub fn initial_scan(&mut self) -> Result<usize, String> {
        let gen = self.store.next_generation().map_err(|e| e.to_string())?;
        let mut batch: Vec<(String, f64)> = vec![];
        let mut is_dir: HashSet<String> = HashSet::new();
        let mut repos = Work::default();
        let mut handled = 0;
        let mut err: Option<String> = None;
        for root in self.roots.clone() {
            self.iter_paths(&root, None, &mut |me, path, dir, mt| {
                if err.is_some() {
                    return;
                }
                if dir {
                    is_dir.insert(path.clone());
                }
                batch.push((path, mt));
                if batch.len() >= me.batch_size {
                    match me.initial_flush(&mut batch, &mut is_dir, gen, &mut repos) {
                        Ok(n) => handled += n,
                        Err(e) => err = Some(e),
                    }
                }
            });
            if let Some(e) = err.take() {
                return Err(e);
            }
        }
        handled += self.initial_flush(&mut batch, &mut is_dir, gen, &mut repos)?;
        if let Err(e) = self.store.sweep_deleted(gen) {
            self.log(&format!("sweep error: {e}"));
        }
        handled += self.run_scans(repos);
        Ok(handled)
    }

    fn initial_flush(
        &mut self,
        batch: &mut Vec<(String, f64)>,
        is_dir: &mut HashSet<String>,
        gen: i64,
        repos: &mut Work,
    ) -> Result<usize, String> {
        if batch.is_empty() {
            return Ok(0);
        }
        self.store
            .upsert_batch(batch, gen)
            .map_err(|e| e.to_string())?;
        let all: Vec<(String, &str)> = batch.iter().map(|(p, _)| (p.clone(), "new")).collect();
        let mut work = Work::default();
        self.handle_changes(&all, &mut work, is_dir, usize::MAX);
        batch.clear();
        is_dir.clear();
        for (repo, reason) in work.repos {
            repos.add_repo(repo, &reason);
        }
        let n = self.run_scans(Work {
            repos: vec![],
            files: work.files,
        });
        self.throttle();
        Ok(n)
    }

    /// Scans what a pass found, plus any debounced repo that has settled.
    fn run_scans(&mut self, work: Work) -> usize {
        let mut handled = 0;
        for (repo, reason) in &work.repos {
            if self.debounced(repo) {
                // still changing right after a scan (a checkout still landing
                // files): rescan once the debounce window closes
                match self.repo_dirty.iter_mut().find(|(r, _)| r == repo) {
                    Some(slot) => slot.1 = reason.clone(),
                    None => self.repo_dirty.push((repo.clone(), reason.clone())),
                }
                continue;
            }
            self.repo_scan_times.insert(repo.clone(), now());
            self.log(&format!("scan trigger: {repo} ({reason})"));
            if let Err(e) = self.scan_repo(repo) {
                self.log(&format!("repo scan error {repo}: {e}"));
            }
            handled += 1;
            self.throttle();
        }
        for (repo, _) in self.repo_dirty.clone() {
            if work.repos.iter().any(|(r, _)| *r == repo) || self.debounced(&repo) {
                continue;
            }
            let i = self
                .repo_dirty
                .iter()
                .position(|(r, _)| *r == repo)
                .unwrap();
            let (_, reason) = self.repo_dirty.remove(i);
            self.repo_scan_times.insert(repo.clone(), now());
            self.log(&format!("scan trigger (settled): {repo} ({reason})"));
            if let Err(e) = self.scan_repo(&repo) {
                self.log(&format!("repo scan error {repo}: {e}"));
            }
            handled += 1;
            self.throttle();
        }
        for f in &work.files {
            self.scan_file(f);
            handled += 1;
        }
        handled
    }

    // ------------------------------------------------------------ native events
    fn scope_root(&self, p: &Path) -> Option<PathBuf> {
        self.roots
            .iter()
            .filter(|r| is_relative_to(p, r))
            .fold(None::<&PathBuf>, |best, r| match best {
                Some(b) if parts(r).len() <= parts(b).len() => Some(b),
                _ => Some(r),
            })
            .cloned()
    }

    /// The watch root when the polling walk would report `p`, else None.
    fn in_scope(&self, p: &Path, is_dir: bool) -> Option<PathBuf> {
        if is_relative_to(p, &self.home_real) {
            return None;
        }
        let root = self.scope_root(p)?;
        if p == root {
            return None;
        }
        let rel = parts(p.strip_prefix(&root).ok()?);
        // a node_modules directory itself is reported, as the walk does
        let dirs = if is_dir && rel.last().map(String::as_str) != Some(DEPS_DIR) {
            &rel[..]
        } else {
            &rel[..rel.len() - 1]
        };
        if dirs.iter().any(|n| self.exclude.contains(n)) {
            return None;
        }
        let parent_depth = rel.len() - 1;
        if parent_depth > self.max_depth || (is_dir && parent_depth == self.max_depth) {
            return None;
        }
        Some(root)
    }

    /// Diffs the paths native events reported against the snapshot and scans
    /// what changed, as a polling pass would. A directory new to the snapshot
    /// is walked too: its contents may have landed before the OS watch did.
    pub fn handle_native(&mut self, paths: Vec<PathBuf>) -> Result<usize, String> {
        let gen = self.store.current_generation().map_err(|e| e.to_string())?;
        let mut batch: Vec<(String, f64)> = vec![];
        let mut is_dir: HashSet<String> = HashSet::new();
        let mut work = Work::default();
        let mut err: Option<String> = None;
        // a burst reports a path several times (create, write, close); scan it once
        let mut seen = HashSet::new();
        for p in paths {
            if !seen.insert(p.clone()) {
                continue;
            }
            let Ok(md) = fs::metadata(&p) else {
                continue; // already gone
            };
            let dir = md.is_dir();
            let Some(root) = self.in_scope(&p, dir) else {
                continue;
            };
            let s = p.to_string_lossy().into_owned();
            // only a directory new to the snapshot is walked: Windows also
            // reports a known directory as modified whenever an entry changes
            let walk = dir
                && pystr::name(&s) != DEPS_DIR
                && !self.store.contains(&s).map_err(|e| e.to_string())?;
            let mut add = |me: &mut Self, path: String, d: bool, mt: f64| {
                if err.is_some() {
                    return;
                }
                if d {
                    is_dir.insert(path.clone());
                }
                batch.push((path, mt));
                if batch.len() >= me.batch_size {
                    if let Err(e) = me.flush(&mut batch, &mut is_dir, gen, false, &mut work) {
                        err = Some(e);
                    }
                }
            };
            add(self, s, dir, mtime(&md));
            if walk {
                self.iter_paths(&p, Some(&root), &mut add);
            }
            if let Some(e) = err.take() {
                return Err(e);
            }
        }
        self.flush(&mut batch, &mut is_dir, gen, false, &mut work)?;
        Ok(self.run_scans(work))
    }

    fn start_native(&mut self) -> Option<FsWatcher> {
        if !self.cfg_truthy("native_events", true) {
            return None;
        }
        let cap = match self.cfg.get("native_queue_cap") {
            None => 50000,
            v => as_int(v).unwrap_or(50000),
        };
        match FsWatcher::new(
            self.roots.clone(),
            self.exclude_sorted.clone(),
            vec![self.home_real.clone()],
            self.max_depth,
            cap.max(0) as usize,
        ) {
            Ok(fw) => {
                let full = self
                    .cfg
                    .get("full_rescan_sec")
                    .map_or("300".into(), pystr::py_str);
                self.log(&format!(
                    "native file events: {}, {} watch(es); full rescan every {full}s",
                    fw.backend(),
                    fw.watch_count()
                ));
                Some(fw)
            }
            Err(e) => {
                self.log(&format!(
                    "native file events failed ({e}); polling every {}s",
                    py_float(self.interval)
                ));
                None
            }
        }
    }

    /// Waits up to poll_interval_sec for events -> (paths, overflow). Once
    /// events arrive it keeps collecting briefly, so a burst (checkout,
    /// extract) is one batch. Short slices keep SIGTERM responsive.
    fn wait_native(&mut self) -> (Vec<PathBuf>, bool) {
        let mut paths = vec![];
        let mut overflow = false;
        let start = Instant::now();
        let deadline = start + Duration::from_secs_f64(self.interval.clamp(0.0, 1e9));
        let mut settle_until: Option<Instant> = None;
        while RUNNING.load(Ordering::SeqCst) {
            let t = Instant::now();
            let end = settle_until.unwrap_or(deadline);
            if t >= end {
                break;
            }
            let Some(native) = self.native.as_ref() else {
                break;
            };
            let (got, lost, errors) = native.drain((end - t).min(Duration::from_millis(500)));
            for e in errors {
                self.log(&format!("native events: {e}"));
                if e.starts_with("watch limit reached") {
                    self.log(
                        "WARNING: OS file-watch limit reached (Linux: raise \
                         fs.inotify.max_user_watches); falling back to polling",
                    );
                    self.native = None;
                    return (paths, true);
                }
            }
            paths.extend(got);
            overflow = overflow || lost;
            if (!paths.is_empty() || overflow) && settle_until.is_none() {
                settle_until = Some((Instant::now() + Duration::from_millis(300)).min(deadline));
            }
            if overflow || paths.len() >= self.max_changes_per_pass {
                break;
            }
        }
        (paths, overflow)
    }

    /// At startup, check Guard can read its watch roots; on macOS raise the
    /// "Allow" prompts.
    fn check_permissions(&mut self) {
        let mut blocked = vec![];
        for r in &self.roots {
            if !r.exists() {
                continue;
            }
            if let Err(e) = fs::read_dir(r).and_then(|mut rd| rd.next().transpose()) {
                if e.kind() == std::io::ErrorKind::PermissionDenied {
                    blocked.push(Value::String(r.to_string_lossy().into_owned()));
                }
            }
        }
        if blocked.is_empty() {
            return;
        }
        self.log(&format!(
            "WARNING: cannot read {} watch root(s): {}",
            blocked.len(),
            pyrepr::repr(&Value::Array(blocked))
        ));
        if cfg!(target_os = "macos") {
            self.log("requesting access (an Allow prompt should appear)\u{2026}");
            crate::permissions::request(true);
        }
    }

    pub fn run(&mut self) {
        install_signal_handlers();
        let roots: Vec<Value> = self
            .roots
            .iter()
            .map(|r| Value::String(r.to_string_lossy().into_owned()))
            .collect();
        self.log(&format!(
            "watcher started; roots={} interval={}s",
            pyrepr::repr(&Value::Array(roots)),
            py_float(self.interval)
        ));
        self.log(&format!("memguard: {}", self.memguard.summary()));
        self.check_permissions();
        // events start before priming, so nothing landing meanwhile is missed
        self.native = self.start_native();
        let mut last_full = 0.0;
        let marker = self.home.join("initial-scan.done");
        // first start (also an install upgraded from a build without it):
        // scan what is already on the machine
        if !marker.exists() {
            self.log("initial scan: scanning existing files in the watch roots");
            match self.initial_scan() {
                Ok(n) => {
                    if let Err(e) = fs::write(&marker, format!("{}\n", crate::util::now_iso())) {
                        self.log(&format!("could not write {}: {e}", marker.display()));
                    }
                    let paths = self.store.count().unwrap_or(0);
                    self.log(&format!(
                        "initial scan complete: {paths} paths, {n} scanned"
                    ));
                }
                Err(e) => self.log(&format!("initial scan error: {e}")),
            }
            last_full = now();
        } else if self.store.is_empty().unwrap_or(false) {
            // the snapshot was reset after the initial scan already ran:
            // record the tree silently (existing files aren't re-alerted)
            self.log(
                "priming baseline snapshot (first run \u{2014} existing files not re-alerted)",
            );
            if let Err(e) = self.poll_once(true) {
                self.log(&format!("poll error: {e}"));
            }
            let n = self.store.count().unwrap_or(0);
            self.log(&format!("primed {n} paths"));
            last_full = now();
        }
        let num = |k: &str, d: f64| match self.cfg.get(k) {
            None => d,
            v => as_float(v).unwrap_or(d),
        };
        let update_every = num("update_check_sec", 6.0 * 3600.0);
        let full_every = num("full_rescan_sec", 300.0);
        let mut last_update = 0.0;
        while RUNNING.load(Ordering::SeqCst) {
            let pass = if self.native.is_none() {
                self.poll_once(false).map(|_| ())
            } else {
                let (paths, overflow) = self.wait_native();
                if overflow || now() - last_full >= full_every || self.native.is_none() {
                    if overflow && last_full != 0.0 {
                        self.log("native events dropped; running a full snapshot pass");
                    }
                    last_full = now();
                    self.poll_once(false).map(|_| ())
                } else {
                    self.handle_native(paths).map(|_| ())
                }
            };
            if let Err(e) = pass {
                self.log(&format!("poll error: {e}"));
            }
            // the signed OTA check (blocklist + binary); never fatal
            if update_every > 0.0 && now() - last_update >= update_every {
                last_update = now();
                match crate::update::Updater::from_env(crate::VERSION)
                    .and_then(|u| u.check_and_apply())
                {
                    Ok(res) if res.binary_updated() => {
                        self.log("new binary installed via OTA - restarting to run it");
                        self.store.close();
                        // launchd/systemd restart on any exit; the Windows task
                        // only on failure
                        std::process::exit(if cfg!(windows) { 1 } else { 0 });
                    }
                    Ok(_) => {}
                    Err(e) => self.log(&format!("update check error: {e}")),
                }
            }
            if self.native.is_some() {
                continue; // wait_native already waited
            }
            let ticks = (self.interval * 10.0).clamp(0.0, 1e12) as u64;
            for _ in 0..ticks {
                if !RUNNING.load(Ordering::SeqCst) {
                    break;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        }
        self.store.close();
        self.log("watcher stopped");
    }
}

/// The basename shown in a popup.
fn display_name(target: &str) -> String {
    let t = target.trim_end_matches(['/', '\\']);
    let base = if cfg!(windows) {
        t.rsplit(['/', '\\']).next().unwrap_or("")
    } else {
        t.rsplit('/').next().unwrap_or("")
    };
    if base.is_empty() {
        target.to_string()
    } else {
        base.to_string()
    }
}

/// The configured quarantine hook: `cmd... <path>`, 30 s at most.
fn run_hook(cmd: &[Value], path: &str) -> Result<(), String> {
    let argv: Vec<String> = cmd.iter().map(pystr::py_str).collect();
    let (prog, args) = argv.split_first().ok_or("empty quarantine_cmd")?;
    let mut child = Command::new(prog)
        .args(args)
        .arg(path)
        .spawn()
        .map_err(|e| pystr::spawn_error(&e, prog))?;
    let end = Instant::now() + Duration::from_secs(30);
    loop {
        if child.try_wait().map_err(|e| e.to_string())?.is_some() {
            return Ok(());
        }
        if Instant::now() >= end {
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!(
                "Command '{}' timed out after 30 seconds",
                pyrepr::repr(&Value::Array(
                    argv.iter()
                        .cloned()
                        .chain([path.to_string()])
                        .map(Value::String)
                        .collect()
                ))
            ));
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Resolves the configured roots. On Windows the service runs as SYSTEM, so a
/// "~/..." root means that folder under every real user profile.
fn expand_roots(raw: &[String]) -> Vec<PathBuf> {
    let mut out = vec![];
    for r in raw {
        if cfg!(windows) && (r == "~" || r.starts_with("~/") || r.starts_with("~\\")) {
            let rest = r[1..].trim_start_matches(['/', '\\']);
            for prof in windows_user_profiles() {
                out.push(if rest.is_empty() {
                    prof
                } else {
                    prof.join(rest)
                });
            }
        } else {
            out.push(expanduser(r));
        }
    }
    let mut seen = HashSet::new();
    out.into_iter()
        .map(|p| resolve(&p))
        .filter(|p| seen.insert(p.clone()))
        .collect()
}

#[cfg(unix)]
fn install_signal_handlers() {
    extern "C" fn stop(_: libc::c_int) {
        RUNNING.store(false, Ordering::SeqCst);
    }
    // SAFETY: the handler only stores to an atomic, which is async-signal-safe.
    unsafe {
        libc::signal(libc::SIGTERM, stop as *const () as libc::sighandler_t);
        libc::signal(libc::SIGINT, stop as *const () as libc::sighandler_t);
    }
}

#[cfg(windows)]
fn install_signal_handlers() {
    use windows_sys::Win32::System::Console::SetConsoleCtrlHandler;
    unsafe extern "system" fn stop(_: u32) -> i32 {
        RUNNING.store(false, Ordering::SeqCst);
        1
    }
    // SAFETY: registering a handler that only stores to an atomic.
    unsafe {
        SetConsoleCtrlHandler(Some(stop), 1);
    }
}

#[cfg(not(any(unix, windows)))]
fn install_signal_handlers() {}

#[cfg(test)]
mod tests {
    use super::*;

    /// A watcher over <tmp>/root (max_depth 3, no repo debounce) with its
    /// home beside it, as test_watcher_native.py's fixture builds it.
    fn make(name: &str) -> (Watcher, PathBuf, PathBuf) {
        let base = std::env::temp_dir().join(format!("guard-native-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(base.join("root")).unwrap();
        let base = resolve(&base);
        let root = base.join("root");
        let mut cfg = super::super::default_config();
        cfg.insert("watch_roots".into(), json!([root.to_string_lossy()]));
        cfg.insert("notify".into(), json!(false));
        cfg.insert("max_depth".into(), json!(3));
        cfg.insert("repo_debounce_sec".into(), json!(0));
        let w = Watcher::new(cfg, base.join("home")).unwrap();
        (w, root, base)
    }

    /// `base` joined with a "/"-separated relative path, one component at a
    /// time, so it reads the way the OS lists it on Windows too.
    fn at(base: &Path, rel: &str) -> PathBuf {
        rel.split('/').fold(base.to_path_buf(), |p, c| p.join(c))
    }

    fn touch(p: &Path) -> PathBuf {
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, b"x").unwrap();
        p.to_path_buf()
    }

    fn done(mut w: Watcher, base: &Path) {
        w.store.close();
        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn new_and_repeated_events() {
        let (mut w, root, base) = make("new");
        w.poll_once(true).unwrap();
        let f = touch(&at(&root, "Downloads/a.js"));
        assert_eq!(w.handle_native(vec![f.clone()]).unwrap(), 1);
        // a repeat event with no newer mtime is not new work
        assert_eq!(w.handle_native(vec![f.clone()]).unwrap(), 0);
        // a burst reports one file several times: scanned once
        let g = touch(&at(&root, "Downloads/b.js"));
        assert_eq!(w.handle_native(vec![g.clone(), g.clone(), g]).unwrap(), 1);
        // deleted before we looked
        assert_eq!(w.handle_native(vec![root.join("gone.js")]).unwrap(), 0);
        // a full pass after native events finds nothing new
        assert_eq!(w.poll_once(false).unwrap(), 0);
        done(w, &base);
    }

    #[test]
    fn modified_file_is_rescanned() {
        let (mut w, root, base) = make("modified");
        let f = touch(&root.join("a.js"));
        w.poll_once(true).unwrap();
        let later = fs::metadata(&f).unwrap().modified().unwrap() + Duration::from_secs(10);
        fs::File::options()
            .write(true)
            .open(&f)
            .unwrap()
            .set_modified(later)
            .unwrap();
        assert_eq!(w.handle_native(vec![f]).unwrap(), 1);
        done(w, &base);
    }

    /// A clone or a folder moved in raises one event for its top directory;
    /// what is inside must still be found.
    #[test]
    fn directory_moved_in_is_walked() {
        let (mut w, root, base) = make("moved");
        w.poll_once(true).unwrap();
        let src = at(&base, "elsewhere/proj");
        fs::create_dir_all(src.join(".git")).unwrap();
        fs::write(at(&src, ".git/HEAD"), b"ref: refs/heads/main\n").unwrap();
        touch(&at(&src, "src/index.js"));
        let proj = root.join("proj");
        fs::rename(&src, &proj).unwrap();
        assert_eq!(w.handle_native(vec![proj.clone()]).unwrap(), 1);
        let log = fs::read_to_string(w.home.join("watcher.log")).unwrap();
        assert!(
            log.contains(&format!("scan trigger: {}", proj.display())),
            "{log}"
        );
        done(w, &base);
    }

    /// in_scope() agrees with the polling walk on excludes and depth, and
    /// never admits the guard home, other trees or the root itself.
    #[test]
    fn scope_matches_polling_walk() {
        let (mut w, root, base) = make("scope");
        for rel in [
            "a.js",
            "d1/b.js",
            "d1/d2/c.js",
            "d1/d2/d3/d.js",
            "d1/d2/d3/d4/e.js",
            "node_modules/x.js",
            "d1/node_modules/y.js",
            "d1/build",
            ".git/HEAD",
        ] {
            touch(&at(&root, rel));
        }
        let mut walked = HashSet::new();
        w.iter_paths(&root.clone(), None, &mut |_, p, _, _| {
            walked.insert(p);
        });
        fn every(d: &Path, out: &mut Vec<PathBuf>) {
            for e in fs::read_dir(d).unwrap().flatten() {
                out.push(e.path());
                if e.path().is_dir() {
                    every(&e.path(), out);
                }
            }
        }
        let mut all = vec![];
        every(&root, &mut all);
        let scoped: HashSet<String> = all
            .iter()
            .filter(|p| w.in_scope(p, p.is_dir()).is_some())
            .map(|p| p.to_string_lossy().into_owned())
            .collect();
        assert_eq!(scoped, walked);
        // a *file* named like an excluded directory
        assert!(scoped.contains(&at(&root, "d1/build").to_string_lossy().into_owned()));
        assert!(w
            .in_scope(&w.home_real.join("watcher.log"), false)
            .is_none());
        assert!(w.in_scope(&at(&base, "other/a.js"), false).is_none());
        assert!(w.in_scope(&root, true).is_none());
        done(w, &base);
    }
}
