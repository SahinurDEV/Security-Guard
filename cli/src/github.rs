//! `guard github`: the force-push watchdog.
//!
//! Every few minutes, for each git repo under the watch roots, Guard asks each
//! remote for its default branch (plus `main` / `master`). Guard remembers the
//! last tip it saw in the repo itself, under refs/guard/good/<remote>/<branch>,
//! so the commits stay on disk. When the remote's new tip no longer contains
//! that commit, someone rewrote the branch (a force push), and Guard restores
//! it on its own:
//!
//! * the rewritten tip is kept as evidence under
//!   refs/guard/rewritten/<remote>/<branch>/<unix time>;
//! * the good tip is pushed back with `--force-with-lease=<branch>:<rewritten
//!   tip>`, so the push only lands while the branch still points at the
//!   rewrite (two machines restoring at once can't clobber each other, and the
//!   one that saw the newest good history wins);
//! * the developer gets an alert and a popup.
//!
//! Only the default branch, `main` and `master` are watched: force-pushing a
//! feature branch (rebasing a PR) is normal and left alone. The push uses the
//! developer's own git credentials, so git runs as the repo's owner. On Linux
//! the root watcher switches to that user. On macOS the watcher already runs
//! as the user. On Windows a per-user `guard github watch` task does it, since
//! SYSTEM can't use the developer's Credential Manager.
//!
//! A rewrite is restored only if Guard's last good check of that branch was
//! within RESTORE_WINDOW_SEC. A machine that was offline for longer reports
//! the rewrite but does not roll back work it never saw; machines that were
//! online have already restored it.

use std::collections::BTreeMap;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::{json, Map, Value};

/// A rewrite seen later than this after the last good check is reported, not
/// rolled back.
pub const RESTORE_WINDOW_SEC: u64 = 72 * 3600;
/// How often `guard github watch` and the watcher check.
pub const DEFAULT_INTERVAL_SEC: u64 = 300;
/// Any git call taking longer than this is killed (a hung network).
const GIT_TIMEOUT: Duration = Duration::from_secs(120);
/// Repos below this many directory levels under a root are not looked for.
const DEFAULT_MAX_DEPTH: usize = 6;

const USAGE: &str = "usage: guard github check [ROOT ...] | watch [--interval SECONDS]\n";

/// What a pass found on one branch.
#[derive(Debug, Clone, PartialEq)]
pub enum Outcome {
    /// rewritten and pushed back to `good`
    Restored,
    /// rewritten; the restore push failed (no access, network, a newer rewrite)
    RestoreFailed(String),
    /// rewritten, but Guard hadn't checked the branch for too long to roll it back
    TooOld,
}

#[derive(Debug, Clone)]
pub struct Rewrite {
    pub repo: String,
    pub remote: String,
    pub branch: String,
    pub good: String,
    pub bad: String,
    pub evidence: String,
    pub outcome: Outcome,
}

impl Rewrite {
    pub fn to_json(&self) -> Value {
        let (status, error) = match &self.outcome {
            Outcome::Restored => ("restored", None),
            Outcome::RestoreFailed(e) => ("restore-failed", Some(e.clone())),
            Outcome::TooOld => ("not-restored-too-old", None),
        };
        let mut m = json!({
            "repo": self.repo, "remote": self.remote, "branch": self.branch,
            "good": self.good, "rewritten": self.bad, "evidence": self.evidence,
            "status": status,
        });
        if let Some(e) = error {
            m["error"] = json!(e);
        }
        m
    }

    pub fn summary(&self) -> String {
        let short = |s: &str| s.chars().take(10).collect::<String>();
        match &self.outcome {
            Outcome::Restored => format!(
                "force push on {}/{} of {}: restored {} (rewritten tip {} kept as {})",
                self.remote, self.branch, self.repo, short(&self.good), short(&self.bad), self.evidence
            ),
            Outcome::RestoreFailed(e) => format!(
                "force push on {}/{} of {}: could not restore {} ({e}); rewritten tip {} kept as {}",
                self.remote, self.branch, self.repo, short(&self.good), short(&self.bad), self.evidence
            ),
            Outcome::TooOld => format!(
                "force push on {}/{} of {}: not restored, Guard last checked it more than {} h ago; \
                 the old tip {} is kept as refs/guard/good-before/{}/{}",
                self.remote, self.branch, self.repo, RESTORE_WINDOW_SEC / 3600, short(&self.good),
                self.remote, self.branch
            ),
        }
    }

    fn popup(&self) -> (&'static str, String) {
        let name = Path::new(&self.repo)
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| self.repo.clone());
        let b = format!("{}/{}", self.remote, self.branch);
        match &self.outcome {
            Outcome::Restored => (
                "Guard - Force push undone",
                format!(
                    "Someone force-pushed '{b}' of '{name}'. Guard restored it. If you didn't do this, \
                     a token may be stolen: revoke your GitHub tokens now.\n{}",
                    self.repo
                ),
            ),
            Outcome::RestoreFailed(_) => (
                "Guard - Force push detected",
                format!(
                    "Someone force-pushed '{b}' of '{name}' and Guard could not restore it. \
                     See ~/.guard alerts. Do not pull until it is fixed.\n{}",
                    self.repo
                ),
            ),
            Outcome::TooOld => (
                "Guard - Force push detected",
                format!(
                    "'{b}' of '{name}' was rewritten while this computer was offline. \
                     Check it before pulling.\n{}",
                    self.repo
                ),
            ),
        }
    }
}

fn unix_now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

// ------------------------------------------------------------------ git

/// Runs git in one repo as the repo's owner, non-interactively.
pub struct Git {
    repo: PathBuf,
    #[cfg(unix)]
    owner: Option<(u32, u32, PathBuf)>,
}

impl Git {
    pub fn new(repo: &Path) -> Git {
        Git {
            repo: repo.to_path_buf(),
            #[cfg(unix)]
            owner: owner_of(repo),
        }
    }

    fn command(&self, args: &[&str]) -> Command {
        let mut c = Command::new("git");
        c.arg("-C").arg(&self.repo);
        // never wait on a password prompt or a stalled transfer
        c.args(["-c", "http.lowSpeedLimit=1000", "-c", "http.lowSpeedTime=60"]);
        c.args(args);
        c.env("GIT_TERMINAL_PROMPT", "0").env("GCM_INTERACTIVE", "never");
        if std::env::var_os("GIT_SSH_COMMAND").is_none() {
            c.env("GIT_SSH_COMMAND", "ssh -o BatchMode=yes -o ConnectTimeout=20");
        }
        c.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
        // the watch task has no console, so git would open a window of its own
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            c.creation_flags(windows_sys::Win32::System::Threading::CREATE_NO_WINDOW);
        }
        #[cfg(unix)]
        if let Some((uid, gid, home)) = &self.owner {
            use std::os::unix::process::CommandExt;
            c.uid(*uid).gid(*gid).env("HOME", home);
            if let Some(name) = crate::util::unix::passwd_name(*uid) {
                c.env("USER", &name).env("LOGNAME", &name);
            }
            // the owner's session bus, for credential helpers like libsecret
            let run = PathBuf::from(format!("/run/user/{uid}"));
            if run.join("bus").exists() {
                c.env("XDG_RUNTIME_DIR", &run)
                    .env("DBUS_SESSION_BUS_ADDRESS", format!("unix:path={}", run.join("bus").display()));
            }
        }
        c
    }

    /// stdout on success, else stderr (trimmed) as the error.
    pub fn run(&self, args: &[&str]) -> Result<String, String> {
        let mut child = self.command(args).spawn().map_err(|e| format!("cannot run git: {e}"))?;
        let mut out = child.stdout.take().ok_or("no stdout")?;
        let mut err = child.stderr.take().ok_or("no stderr")?;
        let t_out = std::thread::spawn(move || {
            let mut s = Vec::new();
            let _ = out.read_to_end(&mut s);
            s
        });
        let t_err = std::thread::spawn(move || {
            let mut s = Vec::new();
            let _ = err.read_to_end(&mut s);
            s
        });
        let end = Instant::now() + GIT_TIMEOUT;
        let status = loop {
            match child.try_wait() {
                Ok(Some(s)) => break s,
                Ok(None) if Instant::now() < end => std::thread::sleep(Duration::from_millis(20)),
                Ok(None) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(format!("git {} timed out", args.first().unwrap_or(&"")));
                }
                Err(e) => return Err(e.to_string()),
            }
        };
        let stdout = String::from_utf8_lossy(&t_out.join().unwrap_or_default()).into_owned();
        let stderr = String::from_utf8_lossy(&t_err.join().unwrap_or_default()).trim().to_string();
        if status.success() {
            Ok(stdout)
        } else {
            let last = stderr.lines().rfind(|l| !l.trim().is_empty()).unwrap_or("").trim();
            Err(if last.is_empty() { format!("git {} failed", args.join(" ")) } else { last.to_string() })
        }
    }

    fn ok(&self, args: &[&str]) -> bool {
        self.run(args).is_ok()
    }

    fn rev(&self, r: &str) -> Option<String> {
        self.run(&["rev-parse", "-q", "--verify", &format!("{r}^{{commit}}")])
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
    }
}

/// When running as root, the (uid, gid, home) to run git as: whoever owns the
/// repo's .git, so their credentials are used and nothing in the repo ends up
/// owned by root.
#[cfg(unix)]
fn owner_of(repo: &Path) -> Option<(u32, u32, PathBuf)> {
    use std::os::unix::fs::MetadataExt;
    if unsafe { libc::geteuid() } != 0 {
        return None;
    }
    let md = fs::metadata(repo.join(".git")).ok()?;
    if md.uid() == 0 {
        return None;
    }
    let home = crate::util::unix::passwd_home(md.uid())?;
    Some((md.uid(), md.gid(), home))
}

// ------------------------------------------------------------------ discovery

/// Git work trees under `roots`, not descending into a repo or an excluded or
/// hidden directory.
pub fn find_repos(roots: &[PathBuf], exclude: &[String], max_depth: usize) -> Vec<PathBuf> {
    let mut out = vec![];
    for root in roots {
        let mut stack = vec![(root.clone(), 0usize)];
        while let Some((dir, depth)) = stack.pop() {
            if dir.join(".git").exists() {
                out.push(dir);
                continue;
            }
            if depth >= max_depth {
                continue;
            }
            let Ok(rd) = fs::read_dir(&dir) else { continue };
            let mut kids: Vec<PathBuf> = rd
                .flatten()
                .filter(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false))
                .filter(|e| {
                    let n = e.file_name().to_string_lossy().into_owned();
                    !n.starts_with('.') && !exclude.contains(&n)
                })
                .map(|e| e.path())
                .collect();
            kids.sort();
            stack.extend(kids.into_iter().rev().map(|p| (p, depth + 1)));
        }
    }
    out.sort();
    out.dedup();
    out
}

// ------------------------------------------------------------------ the check

/// The branches to watch on one remote and their tips: the remote's default
/// branch, `main` and `master`, the ones that exist.
fn protected_tips(git: &Git, remote: &str) -> Result<BTreeMap<String, String>, String> {
    let raw = git.run(&["ls-remote", "--symref", remote, "HEAD", "refs/heads/main", "refs/heads/master"])?;
    let mut default = None;
    let mut head_sha = None;
    let mut tips = BTreeMap::new();
    for line in raw.lines() {
        let Some((a, b)) = line.split_once('\t') else { continue };
        if let Some(target) = a.strip_prefix("ref: ") {
            if b == "HEAD" {
                default = target.strip_prefix("refs/heads/").map(str::to_string);
            }
        } else if b == "HEAD" {
            head_sha = Some(a.to_string());
        } else if let Some(name) = b.strip_prefix("refs/heads/") {
            tips.insert(name.to_string(), a.to_string());
        }
    }
    if let (Some(d), Some(sha)) = (default, head_sha) {
        tips.entry(d).or_insert(sha);
    }
    Ok(tips)
}

/// Persistent per-branch state: when each was last checked cleanly.
pub struct State {
    path: PathBuf,
    data: Map<String, Value>,
}

impl State {
    pub fn load(home: &Path) -> State {
        let path = home.join("github-watch.json");
        let data = fs::read_to_string(&path)
            .ok()
            .and_then(|s| serde_json::from_str::<Value>(&s).ok())
            .and_then(|v| match v {
                Value::Object(m) => Some(m),
                _ => None,
            })
            .unwrap_or_default();
        State { path, data }
    }

    fn key(repo: &Path, remote: &str, branch: &str) -> String {
        format!("{}\t{remote}\t{branch}", repo.display())
    }

    fn checked(&self, k: &str) -> Option<u64> {
        self.data.get(k)?.get("checked")?.as_u64()
    }

    fn set_checked(&mut self, k: &str, t: u64) {
        self.data.insert(k.to_string(), json!({ "checked": t }));
    }

    /// The rewritten tip a failed restore was already reported for.
    fn failed(&self, k: &str) -> Option<&str> {
        self.data.get(k)?.get("failed")?.as_str()
    }

    fn set_failed(&mut self, k: &str, bad: &str) {
        if let Some(Value::Object(m)) = self.data.get_mut(k) {
            m.insert("failed".into(), json!(bad));
        } else {
            self.data.insert(k.to_string(), json!({ "failed": bad }));
        }
    }

    pub fn save(&self) {
        if let Some(p) = self.path.parent() {
            let _ = fs::create_dir_all(p);
        }
        let tmp = self.path.with_extension("json.tmp");
        if fs::write(&tmp, serde_json::to_string_pretty(&Value::Object(self.data.clone())).unwrap_or_default()).is_ok() {
            let _ = fs::rename(&tmp, &self.path);
        }
    }
}

/// Checks every watched branch of one repo; returns the rewrites found.
/// `log` gets one line per problem worth a log line.
pub fn check_repo(repo: &Path, state: &mut State, now: u64, log: &dyn Fn(&str)) -> Vec<Rewrite> {
    let git = Git::new(repo);
    let mut found = vec![];
    let remotes = match git.run(&["remote"]) {
        Ok(r) => r.lines().map(str::trim).filter(|l| !l.is_empty()).map(str::to_string).collect::<Vec<_>>(),
        Err(e) => {
            log(&format!("github watch: {}: {e}", repo.display()));
            return found;
        }
    };
    for remote in remotes {
        let tips = match protected_tips(&git, &remote) {
            Ok(t) => t,
            Err(e) => {
                log(&format!("github watch: {} ({remote}): {e}", repo.display()));
                continue;
            }
        };
        for (branch, tip) in tips {
            if let Some(r) = check_branch(&git, repo, &remote, &branch, &tip, state, now, log) {
                found.push(r);
            }
        }
    }
    found
}

#[allow(clippy::too_many_arguments)]
fn check_branch(
    git: &Git,
    repo: &Path,
    remote: &str,
    branch: &str,
    tip: &str,
    state: &mut State,
    now: u64,
    log: &dyn Fn(&str),
) -> Option<Rewrite> {
    let key = State::key(repo, remote, branch);
    let good_ref = format!("refs/guard/good/{remote}/{branch}");
    let seen_ref = format!("refs/guard/seen/{remote}/{branch}");
    let fetch = |dst: &str| -> Result<String, String> {
        git.run(&["fetch", "--no-tags", "--no-write-fetch-head", "-q", remote, &format!("+refs/heads/{branch}:{dst}")])?;
        git.rev(dst).ok_or_else(|| format!("{dst} missing after fetch"))
    };
    let Some(good) = git.rev(&good_ref) else {
        // first sight: remember it (fetching keeps its commits on disk)
        match fetch(&good_ref) {
            Ok(_) => state.set_checked(&key, now),
            Err(e) => log(&format!("github watch: {} ({remote}/{branch}): {e}", repo.display())),
        }
        return None;
    };
    if tip == good {
        state.set_checked(&key, now);
        return None;
    }
    let new = match fetch(&seen_ref) {
        Ok(n) => n,
        Err(e) => {
            log(&format!("github watch: {} ({remote}/{branch}): {e}", repo.display()));
            return None;
        }
    };
    if new == good || git.ok(&["merge-base", "--is-ancestor", &good, &new]) {
        // a normal push: fast-forward what we trust
        let _ = git.run(&["update-ref", &good_ref, &new]);
        state.set_checked(&key, now);
        return None;
    }
    // rewritten. A restore that already failed for this exact tip is retried
    // quietly; it is reported again only when it works.
    let retry = state.failed(&key) == Some(new.as_str());
    let evidence = if retry {
        format!("refs/guard/rewritten/{remote}/{branch}/*")
    } else {
        // keep the evidence before anything else
        let e = format!("refs/guard/rewritten/{remote}/{branch}/{now}");
        let _ = git.run(&["update-ref", &e, &new]);
        e
    };
    let fresh = state.checked(&key).is_some_and(|t| now.saturating_sub(t) <= RESTORE_WINDOW_SEC);
    let outcome = if !fresh {
        // too long since we last saw it: don't roll back work we never saw.
        // Keep the old tip, then trust the new history from here on.
        let _ = git.run(&["update-ref", &format!("refs/guard/good-before/{remote}/{branch}"), &good]);
        let _ = git.run(&["update-ref", &good_ref, &new]);
        state.set_checked(&key, now);
        Outcome::TooOld
    } else {
        let lease = format!("--force-with-lease=refs/heads/{branch}:{new}");
        match git.run(&["push", "--no-verify", "--porcelain", &lease, remote, &format!("{good}:refs/heads/{branch}")]) {
            Ok(_) => {
                state.set_checked(&key, now);
                Outcome::Restored
            }
            Err(e) => {
                state.set_failed(&key, &new);
                if retry {
                    return None;
                }
                Outcome::RestoreFailed(e)
            }
        }
    };
    Some(Rewrite {
        repo: repo.display().to_string(),
        remote: remote.to_string(),
        branch: branch.to_string(),
        good,
        bad: new,
        evidence,
        outcome,
    })
}

/// One pass over every repo under `roots`.
pub fn check_all(
    roots: &[PathBuf],
    exclude: &[String],
    max_depth: usize,
    home: &Path,
    log: &dyn Fn(&str),
) -> Vec<Rewrite> {
    let mut state = State::load(home);
    let now = unix_now();
    let mut found = vec![];
    for repo in find_repos(roots, exclude, max_depth) {
        found.extend(check_repo(&repo, &mut state, now, log));
    }
    state.save();
    found
}

/// Records a rewrite: a log line, an alerts.jsonl entry, a popup.
pub fn report(r: &Rewrite, home: &Path, log: &dyn Fn(&str), notify: bool) {
    log(&format!("ALERT [force-push] {}", r.summary()));
    let rec = json!({
        "ts": crate::util::now_iso(), "kind": "force-push", "path": r.repo,
        "findings": [r.to_json()],
    });
    if let Ok(mut f) = fs::OpenOptions::new().create(true).append(true).open(home.join("alerts.jsonl")) {
        use std::io::Write;
        let _ = f.write_all(format!("{}\n", crate::pyjson::dumps(&rec, None, false)).as_bytes());
    }
    if notify {
        let (title, msg) = r.popup();
        crate::notify::notify(title, &msg);
    }
}

// ------------------------------------------------------------------ CLI

/// Roots, excluded names and depth from the watcher config in the guard home.
fn configured(home: &Path) -> (Vec<PathBuf>, Vec<String>, usize) {
    let cfg = crate::watch::config(home);
    let list = |k: &str| -> Vec<String> {
        cfg.get(k)
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(Value::as_str).map(str::to_string).collect())
            .unwrap_or_default()
    };
    let roots = crate::watch::expand_roots(&list("watch_roots"));
    let depth = cfg.get("max_depth").and_then(Value::as_u64).map_or(DEFAULT_MAX_DEPTH, |d| d as usize);
    (roots, list("exclude_dir_names"), depth)
}

fn pass(roots: &[PathBuf], exclude: &[String], depth: usize, home: &Path, notify: bool) -> Vec<Rewrite> {
    // stdout may be gone (the Windows task frees its console): write the log
    // file, and stdout only when it is there
    let path = home.join("github-watch.log");
    let log = move |m: &str| {
        use std::io::Write;
        let line = format!("{}  {m}\n", crate::util::now_iso());
        let _ = std::io::stdout().write_all(line.as_bytes());
        if let Ok(mut f) = fs::OpenOptions::new().create(true).append(true).open(&path) {
            let _ = f.write_all(line.as_bytes());
        }
    };
    let found = check_all(roots, exclude, depth, home, &log);
    for r in &found {
        report(r, home, &log, notify);
    }
    found
}

pub fn main(rest: &[String]) -> u8 {
    let home = crate::util::guard_home();
    let _ = fs::create_dir_all(&home);
    let (roots, exclude, depth) = configured(&home);
    match rest.first().map(String::as_str) {
        Some("check") => {
            let roots: Vec<PathBuf> = if rest.len() > 1 { rest[1..].iter().map(PathBuf::from).collect() } else { roots };
            let found = pass(&roots, &exclude, depth, &home, false);
            if found.is_empty() {
                println!("github watch: no force pushes on the watched branches");
            }
            u8::from(found.iter().any(|r| r.outcome != Outcome::Restored))
        }
        Some("watch") => {
            let interval = match rest.get(1).map(String::as_str) {
                None => DEFAULT_INTERVAL_SEC,
                Some("--interval") => match rest.get(2).and_then(|s| s.parse::<u64>().ok()) {
                    Some(n) if n > 0 => n,
                    _ => {
                        eprint!("{USAGE}");
                        return 2;
                    }
                },
                Some(_) => {
                    eprint!("{USAGE}");
                    return 2;
                }
            };
            hide_console();
            loop {
                pass(&roots, &exclude, depth, &home, true);
                std::thread::sleep(Duration::from_secs(interval));
            }
        }
        _ => {
            eprint!("{USAGE}");
            2
        }
    }
}

/// The per-user Windows task starts a console; drop it so no window stays open.
#[cfg(windows)]
fn hide_console() {
    // SAFETY: detaching from the console has no preconditions.
    unsafe {
        windows_sys::Win32::System::Console::FreeConsole();
    }
}
#[cfg(not(windows))]
fn hide_console() {}
