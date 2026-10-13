//! `guard hooks install | uninstall | status`: the global git hooks.
//!
//! Writes the hook scripts (embedded in the binary, so every installer -
//! install.sh, guard.sh, guard.ps1 - ships the same ones) to
//! $GUARD_HOME/githooks and points the user's global `core.hooksPath` at it:
//! post-checkout / post-merge / post-rewrite scan every clone and pull,
//! pre-push blocks infected pushes. A global hooksPath set before Guard
//! (husky-style shared hooks, company hooks) is saved to
//! $GUARD_HOME/githooks.prev; the scripts chain to it and to each repo's own
//! .git/hooks, and `uninstall` puts it back.
//!
//! Run as root under sudo, it re-runs itself as $SUDO_USER: hooks belong to
//! the developer's git config, not root's.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::util;

const SCAN_HOOK: &str = include_str!("../../hooks/guard-scan-hook.sh");
const PUSH_HOOK: &str = include_str!("../../hooks/guard-pre-push.sh");
pub const HOOKS: &[(&str, &str)] = &[
    ("post-checkout", SCAN_HOOK),
    ("post-merge", SCAN_HOOK),
    ("post-rewrite", SCAN_HOOK),
    ("pre-push", PUSH_HOOK),
];

const USAGE: &str = "usage: guard hooks install | uninstall | status\n";

fn hooks_dir() -> PathBuf {
    util::guard_home().join("githooks")
}
fn prev_file() -> PathBuf {
    util::guard_home().join("githooks.prev")
}

/// The form written to git config: forward slashes (Git for Windows reads
/// both, and its sh needs them).
fn config_value(p: &Path) -> String {
    p.to_string_lossy().replace('\\', "/")
}

fn git_global(args: &[&str]) -> Result<(bool, String), String> {
    let out = Command::new("git")
        .args(["config", "--global"])
        .args(args)
        .stdin(Stdio::null())
        .output()
        .map_err(|e| format!("git not found ({e}); install git, then run `guard hooks install`"))?;
    Ok((out.status.success(), String::from_utf8_lossy(&out.stdout).trim().to_string()))
}

fn current() -> Result<Option<String>, String> {
    let (ok, v) = git_global(&["--get", "core.hooksPath"])?;
    Ok((ok && !v.is_empty()).then_some(v))
}

fn same(a: &str, b: &Path) -> bool {
    let norm = |s: &str| s.replace('\\', "/").trim_end_matches('/').to_lowercase();
    if norm(a) == norm(&config_value(b)) {
        return true;
    }
    match (fs::canonicalize(a), fs::canonicalize(b)) {
        (Ok(x), Ok(y)) => x == y,
        _ => false,
    }
}

/// Under sudo, as root: run `guard hooks <sub>` as the invoking user instead.
#[cfg(unix)]
fn as_sudo_user(sub: &str) -> Option<u8> {
    let user = std::env::var("SUDO_USER").ok().filter(|u| !u.is_empty() && u != "root")?;
    if !is_root() || std::env::var_os("GUARD_HOOKS_NO_SUDO").is_some() {
        return None;
    }
    let exe = std::env::current_exe().ok()?;
    let st = Command::new("sudo")
        .args(["-u", &user, "-H", "--"])
        .arg(exe)
        .args(["hooks", sub])
        .status()
        .ok()?;
    Some(st.code().unwrap_or(1) as u8)
}
#[cfg(unix)]
fn is_root() -> bool {
    Command::new("id").arg("-u").output().map(|o| String::from_utf8_lossy(&o.stdout).trim() == "0").unwrap_or(false)
}
#[cfg(not(unix))]
fn as_sudo_user(_: &str) -> Option<u8> {
    None
}

pub fn install() -> Result<u8, String> {
    if let Some(rc) = as_sudo_user("install") {
        return Ok(rc);
    }
    let dir = hooks_dir();
    fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    for (name, body) in HOOKS {
        let p = dir.join(name);
        fs::write(&p, body.replace("\r\n", "\n")).map_err(|e| format!("{}: {e}", p.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&p, fs::Permissions::from_mode(0o755));
        }
    }
    match current()? {
        Some(prev) if !same(&prev, &dir) => {
            // keep the first one we displaced; a reinstall must not save ourselves
            fs::write(prev_file(), &prev).map_err(|e| e.to_string())?;
            println!("guard: previous core.hooksPath saved ({prev}); Guard's hooks chain to it");
        }
        _ => {}
    }
    let (ok, _) = git_global(&["core.hooksPath", &config_value(&dir)])?;
    if !ok {
        return Err("git config --global core.hooksPath failed".into());
    }
    println!(
        "guard: global git hooks -> {} ({})",
        config_value(&dir),
        HOOKS.iter().map(|h| h.0).collect::<Vec<_>>().join(", ")
    );
    Ok(0)
}

/// Quiet when Guard's hooks aren't wired in (so `guard uninstall` can always call it).
pub fn uninstall() -> Result<u8, String> {
    if let Some(rc) = as_sudo_user("uninstall") {
        return Ok(rc);
    }
    let dir = hooks_dir();
    let prev = fs::read_to_string(prev_file()).ok().map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
    if let Some(cur) = current()? {
        if same(&cur, &dir) {
            match &prev {
                Some(p) => {
                    git_global(&["core.hooksPath", p])?;
                    println!("guard: core.hooksPath restored to {p}");
                }
                None => {
                    git_global(&["--unset", "core.hooksPath"])?;
                    println!("guard: core.hooksPath unset (Guard's hooks removed)");
                }
            }
        }
    }
    let _ = fs::remove_file(prev_file());
    if dir.is_dir() {
        let _ = fs::remove_dir_all(&dir);
    }
    Ok(0)
}

pub fn status() -> Result<u8, String> {
    let dir = hooks_dir();
    let cur = current()?;
    let ours = cur.as_deref().is_some_and(|c| same(c, &dir));
    println!("global core.hooksPath: {}", cur.as_deref().unwrap_or("(unset)"));
    println!("guard hooks: {}", if ours { "INSTALLED" } else { "NOT INSTALLED (run: guard hooks install)" });
    if let Ok(p) = fs::read_to_string(prev_file()) {
        println!("chains to previous hooksPath: {}", p.trim());
    }
    // in a repo with its own LOCAL hooksPath (husky v9), git ignores the global one
    if let Ok(o) = Command::new("git").args(["config", "--local", "--get", "core.hooksPath"]).stderr(Stdio::null()).output() {
        let local = String::from_utf8_lossy(&o.stdout).trim().to_string();
        if o.status.success() && !local.is_empty() {
            println!("WARNING: this repo sets its own core.hooksPath ({local}); Guard's pre-push gate does NOT run here.");
            println!("         Add `guard scan-push \"$@\"` (reading stdin) to {local}/pre-push, or `git config --local --unset core.hooksPath`.");
        }
    }
    Ok(if ours { 0 } else { 1 })
}

pub fn main(rest: &[String]) -> u8 {
    let r = match rest.first().map(String::as_str) {
        Some("install") => install(),
        Some("uninstall") => uninstall(),
        Some("status") => status(),
        _ => {
            eprint!("{USAGE}");
            return 2;
        }
    };
    r.unwrap_or_else(|e| {
        eprintln!("guard hooks: {e}");
        1
    })
}
