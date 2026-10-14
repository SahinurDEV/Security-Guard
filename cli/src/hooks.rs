//! `guard hooks install|uninstall|status`: Guard's global git hooks.
//!
//! The hooks live in <guard home>/githooks and git's global core.hooksPath
//! points there, so they run in every repo of the user who installed them:
//! pre-push runs `guard scan-push`, post-checkout/merge/rewrite run
//! `guard scan-checkout`. Each one then runs the hook it hides (the repo's own
//! .git/hooks/<name>, and a global hooks path set before Guard's, which is
//! kept in guard.previousHooksPath and put back on uninstall).
//!
//! The installers run this as the developer, not root: git config and the
//! hooks belong to the user whose pushes they guard.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::util;

const PRE_PUSH: &str = include_str!("../../hooks/guard-pre-push.sh");
const SCAN: &str = include_str!("../../hooks/guard-scan-hook.sh");
pub const HOOKS: [(&str, &str); 4] = [
    ("pre-push", PRE_PUSH),
    ("post-checkout", SCAN),
    ("post-merge", SCAN),
    ("post-rewrite", SCAN),
];
const PREVIOUS: &str = "guard.previousHooksPath";
const USAGE: &str = "usage: guard hooks install|uninstall|status\n";

pub fn dir() -> PathBuf {
    util::guard_home().join("githooks")
}

fn git_global(args: &[&str]) -> Option<String> {
    let out = Command::new("git")
        .args(["config", "--global"])
        .args(args)
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    (out.status.success() && !s.is_empty()).then_some(s)
}

fn set_global(key: &str, value: Option<&str>) -> Result<(), String> {
    let mut c = Command::new("git");
    c.args(["config", "--global"]);
    match value {
        Some(v) => c.args([key, v]),
        None => c.args(["--unset", key]),
    };
    let st = c.stdin(Stdio::null()).status().map_err(|e| format!("cannot run git: {e}"))?;
    // --unset of a missing key exits 5: nothing to undo
    if st.success() || (value.is_none() && st.code() == Some(5)) {
        Ok(())
    } else {
        Err(format!("git config --global {key} failed"))
    }
}

/// The path as git and the hooks print it: forward slashes, so Git for
/// Windows' sh can run it too.
fn slashed(p: &Path) -> String {
    p.display().to_string().replace('\\', "/")
}

/// Does a configured core.hooksPath name Guard's hooks dir?
fn is_ours(configured: &str, ours: &Path) -> bool {
    let canon = |p: &Path| fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf());
    slashed(&canon(Path::new(configured))).trim_end_matches('/') == slashed(&canon(ours)).trim_end_matches('/')
}

/// The hook text with the guard binary's path filled in.
pub fn render(text: &str, guard: &Path) -> String {
    // a single-quoted sh string: close, escaped quote, reopen
    // sh reads a CR as part of the line; a CRLF checkout must not reach it
    text.replace("\r\n", "\n").replace("@GUARD@", &slashed(guard).replace('\'', r"'\''"))
}

fn install() -> Result<u8, String> {
    if Command::new("git").arg("--version").stdout(Stdio::null()).stderr(Stdio::null()).status().is_err() {
        println!("guard: git is not installed; git hooks skipped");
        return Ok(0);
    }
    let dir = dir();
    fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let guard = std::env::current_exe().map_err(|e| format!("cannot find the guard binary: {e}"))?;
    for (name, text) in HOOKS {
        let path = dir.join(name);
        fs::write(&path, render(text, &guard)).map_err(|e| format!("{}: {e}", path.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).map_err(|e| format!("{}: {e}", path.display()))?;
        }
    }
    // keep a hooks path someone set before Guard; its hooks still run
    if let Some(current) = git_global(&["--path", "--get", "core.hooksPath"]) {
        if !is_ours(&current, &dir) {
            set_global(PREVIOUS, Some(&current))?;
            println!("guard: your hooks in {current} keep running after Guard's");
        }
    }
    set_global("core.hooksPath", Some(&slashed(&dir)))?;
    println!(
        "guard: global git hooks -> {} ({})",
        slashed(&dir),
        HOOKS.map(|(n, _)| n).join(", ")
    );
    Ok(0)
}

fn uninstall() -> Result<u8, String> {
    let dir = dir();
    let current = git_global(&["--path", "--get", "core.hooksPath"]);
    if current.as_deref().is_some_and(|c| is_ours(c, &dir)) {
        match git_global(&["--path", "--get", PREVIOUS]) {
            Some(prev) => set_global("core.hooksPath", Some(&prev))?,
            None => set_global("core.hooksPath", None)?,
        }
    }
    set_global(PREVIOUS, None)?;
    for (name, _) in HOOKS {
        let _ = fs::remove_file(dir.join(name));
    }
    let _ = fs::remove_dir(&dir);
    println!("guard: global git hooks removed");
    Ok(0)
}

fn status() -> u8 {
    let dir = dir();
    let current = git_global(&["--path", "--get", "core.hooksPath"]);
    let ours = current.as_deref().is_some_and(|c| is_ours(c, &dir));
    let present = HOOKS.iter().all(|(n, _)| dir.join(n).is_file());
    if ours && present {
        println!("guard: git hooks installed in {} ({})", slashed(&dir), HOOKS.map(|(n, _)| n).join(", "));
    } else {
        println!("guard: git hooks NOT installed (run: guard hooks install)");
    }
    // a repo's own core.hooksPath (husky and the like) wins over the global one
    let local = Command::new("git")
        .args(["config", "--local", "--get", "core.hooksPath"])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string());
    if let Some(local) = local.filter(|l| !l.is_empty()) {
        println!("guard: this repo sets its own core.hooksPath ({local}), so Guard's hooks do not run here");
        println!("guard: the watcher still scans it; to gate its pushes add `guard scan-push \"$@\"` to {local}/pre-push");
    }
    if ours && present {
        0
    } else {
        1
    }
}

pub fn main(rest: &[String]) -> u8 {
    let res = match rest.first().map(String::as_str) {
        Some("install") if rest.len() == 1 => install(),
        Some("uninstall") if rest.len() == 1 => uninstall(),
        Some("status") if rest.len() == 1 => return status(),
        _ => {
            eprint!("{USAGE}");
            return 2;
        }
    };
    match res {
        Ok(rc) => rc,
        Err(e) => {
            eprintln!("guard hooks: {e}");
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_quotes_the_path() {
        let t = render("g='@GUARD@'", Path::new("/opt/it's/guard"));
        assert_eq!(t, r"g='/opt/it'\''s/guard'");
        assert_eq!(render("g='@GUARD@'", Path::new(r"C:\Program Files\Guard\guard.exe")), "g='C:/Program Files/Guard/guard.exe'");
    }

    #[test]
    fn hooks_are_lf_only() {
        for (name, text) in HOOKS {
            let text = render(text, Path::new("/g"));
            assert!(!text.contains('\r'), "{name} has CRLF line endings");
            assert!(text.starts_with("#!/bin/sh\n"), "{name}");
            assert!(text.contains("guard='/g'"), "{name}");
        }
    }
}
