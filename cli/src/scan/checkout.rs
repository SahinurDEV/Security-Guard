//! `guard scan-checkout <hook> [hook args]`: what the post-checkout,
//! post-merge and post-rewrite hooks run.
//!
//! * A clone (post-checkout from the null commit), a rewrite, or a change
//!   touching more than INCREMENTAL_MAX files: scan the whole working tree.
//! * A branch switch / pull: scan only the files that changed (`git diff
//!   <old> <new>`), copied into a scratch dir so the scan sees exactly them.
//!   That keeps a `git checkout` in a big repo fast.
//!
//! On a critical hit the default is to QUARANTINE: injected code is cut out
//! of real files (backed up first), whole-file droppers go to the quarantine
//! vault, VS Code auto-run settings are neutralised, and every change can be
//! undone with `guard restore <path>`. Warn-only instead:
//! `git config --global guard.onClone warn` (or GUARD_ON_CLONE=warn).
//!
//! Always exits 0: git ignores post-* hook status anyway, and a scan problem
//! must never break a checkout. Problems are printed instead.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde_json::Value;

use super::push::safe_rel;
use super::remediate::Remediator;
use super::scanner::Scanner;
use super::sigs;

/// More changed files than this: just scan the tree.
const INCREMENTAL_MAX: usize = 2000;

fn git(repo: &Path, args: &[&str]) -> Option<String> {
    let o = Command::new("git").arg("-C").arg(repo).args(args).stdin(Stdio::null()).stderr(Stdio::null()).output().ok()?;
    o.status.success().then(|| String::from_utf8_lossy(&o.stdout).into_owned())
}

fn is_null(sha: &str) -> bool {
    sha.is_empty() || sha.bytes().all(|b| b == b'0')
}

/// The files to scan: None = the whole tree.
pub fn changed(repo: &Path, hook: &str, args: &[String]) -> Option<Vec<String>> {
    let (old, new) = match hook {
        // <prev HEAD> <new HEAD> <1 = branch checkout>; prev is null on clone
        "post-checkout" => (args.first()?.clone(), args.get(1)?.clone()),
        // pull/merge: what ORIG_HEAD was before it
        "post-merge" => (git(repo, &["rev-parse", "-q", "--verify", "ORIG_HEAD"])?.trim().to_string(), "HEAD".into()),
        _ => return None,
    };
    if is_null(&old) {
        return None;
    }
    let out = git(repo, &["diff", "--name-only", "-z", "--no-renames", "--diff-filter=ACMRT", &old, &new])?;
    let files: Vec<String> = out.split('\0').filter(|s| !s.is_empty()).map(str::to_string).collect();
    (files.len() <= INCREMENTAL_MAX).then_some(files)
}

fn mode_warn() -> bool {
    let env = std::env::var("GUARD_ON_CLONE").unwrap_or_default();
    let v = if env.is_empty() {
        Command::new("git")
            .args(["config", "--get", "guard.onClone"])
            .stderr(Stdio::null())
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .unwrap_or_default()
    } else {
        env
    };
    v.eq_ignore_ascii_case("warn")
}

fn red(s: &str) {
    eprintln!("\x1b[31m[GUARD] {s}\x1b[0m");
}

/// Repo-relative paths of critical findings.
fn critical_paths(results: &Value) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    if let Value::Object(m) = results {
        for v in m.values() {
            for f in v.as_array().into_iter().flatten() {
                if f.get("severity").and_then(Value::as_str) != Some("critical") {
                    continue;
                }
                let p = f.get("path").or_else(|| f.get("where")).and_then(Value::as_str).unwrap_or("");
                if !p.is_empty() {
                    out.insert(p.replace('\\', "/"));
                }
            }
        }
    }
    out
}

fn scratch() -> Option<PathBuf> {
    let n = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).ok()?.as_nanos();
    let d = std::env::temp_dir().join(format!("guard-co-{}-{n}", std::process::id()));
    fs::create_dir_all(&d).ok()?;
    Some(d)
}

fn run(repo: &Path, hook: &str, args: &[String]) -> Result<(), String> {
    let sig = sigs::load(None)?;
    let mut sc = Scanner::new(&sig, true)?;
    let files = changed(repo, hook, args);
    let repo_s = repo.to_string_lossy().into_owned();
    let (results, hits): (Value, Vec<String>) = match &files {
        Some(list) if list.is_empty() => return Ok(()),
        Some(list) => {
            let dir = scratch().ok_or("cannot create a scratch dir")?;
            for f in list {
                let Some(rel) = safe_rel(f) else { continue };
                let src = repo.join(&rel);
                if !src.is_file() {
                    continue;
                }
                let dst = dir.join(&rel);
                if let Some(p) = dst.parent() {
                    let _ = fs::create_dir_all(p);
                }
                let _ = fs::copy(&src, &dst);
            }
            let r = sc.scan_tree(&dir.to_string_lossy());
            let _ = fs::remove_dir_all(&dir);
            let hits = critical_paths(&r)
                .into_iter()
                .map(|p| p.trim_start_matches(&*dir.to_string_lossy().replace('\\', "/")).trim_start_matches('/').to_string())
                .collect();
            (r, hits)
        }
        None => {
            let r = sc.scan_tree(&repo_s);
            let hits = critical_paths(&r)
                .into_iter()
                .map(|p| p.trim_start_matches(&*repo_s.replace('\\', "/")).trim_start_matches('/').to_string())
                .collect();
            (r, hits)
        }
    };
    if results["infected"] != Value::Bool(true) {
        return Ok(());
    }
    let scope = if files.is_some() { "changed files" } else { "working tree" };
    red(&format!("MALWARE detected in {repo_s} ({hook}, {scope}):"));
    for h in &hits {
        red(&format!("  {h}"));
    }
    let vscode = results["vscode"].as_array().is_some_and(|a| !a.is_empty());
    if mode_warn() {
        if vscode {
            red("DO NOT OPEN THIS FOLDER IN VS CODE: it has an auto-run task.");
        }
        red("Warn-only mode (guard.onClone=warn): nothing was changed.");
        red(&format!("Quarantine it now with: guard clean \"{repo_s}\""));
        red("Do NOT open this folder in an editor or run npm/node in it until it is clean.");
        return Ok(());
    }
    let rem = Remediator::new(&crate::util::guard_home());
    let summary = if files.is_none() {
        rem.clean_repo(&repo_s)?
    } else {
        let mut acts = serde_json::Map::new();
        for h in &hits {
            let p = repo.join(h);
            if p.is_file() {
                if let Ok(v) = rem.clean_file(&p.to_string_lossy()) {
                    let a = v.get("action").and_then(Value::as_str).unwrap_or("noop").to_string();
                    acts.entry(a).or_insert_with(|| Value::Array(vec![])).as_array_mut().unwrap().push(Value::String(h.clone()));
                }
            }
        }
        Value::Object(acts)
    };
    let mut any = false;
    for (k, label) in [
        ("quarantined", "moved to quarantine"),
        ("quarantine", "moved to quarantine"),
        ("neutralized", "injected code removed (file kept)"),
        ("neutralize", "injected code removed (file kept)"),
        ("config_cleaned", "VS Code auto-run removed"),
        ("clean-settings", "VS Code auto-run removed"),
        ("clean-tasks", "VS Code auto-run removed"),
    ] {
        for p in summary.get(k).and_then(Value::as_array).into_iter().flatten() {
            any = true;
            red(&format!("  {label}: {}", p.as_str().unwrap_or("")));
        }
    }
    if any {
        red("Every change is backed up. Undo one with: guard restore <path>");
        red("Your working tree now differs from the commit: review with `git status` / `git diff`.");
    } else {
        red(&format!("Could not clean automatically; run: guard clean \"{repo_s}\""));
    }
    red("Warn-only instead of quarantine: git config --global guard.onClone warn");
    Ok(())
}

pub fn main(rest: &[String]) -> u8 {
    let Some((hook, args)) = rest.split_first() else {
        eprintln!("usage: guard scan-checkout <post-checkout|post-merge|post-rewrite> [hook args]");
        return 2;
    };
    let Some(top) = git(Path::new("."), &["rev-parse", "--show-toplevel"]) else {
        return 0; // bare repo or not a work tree: nothing on disk to scan
    };
    let repo = PathBuf::from(top.trim());
    if let Err(e) = run(&repo, hook, args) {
        red(&format!("scan after {hook} failed: {e}. Run: guard scan \"{}\"", repo.display()));
    }
    0
}
