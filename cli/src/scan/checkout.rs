//! `guard scan-checkout <hook> [hook args]`: what the post-checkout,
//! post-merge and post-rewrite hooks run.
//!
//! * A clone (post-checkout from the null commit), or a change touching more
//!   than INCREMENTAL_MAX files: scan the whole working tree.
//! * A branch switch / pull / amend / rebase: scan only the files that
//!   changed (`git diff <old> <new>`; post-rewrite reads git's `<old> <new>`
//!   pairs from stdin), copied into a scratch dir so the scan sees exactly
//!   them. Nothing changed: return before any rules are loaded.
//!
//! Every finding is QUARANTINED, no opt-out: injected code is cut out of real
//! files (backed up first), whole-file droppers go to the quarantine vault,
//! VS Code auto-run settings are neutralised, and every change can be undone
//! with `guard restore <path>`. Guard's own repository is exempt (trust.rs).
//!
//! Always exits 0: git ignores post-* hook status anyway, and a scan problem
//! must never break a checkout. Problems are printed instead.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Read;
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

fn diff(repo: &Path, old: &str, new: &str, out: &mut BTreeSet<String>) -> Option<()> {
    let raw = git(repo, &["diff", "--name-only", "-z", "--no-renames", "--diff-filter=ACMRT", old, new])?;
    out.extend(raw.split('\0').filter(|s| !s.is_empty()).map(str::to_string));
    Some(())
}

/// The files to scan: None = the whole tree.
pub fn changed(repo: &Path, hook: &str, args: &[String], stdin: &str) -> Option<Vec<String>> {
    let mut files = BTreeSet::new();
    match hook {
        // <prev HEAD> <new HEAD> <1 = branch checkout>; prev is null on clone
        "post-checkout" => {
            let (old, new) = (args.first()?, args.get(1)?);
            if is_null(old) {
                return None;
            }
            diff(repo, old, new, &mut files)?;
        }
        // pull/merge: what ORIG_HEAD was before it
        "post-merge" => {
            let old = git(repo, &["rev-parse", "-q", "--verify", "ORIG_HEAD"])?;
            diff(repo, old.trim(), "HEAD", &mut files)?;
        }
        // amend/rebase: "<old> <new> [extra]" per rewritten commit
        "post-rewrite" => {
            let mut any = false;
            for l in stdin.lines() {
                let f: Vec<&str> = l.split_whitespace().collect();
                if f.len() >= 2 {
                    diff(repo, f[0], f[1], &mut files)?;
                    any = true;
                }
            }
            if !any {
                return None;
            }
        }
        _ => return None,
    }
    (files.len() <= INCREMENTAL_MAX).then(|| files.into_iter().collect())
}

fn red(s: &str) {
    eprintln!("\x1b[31m[GUARD] {s}\x1b[0m");
}

/// Repo-relative path -> is it a whole-file threat (fake binary / AV hit),
/// for every finding of any severity except informational ones.
fn hit_paths(results: &Value, root: &str) -> BTreeMap<String, bool> {
    let root = root.replace('\\', "/");
    let mut out: BTreeMap<String, bool> = BTreeMap::new();
    if let Value::Object(m) = results {
        for (bucket, v) in m {
            for f in v.as_array().into_iter().flatten() {
                let sev = f.get("severity").and_then(Value::as_str).unwrap_or("");
                let id = f.get("sig_id").and_then(Value::as_str).unwrap_or("");
                if sev.is_empty() || sev == "info" || sev == "ok" || id.starts_with("scan.") {
                    continue;
                }
                let p = f.get("path").or_else(|| f.get("where")).and_then(Value::as_str).unwrap_or("");
                let p = p.replace('\\', "/");
                let rel = p.strip_prefix(&root).unwrap_or(&p).trim_start_matches('/').to_string();
                if rel.is_empty() {
                    continue;
                }
                let whole = bucket == "magic" || bucket == "av";
                *out.entry(rel).or_insert(false) |= whole;
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

fn run(repo: &Path, hook: &str, args: &[String], stdin: &str) -> Result<(), String> {
    let files = changed(repo, hook, args, stdin);
    // nothing changed: done before any rules are compiled
    if files.as_ref().is_some_and(Vec::is_empty) {
        return Ok(());
    }
    let sig = sigs::load(None)?;
    let mut sc = Scanner::new(&sig, true)?;
    let repo_s = repo.to_string_lossy().into_owned();
    let hits = match &files {
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
            let d = dir.to_string_lossy().into_owned();
            let r = sc.scan_tree(&d);
            let _ = fs::remove_dir_all(&dir);
            hit_paths(&r, &d)
        }
        None => hit_paths(&sc.scan_tree(&repo_s), &repo_s),
    };
    if hits.is_empty() {
        return Ok(());
    }
    let scope = if files.is_some() { "changed files" } else { "working tree" };
    red(&format!("MALWARE detected in {repo_s} ({hook}, {scope}) - quarantining:"));
    let rem = Remediator::new(&crate::util::guard_home());
    let mut failed = vec![];
    for (rel, whole) in &hits {
        let p = repo.join(rel);
        if !p.exists() {
            continue;
        }
        match rem.remediate_file(&p.to_string_lossy(), *whole) {
            Ok(v) => {
                let label = match v.get("action").and_then(Value::as_str).unwrap_or("") {
                    "quarantine" => "moved to quarantine",
                    "neutralize" => "injected code removed (file kept)",
                    "clean-settings" | "clean-tasks" => "VS Code auto-run removed",
                    _ => "checked, nothing to cut",
                };
                red(&format!("  {label}: {rel}"));
            }
            Err(e) => failed.push(format!("{rel} ({e})")),
        }
    }
    for f in &failed {
        red(&format!("  COULD NOT CLEAN: {f}"));
    }
    red("Every change is backed up. Undo one with: guard restore <path>");
    red("Your working tree now differs from the commit: review with `git status` / `git diff`.");
    Ok(())
}

pub fn main(rest: &[String]) -> u8 {
    let Some((hook, args)) = rest.split_first() else {
        eprintln!("usage: guard scan-checkout <post-checkout|post-merge|post-rewrite> [hook args]");
        return 2;
    };
    let mut stdin = String::new();
    if hook == "post-rewrite" {
        let _ = std::io::stdin().read_to_string(&mut stdin);
    }
    let Some(top) = git(Path::new("."), &["rev-parse", "--show-toplevel"]) else {
        return 0; // bare repo or not a work tree: nothing on disk to scan
    };
    let repo = PathBuf::from(top.trim());
    if let Some(why) = super::trust::trusted(&repo) {
        eprintln!("[GUARD] scan skipped: {why}");
        return 0;
    }
    if let Err(e) = run(&repo, hook, args, &stdin) {
        red(&format!("scan after {hook} failed: {e}. Run: guard scan \"{}\"", repo.display()));
    }
    0
}
