//! `guard scan-checkout` (the post-checkout / post-merge hook body):
//! quarantine on clone, warn-only opt-out, incremental scans. Inert fixtures
//! only: a ".otf" whose body is a harmless line of JS.

mod common;

use std::fs;
use std::path::Path;
use std::process::Command;

use common::*;

const FAKE_FONT: &str = "module.exports = function () { return 0; };\n";

/// An empty global git config (Windows has no /dev/null for git to read).
fn empty_gitconfig() -> std::path::PathBuf {
    let p = std::env::temp_dir().join(format!("guard-it-empty-gitconfig-{}", std::process::id()));
    if !p.exists() {
        let _ = fs::write(&p, "");
    }
    p
}

fn git(dir: &Path, args: &[&str]) -> String {
    let o = Command::new("git")
        .current_dir(dir)
        .args(args)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", empty_gitconfig())
        .env("GIT_AUTHOR_NAME", "t")
        .env("GIT_AUTHOR_EMAIL", "t@example.invalid")
        .env("GIT_COMMITTER_NAME", "t")
        .env("GIT_COMMITTER_EMAIL", "t@example.invalid")
        .output()
        .unwrap();
    assert!(o.status.success(), "git {args:?}: {}", String::from_utf8_lossy(&o.stderr));
    String::from_utf8_lossy(&o.stdout).trim().to_string()
}

fn repo(t: &Tmp) -> std::path::PathBuf {
    let r = t.join("repo");
    fs::create_dir_all(&r).unwrap();
    git(&r, &["init", "-q", "-b", "main"]);
    git(&r, &["config", "core.hooksPath", "no-hooks"]);
    write(&r.join("README.md"), "hi\n");
    git(&r, &["add", "-A"]);
    git(&r, &["commit", "-qm", "init"]);
    r
}

fn add(r: &Path, file: &str, body: &str) -> String {
    write(&r.join(file), body);
    git(r, &["add", "-A"]);
    git(r, &["commit", "-qm", file]);
    git(r, &["rev-parse", "HEAD"])
}

fn hook(t: &Tmp, r: &Path, args: &[&str], warn: bool) -> Out {
    let mut a = vec!["scan-checkout"];
    a.extend_from_slice(args);
    guard(&a)
        .home(&t.join("home"))
        .cwd(r)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", empty_gitconfig())
        .env("GUARD_ON_CLONE", if warn { "warn" } else { "" })
        .run()
}

const NULL: &str = "0000000000000000000000000000000000000000";

#[test]
fn clone_quarantines_by_default() {
    let t = Tmp::new("co-clone");
    let r = repo(&t);
    let head = add(&r, "public/fonts/icons.otf", FAKE_FONT);
    let o = hook(&t, &r, &["post-checkout", NULL, &head, "1"], false);
    assert_eq!(o.code, 0, "hooks never fail git");
    assert!(o.stderr.contains("MALWARE detected"), "{}", o.stderr);
    assert!(o.stderr.contains("public/fonts/icons.otf"), "{}", o.stderr);
    assert!(o.stderr.contains("guard restore"), "{}", o.stderr);
    assert!(!r.join("public/fonts/icons.otf").exists(), "quarantined");
    // and it can be put back
    let back = guard(&["restore", &s(&r.join("public/fonts/icons.otf"))]).home(&t.join("home")).run();
    assert_eq!(back.code, 0, "{}", back.shown_all());
    assert!(r.join("public/fonts/icons.otf").exists());
}

#[test]
fn warn_only_changes_nothing() {
    let t = Tmp::new("co-warn");
    let r = repo(&t);
    let head = add(&r, "public/fonts/icons.otf", FAKE_FONT);
    let o = hook(&t, &r, &["post-checkout", NULL, &head, "1"], true);
    assert_eq!(o.code, 0);
    assert!(o.stderr.contains("Warn-only"), "{}", o.stderr);
    assert!(o.stderr.contains("guard clean"), "{}", o.stderr);
    assert!(r.join("public/fonts/icons.otf").exists());
}

#[test]
fn clean_clone_is_silent() {
    let t = Tmp::new("co-quiet");
    let r = repo(&t);
    let head = git(&r, &["rev-parse", "HEAD"]);
    let o = hook(&t, &r, &["post-checkout", NULL, &head, "1"], false);
    assert_eq!((o.code, o.stderr.as_str()), (0, ""));
}

#[test]
fn checkout_scans_only_changed_files() {
    let t = Tmp::new("co-incr");
    let r = repo(&t);
    // an infected file that is NOT part of the switch below
    let base = add(&r, "public/fonts/old.otf", FAKE_FONT);
    let new = add(&r, "public/fonts/new.otf", FAKE_FONT);
    let o = hook(&t, &r, &["post-checkout", &base, &new, "1"], true);
    assert!(o.stderr.contains("changed files"), "{}", o.stderr);
    assert!(o.stderr.contains("new.otf") && !o.stderr.contains("old.otf"), "{}", o.stderr);
    // same commit (e.g. git checkout -b): nothing changed, nothing to say
    let o = hook(&t, &r, &["post-checkout", &new, &new, "1"], false);
    assert_eq!(o.stderr, "");
    assert!(r.join("public/fonts/old.otf").exists());
}

#[test]
fn incremental_hit_is_quarantined() {
    let t = Tmp::new("co-incr-q");
    let r = repo(&t);
    let base = git(&r, &["rev-parse", "HEAD"]);
    let new = add(&r, "public/fonts/new.otf", FAKE_FONT);
    let o = hook(&t, &r, &["post-checkout", &base, &new, "1"], false);
    assert!(o.stderr.contains("moved to quarantine"), "{}", o.stderr);
    assert!(!r.join("public/fonts/new.otf").exists());
}

#[test]
fn post_merge_uses_orig_head() {
    let t = Tmp::new("co-merge");
    let r = repo(&t);
    let base = git(&r, &["rev-parse", "HEAD"]);
    add(&r, "public/fonts/new.otf", FAKE_FONT);
    git(&r, &["update-ref", "ORIG_HEAD", &base]);
    let o = hook(&t, &r, &["post-merge", "0"], true);
    assert!(o.stderr.contains("changed files") && o.stderr.contains("new.otf"), "{}", o.stderr);
}

#[test]
fn outside_a_repo_and_bad_usage() {
    let t = Tmp::new("co-misc");
    assert_eq!(guard(&["scan-checkout"]).run().code, 2);
    let o = guard(&["scan-checkout", "post-checkout"]).home(&t.join("home")).cwd(&t.path).run();
    assert_eq!(o.code, 0);
}
