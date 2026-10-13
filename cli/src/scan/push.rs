//! `guard scan-push`: the pre-push gate.
//!
//! git runs the pre-push hook with the remote name and URL as arguments and one
//! line per ref on stdin: `<local ref> <local sha> <remote ref> <remote sha>`.
//! For every ref being pushed (normal push, `--force`, `--force-with-lease`,
//! a brand-new branch or tag) this collects every blob ADDED OR CHANGED by the
//! commits the remote does not have yet - including blobs that a later commit
//! deletes again, since they would still land in the remote's history - writes
//! them into a scratch directory (never executed, never checked out), and runs
//! the regular tree scan over it. The full tree of each pushed tip is
//! scanned as well, so a push onto an already-infected branch is blocked until
//! the malware is removed in a commit (GUARD_PUSH_SCOPE=new turns that off).
//!
//! Exit 0 lets the push through; exit 1 blocks it. On a block the working tree
//! is cleaned (injected code excised, whole-file droppers quarantined, all
//! reversible with `guard restore`) unless GUARD_PUSH_QUARANTINE=0.
//!
//! Fail closed: if git can't tell what is being pushed, the push is blocked
//! (GUARD_PUSH_FAIL_OPEN=1 lets it through with a warning).
//!
//! Client-side hooks are skipped by `git push --no-verify`; see README
//! "Push protection" for the server-side layer that cannot be bypassed.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};

#[cfg(test)]
const ZERO: &str = "0000000000000000000000000000000000000000";
/// blobs bigger than this are not copied out (the scanner caps reads anyway)
const MAX_BLOB: usize = 32 * 1024 * 1024;

fn is_zero(sha: &str) -> bool {
    !sha.is_empty() && sha.bytes().all(|b| b == b'0')
}

fn git(repo: &Path, args: &[&str]) -> Result<String, String> {
    let out = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .map_err(|e| format!("cannot run git: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "git {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

fn has_commit(repo: &Path, sha: &str) -> bool {
    Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(["cat-file", "-e", &format!("{sha}^{{commit}}")])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// One pushed ref from the hook's stdin.
#[derive(Debug, PartialEq)]
pub struct PushRef {
    pub local_ref: String,
    pub local_sha: String,
    pub remote_ref: String,
    pub remote_sha: String,
}

pub fn parse_refs(input: &str) -> Vec<PushRef> {
    input
        .lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            (f.len() == 4).then(|| PushRef {
                local_ref: f[0].into(),
                local_sha: f[1].into(),
                remote_ref: f[2].into(),
                remote_sha: f[3].into(),
            })
        })
        .collect()
}

/// A repo-relative path from git, safe to recreate under the scratch dir:
/// no absolute paths, no `..`, no drive prefixes.
pub fn safe_rel(p: &str) -> Option<PathBuf> {
    let path = Path::new(p);
    let mut out = PathBuf::new();
    for c in path.components() {
        match c {
            Component::Normal(s) => {
                let s = s.to_str()?;
                if s.contains(':') || s.is_empty() {
                    return None;
                }
                out.push(s);
            }
            _ => return None,
        }
    }
    (!out.as_os_str().is_empty()).then_some(out)
}

/// The commits this push adds to the remote. Force pushes are covered: the
/// range is "reachable from the new tip, not from what the remote had", which
/// does not require the old tip to be an ancestor.
fn new_commits(repo: &Path, r: &PushRef, remote: Option<&str>) -> Result<Vec<String>, String> {
    let mut args = vec!["rev-list".to_string(), r.local_sha.clone(), "--not".into()];
    if !is_zero(&r.remote_sha) && has_commit(repo, &r.remote_sha) {
        args.push(r.remote_sha.clone());
    }
    // a new branch, or a force push whose old tip we never fetched: everything
    // the DESTINATION remote's tracking refs don't already have. Commits that
    // are only on another remote (an infected upstream pushed to a new place)
    // are scanned; a push to a bare URL scans everything it sends.
    if let Some(name) = remote {
        args.push(format!("--remotes={name}"));
    }
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    Ok(git(repo, &args)?.lines().map(str::to_string).collect())
}

/// The pushed-to remote, when it is a configured remote name (not a URL/path).
fn configured_remote(repo: &Path, name: Option<&str>) -> Option<String> {
    let name = name?;
    let list = git(repo, &["remote"]).ok()?;
    list.lines().any(|l| l == name).then(|| name.to_string())
}

/// (blob sha, path) for every file a commit adds or modifies.
fn changed_blobs(repo: &Path, commit: &str, out: &mut BTreeSet<(String, String)>) -> Result<(), String> {
    let raw = git(
        repo,
        &["diff-tree", "-r", "--root", "--no-commit-id", "--no-renames", "-z", "--diff-filter=AMT", commit],
    )?;
    // -z: ":<modes> <old> <new> <status>\0<path>\0"
    let mut it = raw.split('\0');
    while let Some(meta) = it.next() {
        if meta.is_empty() {
            continue;
        }
        let Some(path) = it.next() else { break };
        let f: Vec<&str> = meta.split(' ').collect();
        // skip submodules (mode 160000): not our objects
        if f.len() >= 4 && !f[1].starts_with("160") {
            out.insert((f[3].to_string(), path.to_string()));
        }
    }
    Ok(())
}

/// (blob sha, path) for every file in a commit's tree.
fn tree_blobs(repo: &Path, commit: &str, out: &mut BTreeSet<(String, String)>) -> Result<(), String> {
    let raw = git(repo, &["ls-tree", "-r", "-z", "--full-tree", commit])?;
    // "<mode> blob <sha>\t<path>\0"
    for entry in raw.split('\0').filter(|e| !e.is_empty()) {
        let Some((meta, path)) = entry.split_once('\t') else { continue };
        let f: Vec<&str> = meta.split(' ').collect();
        if f.len() == 3 && f[1] == "blob" {
            out.insert((f[2].to_string(), path.to_string()));
        }
    }
    Ok(())
}

/// Write each blob under dir/<path>; a second distinct version of the same
/// path goes under dir/.guard-rev-N/<path>.
fn materialize(repo: &Path, blobs: &BTreeSet<(String, String)>, dir: &Path) -> Result<BTreeMap<PathBuf, String>, String> {
    let mut child = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(["cat-file", "--batch"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("cannot run git: {e}"))?;
    let mut input = String::new();
    for (sha, _) in blobs {
        input.push_str(sha);
        input.push('\n');
    }
    let mut stdin = child.stdin.take().ok_or("no stdin")?;
    let writer = std::thread::spawn(move || {
        let _ = stdin.write_all(input.as_bytes());
    });
    let mut data = Vec::new();
    child
        .stdout
        .take()
        .ok_or("no stdout")?
        .read_to_end(&mut data)
        .map_err(|e| e.to_string())?;
    let _ = writer.join();
    let _ = child.wait();

    let mut seen: BTreeMap<PathBuf, usize> = BTreeMap::new();
    let mut written = BTreeMap::new();
    let mut pos = 0usize;
    for (sha, path) in blobs {
        let nl = data[pos..].iter().position(|&b| b == b'\n').ok_or("short cat-file output")? + pos;
        let header = String::from_utf8_lossy(&data[pos..nl]).into_owned();
        pos = nl + 1;
        let h: Vec<&str> = header.split(' ').collect();
        if h.len() != 3 || h[0] != sha {
            return Err(format!("unexpected cat-file header: {header}"));
        }
        if h[1] != "blob" {
            continue; // "missing" has 2 fields, so it never gets here
        }
        let size: usize = h[2].parse().map_err(|_| "bad size")?;
        let body = data.get(pos..pos + size).ok_or("truncated blob")?;
        pos += size + 1;
        let Some(rel) = safe_rel(path) else { continue };
        if size > MAX_BLOB {
            continue;
        }
        let n = seen.entry(rel.clone()).or_insert(0);
        let dest_rel = if *n == 0 {
            rel.clone()
        } else {
            Path::new(&format!(".guard-rev-{n}")).join(&rel)
        };
        *n += 1;
        let dest = dir.join(&dest_rel);
        if let Some(p) = dest.parent() {
            fs::create_dir_all(p).map_err(|e| e.to_string())?;
        }
        fs::write(&dest, body).map_err(|e| e.to_string())?;
        written.insert(dest_rel, path.clone());
    }
    Ok(written)
}

fn scratch() -> Result<PathBuf, String> {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let d = std::env::temp_dir().join(format!("guard-push-{}-{nanos}", std::process::id()));
    fs::create_dir_all(&d).map_err(|e| format!("cannot create {}: {e}", d.display()))?;
    Ok(d)
}

fn env_is(k: &str, v: &str) -> bool {
    std::env::var(k).map(|x| x.eq_ignore_ascii_case(v)).unwrap_or(false)
}

fn banner(msg: &str) {
    eprintln!("\x1b[31m[GUARD] {msg}\x1b[0m");
}

/// The gate itself; Ok(true) = infected.
fn check(repo: &Path, refs: &[PushRef], remote: Option<&str>) -> Result<bool, String> {
    let remote = configured_remote(repo, remote);
    let mut blobs = BTreeSet::new();
    for r in refs {
        if is_zero(&r.local_sha) {
            continue; // deleting a remote ref pushes no content
        }
        for c in new_commits(repo, r, remote.as_deref())? {
            changed_blobs(repo, &c, &mut blobs)?;
        }
        // the tree the remote ends up with, too: pushing on top of a branch
        // that is already infected is blocked until the infection is
        // committed away (GUARD_PUSH_SCOPE=new: only what the push adds)
        if !env_is("GUARD_PUSH_SCOPE", "new") {
            tree_blobs(repo, &r.local_sha, &mut blobs)?;
        }
    }
    if blobs.is_empty() {
        return Ok(false);
    }
    let dir = scratch()?;
    let result = (|| {
        materialize(repo, &blobs, &dir)?;
        let d = dir.to_string_lossy().into_owned();
        super::scanner_main(&["scan-tree".to_string(), d]).map(|code| code == 1)
    })();
    let _ = fs::remove_dir_all(&dir);
    result
}

pub fn main(rest: &[String]) -> u8 {
    // read stdin first, always: git (or a chained hook) is writing to us
    let mut input = String::new();
    let read = std::io::stdin().read_to_string(&mut input);
    if env_is("GUARD_PUSH", "off") {
        banner("GUARD_PUSH=off: pre-push scan skipped");
        return 0;
    }
    if let Err(e) = read {
        eprintln!("guard scan-push: cannot read stdin: {e}");
        return 1;
    }
    let refs = parse_refs(&input);
    let repo = match git(Path::new("."), &["rev-parse", "--show-toplevel"]) {
        Ok(s) => PathBuf::from(s.trim()),
        Err(e) => return fail(&e),
    };
    let remote = rest.first().map(String::as_str).unwrap_or("?");
    match check(&repo, &refs, rest.first().map(String::as_str)) {
        Ok(false) => 0,
        Ok(true) => {
            banner(&format!("PUSH BLOCKED: malware signatures in the commits being pushed to '{remote}'."));
            banner("Paths above are relative to the pushed content (.guard-rev-N/ = an older version of that file in this push).");
            if env_is("GUARD_PUSH_QUARANTINE", "0") {
                banner("GUARD_PUSH_QUARANTINE=0: working tree left untouched. Clean it with: guard clean .");
            } else {
                banner("Cleaning the working tree (reversible; see `guard restore <path>`):");
                let code = super::remediate_main("clean", &[repo.to_string_lossy().into_owned()]);
                if code != 0 {
                    banner("automatic clean failed; run `guard clean .` manually");
                }
            }
            banner("Infected content is still in your local commits. Remove it (e.g. rewrite with");
            banner("git rebase -i / git commit --amend), re-run the push, and never push it with --no-verify.");
            1
        }
        Err(e) => fail(&e),
    }
}

fn fail(e: &str) -> u8 {
    if env_is("GUARD_PUSH_FAIL_OPEN", "1") {
        banner(&format!("pre-push scan failed ({e}); GUARD_PUSH_FAIL_OPEN=1 so the push continues"));
        0
    } else {
        banner(&format!("PUSH BLOCKED: pre-push scan could not run ({e})."));
        banner("Fix the error, or set GUARD_PUSH_FAIL_OPEN=1 for this push if you are sure it is clean.");
        1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_hook_stdin() {
        let r = parse_refs(&format!("refs/heads/a 1111 refs/heads/a {ZERO}\nbad line\n"));
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].local_ref, "refs/heads/a");
        assert_eq!(r[0].remote_ref, "refs/heads/a");
        assert!(is_zero(&r[0].remote_sha));
        assert!(!is_zero("1111") && !is_zero(""));
        assert_eq!(r[0].local_sha, "1111");
    }

    #[test]
    fn rejects_unsafe_paths() {
        assert_eq!(safe_rel("a/b.js"), Some(PathBuf::from("a/b.js")));
        assert_eq!(safe_rel("../x"), None);
        assert_eq!(safe_rel("a/../../x"), None);
        assert_eq!(safe_rel("/etc/passwd"), None);
        assert_eq!(safe_rel("C:x"), None);
        assert_eq!(safe_rel(""), None);
        assert_eq!(safe_rel("./a"), None);
    }
}
