//! The repo / tree scanner (port of scanner.py's GuardScanner): VS Code
//! auto-run, workflow baselines, disguised droppers, incident fingerprints,
//! malicious dependencies and the av engine over every file, plus the added
//! lines of every commit for scan-git.

use std::fs;
use std::io::Read;
use std::path::Path;
use std::process::Command;

use serde_json::{json, Map, Value};

use super::depbl::Blocklist;
use super::fingerprint::{Matcher, DEPS_DIR};
use super::magic::Checker;
use super::py;
use super::sigs::Res;
use super::vscode::Guard;
use super::workflow::Baseline;
use crate::av::engine::{action_hint, Config, Engine};
use crate::av::model::Verdict;
use crate::av::pystr;
use crate::deps::py_path_str;

/// Text scanning reads at most this much of a file.
const MAX_SCAN_BYTES: u64 = 5 * 1024 * 1024;
/// Content the av engine examines per file.
const AV_MAX_SCAN_BYTES: u64 = 16 * 1024 * 1024;
/// A tree with more files than this is the wrong target: bail loudly.
const MAX_FILES: usize = 50_000;
pub const BINARY_EXTS: &[&str] = &[
    ".woff2", ".woff", ".ttf", ".otf", ".eot", ".png", ".jpg", ".jpeg", ".gif", ".ico",
];
const BUCKETS: &[&str] = &[
    "vscode",
    "magic",
    "fingerprint",
    "workflow_baseline",
    "malicious_deps",
    "av",
];

pub struct Scanner {
    pub vscode: Guard,
    pub magic: Checker,
    pub matcher: Matcher,
    skip_names: Vec<String>,
    deps: Option<Blocklist>,
    av: Option<Engine>,
    /// Leave node_modules out of a tree walk (the watcher scans it on its own
    /// when it changes), unless the tree is a node_modules directory itself.
    pub skip_deps: bool,
}

pub fn read_text_capped(p: &Path) -> Option<String> {
    let mut raw = Vec::new();
    fs::File::open(p)
        .ok()?
        .take(MAX_SCAN_BYTES)
        .read_to_end(&mut raw)
        .ok()?;
    Some(String::from_utf8_lossy(&raw).into_owned())
}

fn obj(v: Value) -> Map<String, Value> {
    match v {
        Value::Object(m) => m,
        _ => unreachable!(),
    }
}

fn critical(v: &Value) -> bool {
    v.get("severity").and_then(Value::as_str) == Some("critical")
}

/// Directory entries the way os.walk splits them: (dirs, files), with links
/// to directories counted as directories, each sorted by name. None when the
/// listing fails.
fn listdir(dir: &Path) -> Option<(Vec<String>, Vec<String>)> {
    let (mut dirs, mut files) = (vec![], vec![]);
    for e in fs::read_dir(dir).ok()? {
        let e = e.ok()?;
        let name = e.file_name().to_string_lossy().into_owned();
        let is_dir = match e.file_type() {
            Ok(t) if t.is_symlink() => fs::metadata(e.path()).map(|m| m.is_dir()).unwrap_or(false),
            Ok(t) => t.is_dir(),
            Err(_) => false,
        };
        if is_dir {
            dirs.push(name);
        } else {
            files.push(name);
        }
    }
    // sorted, so the report reads the same on every machine and file system
    dirs.sort();
    files.sort();
    Some((dirs, files))
}

impl Scanner {
    /// `with_av`: load the av engine too (not needed for the pre-open check).
    pub fn new(sig: &Value, with_av: bool) -> Res<Scanner> {
        let skip_names = super::sigs::str_list(sig.get("skip_path_prefixes"))?
            .iter()
            .map(|p| p.trim_matches('/').to_string())
            .collect();
        let av = with_av
            .then(|| {
                Engine::new(
                    Config {
                        scan_archives: true,
                        heuristics: true,
                        max_scan_bytes: AV_MAX_SCAN_BYTES,
                        community_rules: crate::av::engine::community_rules_enabled(),
                    },
                    &[],
                )
                .ok()
            })
            .flatten();
        Ok(Scanner {
            vscode: Guard::new(sig)?,
            magic: Checker::new(sig)?,
            matcher: Matcher::new(sig)?,
            skip_names,
            deps: Blocklist::load(),
            av,
            skip_deps: false,
        })
    }

    /// The av engine on one file: a finding when it is not clean.
    pub fn av_scan_file(&mut self, path: &str, rel: &str) -> Option<Value> {
        let r = self.av.as_mut()?.scan_file(Path::new(path));
        if !r.error.is_empty() || r.verdict == Verdict::Clean {
            return None;
        }
        let mut top = None;
        for d in r.all_detections() {
            if top.is_none_or(|t: &crate::av::model::Detection| d.verdict > t.verdict) {
                top = Some(d);
            }
        }
        let top = top?;
        let threat = r.threat_name();
        let desc = format!("{threat}: {}", top.description);
        Some(json!({
            "path": rel, "where": rel,
            "severity": if r.verdict == Verdict::Malicious { "critical" } else { "medium" },
            "sig_id": if top.rule_id.is_empty() { &top.name } else { &top.rule_id },
            "category": top.engine,
            "desc": desc.trim_end_matches([':', ' ']),
            "threat": threat, "verdict": r.verdict.label(),
            "action": action_hint(&r), "sha256": r.sha256,
        }))
    }

    pub fn scan_tree(&mut self, repo_arg: &str) -> Value {
        let repo = py_path_str(repo_arg);
        let mut buckets: Vec<(&str, Vec<Value>)> = BUCKETS.iter().map(|b| (*b, vec![])).collect();
        let vscode: Vec<Value> = self
            .vscode
            .scan_repo(&repo)
            .iter()
            .map(|f| Value::Object(f.to_json()))
            .collect();
        buckets[0].1 = vscode;
        if Path::new(&py::join(&repo, ".github/workflows")).is_dir() {
            let wf: Vec<Value> = Baseline::new(&self.matcher)
                .diff(&repo)
                .into_iter()
                .filter(|f| f.severity != "ok")
                .map(|f| f.to_json())
                .collect();
            buckets[3].1 = wf;
        }

        // os.walk order, pruning skipped directory names before descending.
        // Dependency code is never trusted: inside node_modules nothing is
        // pruned, and its files don't count toward MAX_FILES (a big project's
        // dependencies alone pass it).
        let root_is_deps = pystr::name(repo.trim_end_matches(['/', '\\'])) == DEPS_DIR;
        let mut seen = 0usize;
        let mut stack: Vec<String> = vec![String::new()];
        'walk: while let Some(rel_dir) = stack.pop() {
            let dir = if rel_dir.is_empty() {
                repo.clone()
            } else {
                py::join(&repo, &rel_dir)
            };
            let Some((dirs, files)) = listdir(Path::new(&dir)) else {
                continue;
            };
            let in_deps = root_is_deps || rel_dir.split('/').any(|c| c == DEPS_DIR);
            let dirs: Vec<String> = dirs
                .into_iter()
                .filter(|d| {
                    in_deps
                        || if d == DEPS_DIR {
                            !self.skip_deps
                        } else {
                            !self.skip_names.contains(d)
                        }
                })
                .collect();
            for f in files {
                let rel = if rel_dir.is_empty() {
                    f.clone()
                } else {
                    format!("{rel_dir}/{f}")
                };
                let full = py::join(&repo, &rel);
                seen += usize::from(!in_deps);
                if seen > MAX_FILES {
                    buckets[2].1.push(json!({
                        "where": repo, "sig_id": "scan.aborted", "severity": "info", "category": "scanner",
                        "desc": format!("tree exceeds {MAX_FILES} files — aborted (wrong target?)"),
                    }));
                    break 'walk;
                }
                let ext = pystr::suffix(&full).to_lowercase();
                if let Some(hit) = self.av_scan_file(&full, &rel) {
                    buckets[5].1.push(hit);
                }
                if BINARY_EXTS.contains(&ext.as_str()) {
                    for f in self.magic.check_file(&full) {
                        let mut d = f.to_json();
                        d.insert("path".into(), json!(rel));
                        buckets[1].1.push(Value::Object(d));
                    }
                    continue;
                }
                let Some(content) = read_text_capped(Path::new(&full)) else {
                    continue;
                };
                let found = if in_deps {
                    // GitHub runs only a repo's own workflows, never a package's
                    let mut f = self.matcher.scan_text(&rel, &content);
                    f.retain(|f| f.sig_id != "wf.name");
                    f
                } else {
                    self.matcher.scan_content(&rel, &content)
                };
                for f in found {
                    buckets[2].1.push(f.to_json());
                }
                if let Some(bl) = &self.deps {
                    if Blocklist::is_manifest(&rel) {
                        buckets[4].1.extend(bl.check_manifest(&rel, &content));
                    }
                }
            }
            for d in dirs.iter().rev() {
                let sub = if rel_dir.is_empty() {
                    d.clone()
                } else {
                    format!("{rel_dir}/{d}")
                };
                let is_link = fs::symlink_metadata(py::join(&repo, &sub))
                    .map(|m| m.file_type().is_symlink())
                    .unwrap_or(false);
                if !is_link {
                    stack.push(sub);
                }
            }
        }

        let infected = buckets.iter().any(|(_, v)| v.iter().any(critical));
        let mut out = Map::new();
        out.insert("repo".into(), json!(repo));
        for (k, v) in buckets {
            out.insert(k.into(), Value::Array(v));
        }
        out.insert("infected".into(), json!(infected));
        Value::Object(out)
    }

    /// Added lines of every commit on every branch.
    pub fn scan_git_history(&self, repo_arg: &str) -> Value {
        let repo = py_path_str(repo_arg);
        let mut out = obj(
            json!({"repo": repo, "diff_findings": [], "infected": false, "commits_scanned": 0}),
        );
        let argv = [
            "git",
            "-C",
            repo.as_str(),
            "rev-list",
            "--all",
            "--no-merges",
        ];
        let shas = match git(&argv) {
            Ok(s) => s,
            Err(e) => {
                out.insert("error".into(), json!(format!("git rev-list failed: {e}")));
                return Value::Object(out);
            }
        };
        let mut findings = vec![];
        let mut commits = 0u64;
        for sha in pystr::split_ws(&shas) {
            let Ok(diff) = git(&[
                "git",
                "-C",
                repo.as_str(),
                "show",
                "--format=%H%n%an <%ae>%n%aI",
                sha,
            ]) else {
                continue;
            };
            commits += 1;
            for f in self.matcher.scan_diff(&diff) {
                let Value::Object(mut d) = f.to_json() else {
                    unreachable!()
                };
                d.insert("commit".into(), json!(py::head(sha, 12)));
                findings.push(Value::Object(d));
            }
        }
        let infected = findings.iter().any(critical);
        out.insert("diff_findings".into(), Value::Array(findings));
        out.insert("infected".into(), json!(infected));
        out.insert("commits_scanned".into(), json!(commits));
        Value::Object(out)
    }
}

/// subprocess.run(argv, capture_output=True, text=True, check=True).stdout,
/// with the error text Python's exceptions print.
fn git(argv: &[&str]) -> Result<String, String> {
    let out = match Command::new(argv[0]).args(&argv[1..]).output() {
        Ok(o) => o,
        Err(e) => return Err(pystr::spawn_error(&e, argv[0])),
    };
    if !out.status.success() {
        let list = argv
            .iter()
            .map(|a| crate::pyrepr::str_repr(a))
            .collect::<Vec<_>>()
            .join(", ");
        return Err(match out.status.code() {
            Some(c) => format!("Command '[{list}]' returned non-zero exit status {c}."),
            None => format!("Command '[{list}]' died with a signal."),
        });
    }
    Ok(py::universal(
        String::from_utf8_lossy(&out.stdout).into_owned(),
    ))
}
