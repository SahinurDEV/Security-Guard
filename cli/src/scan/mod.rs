//! `guard scan`, `guard scan-git`, `guard open` (port of scanner.py) and
//! `guard clean` / `guard restore` (port of remediator.py).
//!
//! Exit codes: scan 0 clean, 1 infected (critical findings), 2 usage; open 0
//! safe, 1 unsafe. Output matches the Python build.

mod depbl;
mod fingerprint;
mod magic;
pub(crate) mod py;
pub mod remediate;
pub(crate) mod scanner;
pub(crate) mod sigs;
mod vscode;
pub(crate) mod workflow;

use serde_json::{json, Value};

use crate::pyjson;
pub use fingerprint::DEPS_DIR;
use scanner::Scanner;
pub use sigs::gunzip;

const PROG: &str = "scanner.py";
const MODES: &[&str] = &["scan-tree", "scan-git", "guard-open"];

const USAGE: &str = "\
usage: scanner.py [-h] [--signatures SIGNATURES] [--json]
                  [{scan-tree,scan-git,guard-open}] [path]
";

const HELP: &str = "
Guard supply-chain scanner

positional arguments:
  {scan-tree,scan-git,guard-open}
  path

options:
  -h, --help            show this help message and exit
  --signatures SIGNATURES
                        path to signatures.json
  --json                machine-readable output
";

struct Args {
    mode: String,
    path: String,
    signatures: Option<String>,
    json: bool,
}

enum Parsed {
    Run(Args),
    Exit(u8),
}

fn usage_error(msg: &str) -> Parsed {
    eprint!("{USAGE}");
    eprintln!("{PROG}: error: {msg}");
    Parsed::Exit(2)
}

/// argparse reads "-1" or "-.5" as a value, not an option.
fn negative_number(arg: &str) -> bool {
    static RE: std::sync::LazyLock<regex::Regex> =
        std::sync::LazyLock::new(|| regex::Regex::new(r"^-\d+$|^-\d*\.\d+$").unwrap());
    RE.is_match(arg)
}

/// argparse (Python 3.12, which builds the release) for
/// `scanner.py [mode] [path] [--signatures S] [--json]`: plain arguments fill
/// mode then path wherever they appear, and anything left over is an
/// unrecognized argument.
fn parse(argv: &[String]) -> Parsed {
    const OPTS: &[&str] = &["--help", "--signatures", "--json"];
    let mut a = Args {
        mode: "scan-tree".into(),
        path: ".".into(),
        signatures: None,
        json: false,
    };
    let mut positionals: Vec<String> = vec![];
    let mut extras: Vec<String> = vec![];
    let mut after_dashes = false;
    let mut i = 0;
    while i < argv.len() {
        let arg = &argv[i];
        i += 1;
        if !after_dashes && arg == "--" {
            after_dashes = true;
            continue;
        }
        let looks_opt =
            !after_dashes && arg.starts_with('-') && arg.len() > 1 && !negative_number(arg);
        if !looks_opt {
            if positionals.len() < 2 {
                positionals.push(arg.clone());
            } else {
                extras.push(arg.clone());
            }
            continue;
        }
        if arg == "-h" {
            print!("{USAGE}{HELP}");
            return Parsed::Exit(0);
        }
        let (key, inline) = match arg.split_once('=') {
            Some((k, v)) if k.starts_with("--") => (k, Some(v.to_string())),
            _ => (arg.as_str(), None),
        };
        let opt = if key.starts_with("--") {
            let hits: Vec<&str> = OPTS
                .iter()
                .filter(|o| o.starts_with(key))
                .copied()
                .collect();
            match (OPTS.contains(&key), hits.as_slice()) {
                (true, _) => Some(key),
                (false, [one]) => Some(*one),
                (false, []) => None,
                (false, many) => {
                    let list = many.join(", ");
                    return usage_error(&format!("ambiguous option: {key} could match {list}"));
                }
            }
        } else {
            None
        };
        match opt {
            None => extras.push(arg.clone()),
            Some("--help") => {
                print!("{USAGE}{HELP}");
                return Parsed::Exit(0);
            }
            Some("--json") => {
                if let Some(v) = inline {
                    return usage_error(&format!(
                        "argument --json: ignored explicit argument {}",
                        crate::pyrepr::str_repr(&v)
                    ));
                }
                a.json = true;
            }
            Some(_) => {
                let v = match inline {
                    Some(v) => v,
                    None if i < argv.len()
                        && !(argv[i].starts_with('-')
                            && argv[i].len() > 1
                            && !negative_number(&argv[i])) =>
                    {
                        i += 1;
                        argv[i - 1].clone()
                    }
                    None => return usage_error("argument --signatures: expected one argument"),
                };
                a.signatures = Some(v);
            }
        }
    }
    let mut pos = positionals.into_iter();
    if let Some(m) = pos.next() {
        if !MODES.contains(&m.as_str()) {
            let choices = MODES
                .iter()
                .map(|m| format!("'{m}'"))
                .collect::<Vec<_>>()
                .join(", ");
            return usage_error(&format!(
                "argument mode: invalid choice: {} (choose from {choices})",
                crate::pyrepr::str_repr(&m)
            ));
        }
        a.mode = m;
    }
    if let Some(p) = pos.next() {
        a.path = p;
    }
    if !extras.is_empty() {
        return usage_error(&format!("unrecognized arguments: {}", extras.join(" ")));
    }
    Parsed::Run(a)
}

fn print_human(results: &Value, git: Option<&Value>) {
    let dump = |title: &str, items: Option<&Value>| {
        let items = items.and_then(Value::as_array).cloned().unwrap_or_default();
        if items.is_empty() {
            return;
        }
        println!("\n== {title} ({}) ==", items.len());
        for x in &items {
            let get = |k: &str| {
                x.get(k)
                    .filter(|v| pyjson::truthy(Some(v)))
                    .map(crate::av::pystr::py_str)
            };
            let sev = x
                .get("severity")
                .map(crate::av::pystr::py_str)
                .unwrap_or_else(|| "?".into())
                .to_uppercase();
            let loc = get("path")
                .or_else(|| get("where"))
                .or_else(|| get("commit"))
                .unwrap_or_default();
            let state = x
                .get("state")
                .map(crate::av::pystr::py_str)
                .unwrap_or_default();
            let reason = get("reason")
                .or_else(|| get("desc"))
                .or_else(|| get("detail"))
                .unwrap_or_default();
            let sid = x
                .get("sig_id")
                .map(crate::av::pystr::py_str)
                .unwrap_or_default();
            let line = format!("  [{sev}] {loc} {sid} {state} {reason}");
            println!("{}", line.trim_end_matches(crate::av::pystr::is_space));
        }
    };
    println!("Repo: {}", crate::av::pystr::py_str(&results["repo"]));
    dump("VS CODE AUTO-RUN (pre-open)", results.get("vscode"));
    dump("WORKFLOW BASELINE DIFF", results.get("workflow_baseline"));
    dump(
        "MALICIOUS DEPENDENCIES (GitHub malware list)",
        results.get("malicious_deps"),
    );
    dump("BINARY-DISGUISED DROPPERS", results.get("magic"));
    dump("FINGERPRINT MATCHES", results.get("fingerprint"));
    dump(
        "ANTIVIRUS ENGINE (signatures / rules / heuristics)",
        results.get("av"),
    );
    if let Some(g) = git {
        let n = g
            .get("commits_scanned")
            .map(crate::av::pystr::py_str)
            .unwrap_or("0".into());
        dump(
            &format!("GIT HISTORY (added lines, {n} commits)"),
            g.get("diff_findings"),
        );
        if let Some(e) = g.get("error").filter(|e| pyjson::truthy(Some(e))) {
            println!("  (git scan note: {})", crate::av::pystr::py_str(e));
        }
    }
    let infected = infected(results, git);
    println!(
        "\n{}",
        if infected {
            "RESULT: INFECTED (critical findings present)"
        } else {
            "RESULT: clean"
        }
    );
}

fn infected(results: &Value, git: Option<&Value>) -> bool {
    results["infected"] == json!(true) || git.is_some_and(|g| g["infected"] == json!(true))
}

/// scanner.main with argv after the program name.
fn scanner_main(argv: &[String]) -> Result<u8, String> {
    let a = match parse(argv) {
        Parsed::Run(a) => a,
        Parsed::Exit(c) => return Ok(c),
    };
    let sig = sigs::load(a.signatures.as_deref())?;
    let open = a.mode == "guard-open";
    let mut scanner = Scanner::new(&sig, !open)?;

    if open {
        let (safe, findings) = scanner.vscode.is_safe_to_open(&a.path);
        if a.json {
            let payload = json!({"repo": a.path, "safe_to_open": safe,
                "findings": findings.iter().map(|f| Value::Object(f.to_json())).collect::<Vec<_>>()});
            println!("{}", pyjson::dumps(&payload, Some(2), false));
        } else {
            for f in &findings {
                println!("{f}");
            }
            println!(
                "{}",
                if safe {
                    "SAFE TO OPEN"
                } else {
                    ">>> DO NOT OPEN — critical auto-run task detected"
                }
            );
        }
        return Ok(if safe { 0 } else { 1 });
    }

    let results = scanner.scan_tree(&a.path);
    let git = (a.mode == "scan-git").then(|| scanner.scan_git_history(&a.path));
    if a.json {
        let out = json!({"tree": results, "git": git});
        println!("{}", pyjson::dumps(&out, Some(2), false));
    } else {
        print_human(&results, git.as_ref());
    }
    Ok(if infected(&results, git.as_ref()) {
        1
    } else {
        0
    })
}

fn report(r: Result<u8, String>) -> u8 {
    r.unwrap_or_else(|e| {
        eprintln!("guard: {e}");
        1
    })
}

/// guard scan / scan-git / open: the mode, then the user's arguments ("." when
/// there are none), as guard.py hands them to scanner.py.
pub fn main(mode: &str, rest: &[String]) -> u8 {
    let mut argv = vec![mode.to_string()];
    if rest.is_empty() {
        argv.push(".".into());
    } else {
        argv.extend_from_slice(rest);
    }
    report(scanner_main(&argv))
}

/// guard clean / guard restore.
pub fn remediate_main(sub: &str, rest: &[String]) -> u8 {
    let mut argv = vec![sub.to_string()];
    if sub == "clean" && rest.is_empty() {
        argv.push(".".into());
    } else {
        argv.extend_from_slice(rest);
    }
    report(remediate::main(&argv))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(args: &[&str]) -> Option<(String, String, bool)> {
        match parse(&args.iter().map(|s| s.to_string()).collect::<Vec<_>>()) {
            Parsed::Run(a) => Some((a.mode, a.path, a.json)),
            Parsed::Exit(_) => None,
        }
    }

    #[test]
    fn argparse_quirks() {
        assert_eq!(
            run(&["scan-tree", "."]),
            Some(("scan-tree".into(), ".".into(), false))
        );
        assert_eq!(
            run(&["scan-tree", "x", "--j"]),
            Some(("scan-tree".into(), "x".into(), true))
        );
        assert_eq!(
            run(&["scan-tree", "--json", "x"]),
            Some(("scan-tree".into(), "x".into(), true))
        );
        assert_eq!(run(&["scan-tree", "a", "b"]), None);
        assert_eq!(
            run(&["scan-tree", "--", "--json"]),
            Some(("scan-tree".into(), "--json".into(), false))
        );
        assert_eq!(run(&["scan-tree", "--json=1"]), None);
    }
}
