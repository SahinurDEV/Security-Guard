//! `guard watch`: the always-on filesystem watcher the service runs (port of
//! watcher.py, snapshot_store.py and memguard.py). Arguments, config, log
//! lines, alerts and the snapshot database match the Python build, so a
//! machine switching builds keeps its state.

mod memguard;
mod store;
mod watcher;

pub(crate) use watcher::expand_roots;

use std::path::Path;

use serde_json::{json, Map, Value};

use crate::pyjson;
use crate::pyrepr::str_repr;

const PROG: &str = "watcher.py";

const USAGE: &str = "\
usage: watcher.py [-h] [--once] [--roots [ROOTS ...]] [--interval INTERVAL]
                  [--print-default-config]
";

const HELP: &str = "
Guard filesystem watcher

options:
  -h, --help            show this help message and exit
  --once                single poll pass then exit (testing)
  --roots [ROOTS ...]   override watch roots
  --interval INTERVAL   poll interval seconds
  --print-default-config
";

/// watcher.py's DEFAULT_CONFIG, in its order.
pub fn default_config() -> Map<String, Value> {
    match json!({
        "watch_roots": ["~/Projects", "~/Desktop", "~/Downloads", "~/Documents"],
        "poll_interval_sec": 5,
        "native_events": true,
        "full_rescan_sec": 300,
        "native_queue_cap": 50000,
        "max_depth": 6,
        "exclude_dir_names": ["node_modules", "dist", "build", ".next", "coverage",
                              "Library", ".Trash", "venv", ".venv", "__pycache__",
                              ".dart_tool", "Pods", ".gradle", ".symlinks", "vendor",
                              "target", ".pub-cache", ".cache", "DerivedData", "Carthage"],
        "scan_new_files_ext": [".ts", ".js", ".mjs", ".cjs", ".json", ".yml", ".yaml",
                               ".env", ".woff2", ".woff", ".ttf", ".otf", ".png", ".jpg", ".ico"],
        "git_trigger_files": ["HEAD", "FETCH_HEAD", "ORIG_HEAD", "MERGE_HEAD",
                              "packed-refs", "config"],
        "repo_debounce_sec": 30,
        "batch_size": 2000,
        "max_changes_per_pass": 2000,
        "mem_budget_fraction": 0.10,
        "hard_memory_ceiling": false,
        "update_check_sec": 21600,
        "notify": true,
        "remediate": true,
        "quarantine_cmd": null,
    }) {
        Value::Object(m) => m,
        _ => unreachable!(),
    }
}

/// <guard_home>/watcher.config.json over the defaults; the defaults alone when
/// it is missing or not valid JSON.
fn load_config(home: &Path) -> Result<Map<String, Value>, String> {
    let mut cfg = default_config();
    let path = home.join("watcher.config.json");
    let Ok(raw) = std::fs::read(&path) else {
        return Ok(cfg);
    };
    let text =
        String::from_utf8(raw).map_err(|_| format!("{}: not valid UTF-8", path.display()))?;
    match serde_json::from_str::<Value>(&text) {
        Ok(Value::Object(m)) => {
            cfg.extend(m);
            Ok(cfg)
        }
        Ok(_) => Err(format!("{}: not a JSON object", path.display())),
        Err(_) => Ok(cfg),
    }
}

/// The watcher config in `home` over the defaults (the defaults alone when it
/// can't be read).
pub(crate) fn config(home: &Path) -> Map<String, Value> {
    load_config(home).unwrap_or_else(|_| default_config())
}

/// Python's float() of a string: surrounding whitespace, `_` between digits,
/// inf / nan in any case.
pub fn parse_float(s: &str) -> Option<f64> {
    let t = s.trim_matches(|c: char| c.is_whitespace() || ('\x1c'..='\x1f').contains(&c));
    let b = t.as_bytes();
    for (i, &c) in b.iter().enumerate() {
        if c == b'_'
            && !(i > 0 && b[i - 1].is_ascii_digit() && i + 1 < b.len() && b[i + 1].is_ascii_digit())
        {
            return None;
        }
    }
    let t = t.replace('_', "");
    let body = t.trim_start_matches(['+', '-']);
    if body.len() + 1 < t.len() {
        return None; // more than one sign
    }
    let lower = body.to_ascii_lowercase();
    if lower.starts_with("in") && lower != "inf" && lower != "infinity" {
        return None;
    }
    t.parse().ok()
}

struct Args {
    once: bool,
    roots: Option<Vec<String>>,
    interval: Option<f64>,
    print_default: bool,
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

/// An argument argparse would treat as an option string.
fn optionish(a: &str) -> bool {
    let negative_number = a.len() > 1
        && a[1..].parse::<f64>().is_ok()
        && a[1..].chars().all(|c| c.is_ascii_digit() || c == '.');
    a.starts_with('-') && a != "-" && !negative_number
}

fn parse(argv: &[String]) -> Parsed {
    const OPTS: &[&str] = &[
        "--help",
        "--once",
        "--roots",
        "--interval",
        "--print-default-config",
    ];
    let mut a = Args {
        once: false,
        roots: None,
        interval: None,
        print_default: false,
    };
    let mut extras: Vec<String> = vec![];
    let mut i = 0;
    while i < argv.len() {
        let arg = &argv[i];
        i += 1;
        if arg == "--" {
            extras.extend(argv[i - 1..].iter().cloned());
            break;
        }
        if !optionish(arg) {
            extras.push(arg.clone());
            continue;
        }
        if !arg.starts_with("--") {
            if arg.starts_with("-h") {
                print!("{USAGE}{HELP}");
                return Parsed::Exit(0);
            }
            extras.push(arg.clone());
            continue;
        }
        let (key, inline) = match arg.split_once('=') {
            Some((k, v)) => (k, Some(v.to_string())),
            None => (arg.as_str(), None),
        };
        let hits: Vec<&str> = OPTS
            .iter()
            .filter(|o| o.starts_with(key))
            .copied()
            .collect();
        let opt = if OPTS.contains(&key) {
            key
        } else {
            match hits.as_slice() {
                [one] => one,
                [] => {
                    extras.push(arg.clone());
                    continue;
                }
                many => {
                    return usage_error(&format!(
                        "ambiguous option: {key} could match {}",
                        many.join(", ")
                    ))
                }
            }
        };
        match opt {
            "--help" => {
                print!("{USAGE}{HELP}");
                return Parsed::Exit(0);
            }
            "--once" | "--print-default-config" => {
                if let Some(v) = inline {
                    return usage_error(&format!(
                        "argument {opt}: ignored explicit argument {}",
                        str_repr(&v)
                    ));
                }
                if opt == "--once" {
                    a.once = true;
                } else {
                    a.print_default = true;
                }
            }
            "--interval" => {
                let v = match inline {
                    Some(v) => v,
                    None if i < argv.len() && !optionish(&argv[i]) && argv[i] != "--" => {
                        i += 1;
                        argv[i - 1].clone()
                    }
                    None => return usage_error("argument --interval: expected one argument"),
                };
                match parse_float(&v) {
                    Some(f) => a.interval = Some(f),
                    None => {
                        return usage_error(&format!(
                            "argument --interval: invalid float value: {}",
                            str_repr(&v)
                        ))
                    }
                }
            }
            _ => {
                // --roots: nargs="*"
                let mut roots = vec![];
                match inline {
                    Some(v) => roots.push(v),
                    None => {
                        while i < argv.len() && !optionish(&argv[i]) && argv[i] != "--" {
                            roots.push(argv[i].clone());
                            i += 1;
                        }
                    }
                }
                a.roots = Some(roots);
            }
        }
    }
    if !extras.is_empty() {
        return usage_error(&format!("unrecognized arguments: {}", extras.join(" ")));
    }
    Parsed::Run(a)
}

pub fn main(argv: &[String]) -> u8 {
    let a = match parse(argv) {
        Parsed::Run(a) => a,
        Parsed::Exit(rc) => return rc,
    };
    if a.print_default {
        println!(
            "{}",
            pyjson::dumps(&Value::Object(default_config()), Some(2), false)
        );
        return 0;
    }
    let home = crate::util::guard_home();
    let run = || -> Result<u8, String> {
        let mut cfg = load_config(&home)?;
        // external disks join the configured roots, not an explicit --roots
        let mut volumes = cfg
            .get("watch_external_disks")
            .is_none_or(|v| pyjson::truthy(Some(v)));
        if let Some(r) = a.roots.filter(|r| !r.is_empty()) {
            cfg.insert("watch_roots".into(), json!(r));
            volumes = false;
        }
        if let Some(f) = a.interval.filter(|f| *f != 0.0) {
            cfg.insert("poll_interval_sec".into(), json!(f));
        }
        let mut w = watcher::Watcher::new(cfg, home.clone())?;
        if volumes && !a.once {
            w.add_volumes(watcher::external_volumes());
        }
        if a.once {
            // no priming: report what this pass finds (used by tests)
            let n = w.poll_once(false)?;
            w.log(&format!("--once complete: {n} event(s) handled"));
            return Ok(0);
        }
        w.run();
        Ok(0)
    };
    run().unwrap_or_else(|e| {
        eprintln!("guard watch: {e}");
        1
    })
}
