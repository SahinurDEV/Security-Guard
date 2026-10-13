//! Rules from the sparktechagency "api.js" wave (EtherHiding loader), checked
//! on inert fixtures assembled at runtime (split strings, so this file itself
//! scans clean). No live payload: just the shapes the rules key on.

mod common;

use std::fs;

use common::*;
use serde_json::Value;

fn j(parts: &[&str]) -> String {
    parts.concat()
}

fn scan_json(t: &Tmp, dir: &std::path::Path) -> (i32, Value) {
    let o = guard(&["scan", &s(dir), "--json"]).home(&t.join("home")).run();
    (o.code, parse_json(&o.stdout))
}

fn ids(v: &Value) -> Vec<String> {
    let mut out = vec![];
    if let Some(m) = v["tree"].as_object() {
        for b in m.values() {
            for f in b.as_array().into_iter().flatten() {
                if let Some(id) = f["sig_id"].as_str() {
                    out.push(id.to_string());
                }
            }
        }
    }
    out
}

fn case(tag: &str, file: &str, body: &str, want: &str, critical: bool) {
    let t = Tmp::new(tag);
    let d = t.join("repo");
    write(&d.join(file), body);
    let (code, v) = scan_json(&t, &d);
    let got = ids(&v);
    assert!(got.iter().any(|i| i == want), "{tag}: want {want}, got {got:?}");
    assert_eq!(code == 1, critical, "{tag}: exit {code}");
}

#[test]
fn npm_script_runs_hidden_root_loader() {
    let body = format!("{{\"scripts\": {{\"dev\": \"{}\"}}}}\n", j(&["node api", ".js && next dev"]));
    case("pkg-api", "package.json", &body, "pkg.script.api", true);
}

#[test]
fn npm_script_runs_a_font() {
    let body = format!("{{\"scripts\": {{\"start\": \"{}\"}}}}\n", j(&["node ./public/img/x", ".otf && node s.js"]));
    case("pkg-font", "package.json", &body, "pkg.script.asset.exec", true);
}

#[test]
fn npm_lifecycle_preloader_is_reported_not_quarantined() {
    let body = "{\"scripts\": {\"start\": \"node boot.js && node server.js\"}}\n";
    case("pkg-pre", "package.json", body, "pkg.script.hidden.loader", false);
}

#[test]
fn loader_prologue_and_chunk_array() {
    let body = j(&["const __0x0", "4b12=77;function f(){}\n"]);
    case("prologue", "src/a.js", &body, "payload.fp.04b12", true);
    let body = j(&["var _0x05a5", "98a=[\"QUJD\"];\n"]);
    case("chunks", "src/b.js", &body, "payload.fp.05a598", true);
}

#[test]
fn ethereum_c2_address_and_stage_urls() {
    let body = j(&["const S='0xa322E5f3D311D3080e6f01", "21063e9aDC2490Ef1a';\n"]);
    case("eth", "lib/c.js", &body, "ioc.eth.sender", true);
    let body = j(&["const u=`http://${a}:443/0", "x/cls`;\n"]);
    case("stage", "lib/d.js", &body, "c2.stage.url", true);
    let body = j(&["const h=res.headers['x-payload", "-b64'];\n"]);
    case("hdr", "lib/e.js", &body, "c2.payload.header", true);
}

#[test]
fn rpc_lookup_then_node_dash_e() {
    let body = j(&[
        "const I='https://eth.block", "scout.com/api';\n",
        "/* ... */ spawn('node',['-", "e',code],{detached:true}).unref();\n",
    ]);
    case("rpc", "lib/f.js", &body, "c2.eth.lookup.exec", true);
}

#[test]
fn legit_web3_rpc_use_is_clean() {
    let t = Tmp::new("web3");
    let d = t.join("repo");
    write(&d.join("src/rpc.js"), "const RPC = 'https://eth.drpc.org';\nfetch(RPC, {method: 'POST'});\n");
    write(&d.join("package.json"), "{\"scripts\": {\"build\": \"tsc && node dist/index.js\"}}\n");
    let (code, v) = scan_json(&t, &d);
    assert_eq!(code, 0, "{v}");
}

#[test]
fn gitignore_autopush_entry_is_reported() {
    case("gi", ".gitignore", &j(&["node_modules\ntemp_auto", "_push.bat\n"]), "gitignore.autopush", false);
}

/// Fail closed: a folder the scan can't read is not reported as clean.
#[cfg(unix)]
#[test]
fn unreadable_directory_is_incomplete_not_clean() {
    use std::os::unix::fs::PermissionsExt;
    let t = Tmp::new("unreadable");
    let d = t.join("repo");
    write(&d.join("ok.txt"), "x\n");
    let locked = d.join("locked");
    fs::create_dir_all(&locked).unwrap();
    write(&locked.join("x.js"), "1\n");
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o000)).unwrap();
    if fs::read_dir(&locked).is_ok() {
        // running as root: permissions don't apply
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o755)).unwrap();
        eprintln!("skipped: root can read anything");
        return;
    }
    let o = guard(&["scan", &s(&d)]).home(&t.join("home")).run();
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(o.code, 3, "{}", o.shown_all());
    assert!(o.stdout.contains("RESULT: INCOMPLETE"), "{}", o.stdout);
    assert!(!o.stdout.contains("RESULT: clean"));
}
