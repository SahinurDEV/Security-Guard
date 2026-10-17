//! macOS access check and "just click Allow" request: the port of permissions.py.
//!
//! Guard only detects what it can read, and macOS (TCC) blocks Desktop,
//! Documents, Downloads and removable volumes until the user allows it. check()
//! reports per location; request() touches each blocked one so macOS shows its
//! Allow dialog (only from the user's GUI session) and opens the Full Disk
//! Access pane if something stays blocked. Elsewhere these are no-ops.

use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::{json, Value};

use crate::pyjson;

pub const FDA_SETTINGS_URL: &str =
    "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles";

/// The human user's home, even under sudo.
fn user_home() -> PathBuf {
    #[cfg(unix)]
    if let Ok(u) = std::env::var("SUDO_USER") {
        if !u.is_empty() && u != "root" {
            if let Some(p) = crate::util::unix::by_name(&u) {
                return p.dir;
            }
        }
    }
    crate::util::user_home()
}

fn internal_targets() -> Vec<PathBuf> {
    let h = user_home();
    vec![h.join("Desktop"), h.join("Documents"), h.join("Downloads")]
}

pub(crate) fn removable_targets() -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Ok(rd) = fs::read_dir("/Volumes") {
        for e in rd.flatten() {
            let v = e.path();
            let is_link = fs::symlink_metadata(&v)
                .map(|m| m.file_type().is_symlink())
                .unwrap_or(false);
            if is_link
                || fs::canonicalize(&v)
                    .map(|r| r == Path::new("/"))
                    .unwrap_or(false)
            {
                continue; // /Volumes/Macintosh HD -> /
            }
            out.push(v);
        }
    }
    out
}

/// Read one entry; in a GUI session this blocks on the TCC dialog the first time.
fn can_read(p: &Path) -> bool {
    match fs::read_dir(p) {
        Ok(mut rd) => {
            let _ = rd.next();
            true
        }
        Err(e) => e.kind() == ErrorKind::NotFound,
    }
}

fn strs(v: &[PathBuf]) -> Vec<String> {
    v.iter().map(|p| p.display().to_string()).collect()
}

pub fn check(targets: Option<Vec<PathBuf>>) -> Value {
    if !cfg!(target_os = "macos") {
        return json!({"ok": true, "blocked": [], "readable": [], "checked": []});
    }
    let tg: Vec<PathBuf> = targets
        .unwrap_or_else(|| [internal_targets(), removable_targets()].concat())
        .into_iter()
        .filter(|p| p.exists())
        .collect();
    let (mut blocked, mut readable) = (Vec::new(), Vec::new());
    for p in &tg {
        if can_read(p) {
            readable.push(p.clone())
        } else {
            blocked.push(p.clone())
        }
    }
    json!({"ok": blocked.is_empty(), "blocked": strs(&blocked), "readable": strs(&readable), "checked": strs(&tg)})
}

pub fn open_fda_settings() {
    match Command::new("open").arg(FDA_SETTINGS_URL).spawn() {
        Ok(_) => println!(
            "guard: opened System Settings -> Privacy & Security -> Full Disk Access. \
             Add and enable 'guard' to allow scanning all internal and removable disks."
        ),
        Err(e) => println!(
            "guard: could not open settings ({e}); enable Full Disk Access for 'guard' manually."
        ),
    }
}

pub fn request(open_settings_if_blocked: bool) -> Value {
    if !cfg!(target_os = "macos") {
        return json!({"ok": true, "prompted": [], "still_blocked": []});
    }
    let targets: Vec<PathBuf> = [internal_targets(), removable_targets()]
        .concat()
        .into_iter()
        .filter(|p| p.exists())
        .collect();
    let prompted: Vec<String> = targets
        .iter()
        .filter(|p| !can_read(p))
        .map(|p| p.display().to_string())
        .collect();
    let res = check(Some(targets));
    let still = res["blocked"].clone();
    let blocked_any = still.as_array().is_some_and(|a| !a.is_empty());
    if blocked_any {
        crate::util::emit(&format!(
            "guard: still blocked after prompt: {}",
            crate::pyrepr::repr(&still)
        ));
        if open_settings_if_blocked {
            open_fda_settings();
        }
    } else {
        crate::util::emit("guard: all watched locations are now readable.");
    }
    json!({"ok": !blocked_any, "prompted": prompted, "still_blocked": still})
}

/// The watcher's own view of its access, written at each start: what this
/// shell can read says nothing about the launchd service, which macOS
/// judges separately.
/// Returns true when Full Disk Access was on at the previous start and is off
/// now: macOS ties the grant to the exact build of an ad-hoc signed binary,
/// so a self-update loses it.
pub fn write_status(home: &Path, blocked: &[String]) -> bool {
    let fda = has_full_disk_access();
    let had = fs::read_to_string(home.join(STATUS_FILE))
        .ok()
        .and_then(|t| serde_json::from_str::<Value>(&t).ok())
        .is_some_and(|v| v["full_disk_access"] == json!(true));
    let rec = json!({
        "checked_at": crate::util::now_iso(),
        "full_disk_access": fda,
        "blocked": blocked,
    });
    let _ = crate::util::write_text(
        &home.join(STATUS_FILE),
        &pyjson::dumps(&rec, Some(2), false),
    );
    had && !fda
}

const STATUS_FILE: &str = "permissions.json";

/// The service has written a status since `since` and has Full Disk Access.
fn service_granted(home: &Path, since: std::time::SystemTime) -> bool {
    let f = home.join(STATUS_FILE);
    let fresh = fs::metadata(&f)
        .and_then(|m| m.modified())
        .is_ok_and(|t| t >= since);
    fresh
        && fs::read_to_string(&f)
            .ok()
            .and_then(|t| serde_json::from_str::<Value>(&t).ok())
            .is_some_and(|v| v["full_disk_access"] == json!(true))
}

/// Restart the watcher so it starts with whatever access macOS now grants.
fn restart_service() {
    #[cfg(unix)]
    {
        let uid = unsafe { libc::getuid() };
        let target = format!("gui/{uid}/{}", crate::install::LAUNCHD_LABEL);
        let _ = Command::new("launchctl")
            .args(["kickstart", "-k", &target])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
    }
}

/// Installer step on macOS: get Full Disk Access for the watcher service, so
/// it can read Downloads, Desktop, Documents and external disks. macOS only
/// lets the user grant it, so this opens the setting, shows the guard binary
/// to switch on, and waits until the service reports the grant.
fn setup(wait_secs: u64) -> u8 {
    if !cfg!(target_os = "macos") {
        println!("guard: nothing to set up here; the Guard service can already read your files.");
        return 0;
    }
    let home = crate::util::guard_home();
    let wait = |since| {
        for _ in 0..10 {
            if service_granted(&home, since) {
                return true;
            }
            std::thread::sleep(std::time::Duration::from_secs(1));
        }
        false
    };
    let since = std::time::SystemTime::now();
    restart_service();
    if wait(since) {
        println!("guard: Full Disk Access is on; the service can read every folder and disk.");
        return 0;
    }
    let exe = std::env::current_exe()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| "guard".into());
    println!("guard: one step left. macOS needs you to allow Guard to read your files:");
    println!("  1. In the Full Disk Access list that just opened, turn on 'guard'.");
    println!(
        "  2. If 'guard' isn't listed, drag it in from the Finder window that opened ({exe})."
    );
    open_fda_settings();
    let _ = Command::new("open").args(["-R", &exe]).status();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(wait_secs);
    println!("guard: waiting for the switch (up to {wait_secs}s)...");
    while std::time::Instant::now() < deadline {
        let since = std::time::SystemTime::now();
        restart_service();
        if wait(since) {
            println!("guard: Full Disk Access is on; the service can read every folder and disk.");
            return 0;
        }
        std::thread::sleep(std::time::Duration::from_secs(5));
    }
    println!(
        "guard: not allowed yet. Guard keeps running but can't read protected folders; \
         finish any time with: guard permissions setup"
    );
    1
}

fn has_full_disk_access() -> bool {
    if !cfg!(target_os = "macos") {
        return true;
    }
    let mut b = [0u8; 1];
    fs::File::open("/Library/Application Support/com.apple.TCC/TCC.db")
        .and_then(|mut f| std::io::Read::read(&mut f, &mut b))
        .is_ok()
}

pub fn main(args: &[String]) -> u8 {
    let action = args
        .first()
        .map(|a| a.to_lowercase())
        .unwrap_or_else(|| "check".into());
    if ["request", "ask", "fix", "allow"].contains(&action.as_str()) {
        let r = request(true);
        println!("{}", pyjson::dumps(&r, Some(2), false));
        return if r["ok"] == json!(true) { 0 } else { 1 };
    }
    if action == "setup" {
        let secs = args.get(1).and_then(|a| a.parse().ok()).unwrap_or(180);
        return setup(secs);
    }
    if ["open-settings", "settings", "fda"].contains(&action.as_str()) {
        open_fda_settings();
        return 0;
    }
    let r = check(None);
    println!("{}", pyjson::dumps(&r, Some(2), false));
    if cfg!(target_os = "macos") {
        println!(
            "full_disk_access: {}",
            if has_full_disk_access() { "yes" } else { "no" }
        );
        if r["blocked"].as_array().is_some_and(|a| !a.is_empty()) {
            println!("hint: run 'guard permissions request' in your login session to get the Allow prompts.");
        }
    }
    if r["ok"] == json!(true) {
        0
    } else {
        1
    }
}
