//! `guard install` / `guard uninstall`: the auto-start service, ported from guard.py.
//!
//! Linux: a systemd unit running `guard watch` as root out of /var/lib/guard.
//! macOS: a per-user LaunchAgent in the GUI session (so TCC can show its Allow
//! prompts); it seeds ~/.guard itself on first run. Windows: guard.ps1 registers
//! the scheduled task and uninstall deletes it. The unit and plist text match
//! what guard.py wrote, so an install from either build looks the same to the OS.

use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde_json::{json, Value};

use crate::{pyjson, util, VERSION};

#[cfg(unix)]
pub const LAUNCHD_LABEL: &str = "me.syedbipul.guard";

/// System paths, under $GUARD_INSTALL_PREFIX when set (tests install into a
/// scratch directory with it).
fn sys_path(p: &str) -> PathBuf {
    match std::env::var_os("GUARD_INSTALL_PREFIX") {
        Some(prefix) => PathBuf::from(prefix).join(p.trim_start_matches('/')),
        None => PathBuf::from(p),
    }
}

#[cfg(unix)]
fn launchd_plist() -> PathBuf {
    sys_path(&format!("/Library/LaunchDaemons/{LAUNCHD_LABEL}.plist")) // legacy root daemon
}
#[cfg(unix)]
fn launchagent_plist() -> PathBuf {
    sys_path(&format!("/Library/LaunchAgents/{LAUNCHD_LABEL}.plist")) // per-user, GUI session
}
fn systemd_unit() -> PathBuf {
    sys_path("/etc/systemd/system/guard.service")
}

fn sudo_user() -> Option<String> {
    std::env::var("SUDO_USER").ok().filter(|u| !u.is_empty())
}

fn write_json(path: &Path, v: &Value) -> std::io::Result<()> {
    util::write_text(path, &pyjson::dumps(v, Some(2), false))
}

/// Who installed Guard and when (scoping for incident response, not blame).
fn write_install_stamp(home: &Path) {
    let who = sudo_user().or_else(util::username);
    let _ = fs::create_dir_all(home).and_then(|_| {
        write_json(
            &home.join("install.json"),
            &json!({"installed_by": who, "installed_at": util::now_iso(), "version": VERSION}),
        )
    });
}

/// Under sudo the daemon runs as root: point its watch roots at the real user's
/// home so it sees the developer's projects.
fn write_watch_config(home: &Path) {
    let Some(user) = sudo_user().filter(|u| u != "root") else {
        return;
    };
    let cfg_path = home.join("watcher.config.json");
    if cfg_path.exists() {
        return; // don't clobber a tuned config
    }
    let userhome = util::home_of(&user).map(|p| p.display().to_string());
    let userhome = userhome.unwrap_or_else(|| {
        if cfg!(target_os = "macos") {
            format!("/Users/{user}")
        } else {
            format!("/home/{user}")
        }
    });
    let roots: Vec<String> = [
        "Projects",
        "code",
        "src",
        "Desktop",
        "Downloads",
        "Documents",
    ]
    .iter()
    .map(|d| format!("{userhome}/{d}"))
    .collect();
    let _ = fs::create_dir_all(home)
        .and_then(|_| write_json(&cfg_path, &json!({"watch_roots": roots})));
}

/// The path a service unit launches.
fn self_exe() -> String {
    std::env::current_exe()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| "guard".into())
}

/// subprocess.call: run, inherit output, return the exit code.
fn call(args: &[&str]) -> Result<i32, String> {
    Command::new(args[0])
        .args(&args[1..])
        .status()
        .map(|s| s.code().unwrap_or(1))
        .map_err(|e| format!("{}: {e}", args[0]))
}

fn write_or_needs_root(path: &Path, text: &str) -> Result<bool, String> {
    if let Some(dir) = path.parent() {
        if std::env::var_os("GUARD_INSTALL_PREFIX").is_some() {
            let _ = fs::create_dir_all(dir);
        }
    }
    match fs::write(path, text) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == ErrorKind::PermissionDenied => {
            eprintln!("guard install needs root (run with sudo)");
            Ok(false)
        }
        Err(e) => Err(format!("{}: {e}", path.display())),
    }
}

#[cfg(unix)]
fn target_user_uid() -> (String, u32) {
    let user = sudo_user()
        .or_else(util::username)
        .unwrap_or_else(|| "root".into());
    let uid = util::unix::by_name(&user)
        .map(|p| p.uid)
        .unwrap_or_else(|| unsafe { libc::getuid() });
    (user, uid)
}

#[cfg(unix)]
fn install_macos(uninstall: bool) -> Result<u8, String> {
    let (user, uid) = target_user_uid();
    let (agent, daemon) = (launchagent_plist(), launchd_plist());
    let (agent_s, daemon_s) = (agent.display().to_string(), daemon.display().to_string());
    let gui = format!("gui/{uid}");
    if uninstall {
        call(&["launchctl", "bootout", &gui, &agent_s])?;
        call(&["launchctl", "bootout", "system", &daemon_s])?; // legacy
        let _ = fs::remove_file(&agent);
        let _ = fs::remove_file(&daemon);
        println!("guard: launch agent removed");
        return Ok(0);
    }
    let exe = self_exe();
    let plist = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>{LAUNCHD_LABEL}</string>
  <key>ProgramArguments</key><array><string>{exe}</string><string>watch</string></array>
  <key>RunAtLoad</key><true/><key>KeepAlive</key><true/>
  <key>ProcessType</key><string>Background</string>
  <key>LimitLoadToSessionType</key><string>Aqua</string>
</dict></plist>"#
    );
    if !write_or_needs_root(&agent, &plist)? {
        return Ok(1);
    }
    // remove any legacy root daemon so two watchers don't run
    call(&["launchctl", "bootout", "system", &daemon_s])?;
    if daemon.exists() {
        let _ = fs::remove_file(&daemon);
    }
    // If reloading: bootout returns before a running agent has stopped, and
    // bootstrapping it again meanwhile fails ("5: Input/output error"), so retry.
    call(&["launchctl", "bootout", &gui, &agent_s])?;
    let mut rc = call(&["launchctl", "bootstrap", &gui, &agent_s])?;
    for _ in 0..10 {
        if rc == 0 {
            break;
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
        rc = call(&["launchctl", "bootstrap", &gui, &agent_s])?;
    }
    println!("guard: launch agent installed ({agent_s}); runs '{exe} watch' as {user} at login.");
    println!("guard: on first run an 'Allow' prompt appears for Desktop/Documents/Downloads and removable disks — click Allow.");
    println!("guard: for full internal+removable coverage in one grant, enable Full Disk Access for 'guard' (guard permissions open-settings).");
    if rc != 0 {
        println!("guard: (agent will also start at next login if bootstrap was deferred)");
    }
    Ok(0)
}

fn install_linux(uninstall: bool) -> Result<u8, String> {
    let unit_path = systemd_unit();
    let unit_s = unit_path.display().to_string();
    if uninstall {
        call(&["systemctl", "disable", "--now", "guard.service"])?;
        let _ = fs::remove_file(&unit_path);
        call(&["systemctl", "daemon-reload"])?;
        println!("guard: systemd service removed");
        return Ok(0);
    }
    let home = std::env::var("GUARD_HOME").unwrap_or_else(|_| "/var/lib/guard".into());
    fs::create_dir_all(&home).map_err(|e| format!("{home}: {e}"))?;
    let exe = self_exe();
    let unit = format!(
        "[Unit]
Description=Guard supply-chain watcher
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
Environment=GUARD_HOME={home}
ExecStart={exe} watch
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
"
    );
    if !write_or_needs_root(&unit_path, &unit)? {
        return Ok(1);
    }
    call(&["systemctl", "daemon-reload"])?;
    let rc = call(&["systemctl", "enable", "--now", "guard.service"])?;
    println!("guard: systemd service installed ({unit_s}); runs '{exe} watch' at boot");
    Ok(if rc == 0 { 0 } else { (rc & 0xff) as u8 })
}

/// Take the installing user's global git hooks out too (`guard hooks
/// uninstall`, as that user: the hooks and git config are theirs).
fn remove_git_hooks() {
    if std::env::var_os("GUARD_INSTALL_PREFIX").is_some() {
        return; // tests: never touch the real git config
    }
    let exe = self_exe();
    let mut c = match sudo_user().filter(|u| u != "root") {
        #[cfg(unix)]
        Some(user) if unsafe { libc::geteuid() } == 0 => {
            let mut c = Command::new("sudo");
            c.args(["-u", &user, "-H", &exe]);
            c
        }
        _ => Command::new(&exe),
    };
    let _ = c.args(["hooks", "uninstall"]).stdout(Stdio::null()).stderr(Stdio::null()).status();
}

pub fn run(uninstall: bool) -> Result<u8, String> {
    let macos = cfg!(target_os = "macos");
    if uninstall {
        remove_git_hooks();
    }
    if !uninstall && !macos {
        // Linux/Windows: the service runs as root/SYSTEM out of /var/lib/guard,
        // so seed its state now. macOS seeds the user's ~/.guard on first run.
        let home = util::service_home();
        write_install_stamp(&home);
        write_watch_config(&home);
    }
    #[cfg(unix)]
    if macos {
        return install_macos(uninstall);
    }
    if cfg!(target_os = "linux") {
        return install_linux(uninstall);
    }
    if cfg!(windows) {
        if uninstall {
            // guard.ps1 registered it; the binary stays, as on Linux and macOS
            call(&["schtasks", "/End", "/TN", "GuardWatcher"])?;
            // the per-user force-push watchdog; older installs don't have it
            for args in [&["/End", "/TN", "GuardGitHubWatch"][..], &["/Delete", "/TN", "GuardGitHubWatch", "/F"]] {
                let _ = Command::new("schtasks").args(args).stdout(Stdio::null()).stderr(Stdio::null()).status();
            }
            let rc = call(&["schtasks", "/Delete", "/TN", "GuardWatcher", "/F"])?;
            if rc != 0 {
                eprintln!("guard: could not remove the GuardWatcher task (not installed, or not an elevated prompt)");
                return Ok(1);
            }
            println!("guard: GuardWatcher scheduled task removed");
            return Ok(0);
        }
        println!("Windows: install via guard.ps1 (it registers the GuardWatcher scheduled task).");
        return Ok(0);
    }
    eprintln!("unsupported platform: {}", std::env::consts::OS);
    Ok(2)
}
