//! Desktop threat alerts: the Rust port of notifier.py.
//!
//! Windows: a toast notification (Action Center), the way Defender reports a
//! threat, so nothing has to be clicked away. The watcher runs as SYSTEM in
//! session 0, which the logged-in user never sees, so the toast is raised by a
//! hidden Windows PowerShell started in the active console session with the
//! user's token. Clicking it opens the watcher log. When toasts are unavailable
//! (no WinRT, notifications turned off for PowerShell, no user token) it falls
//! back to the old alert box through WTSSendMessageW, then msg.exe. Setting
//! `GUARD_NOTIFY_STYLE=modal` (or `"notify_style": "modal"` in
//! watcher.config.json) keeps the alert box.
//! macOS: a Notification Center banner via osascript (the watcher is a per-user
//! LaunchAgent). Linux: notify-send.
//! notify() never fails loudly; a missing alert must not take down the watcher.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

pub fn notify(title: &str, message: &str) -> bool {
    alert(title, message, None, modal_style(None))
}

/// notify() with a file the Windows toast opens when clicked (the watcher log),
/// and `modal` to show the old alert box instead of a toast.
pub fn alert(title: &str, message: &str, open: Option<&Path>, modal: bool) -> bool {
    if cfg!(windows) {
        notify_windows(title, message, open, modal)
    } else if cfg!(target_os = "macos") {
        let t = title.replace('"', "'");
        let m = message.replace('"', "'").replace('\n', " ");
        let script =
            format!("display notification \"{m}\" with title \"{t}\" sound name \"Basso\"");
        run(Command::new("osascript").args(["-e", &script]))
    } else {
        let Some(exe) = crate::util::which("notify-send") else {
            return false;
        };
        run(Command::new(exe).args(["-u", "critical", "-a", "Guard", title, message]))
    }
}

/// alert() without holding up a scan: on Windows on its own thread, since
/// starting PowerShell for the toast takes a second or two. osascript and
/// notify-send return at once, so they still run in line.
pub fn alert_in_background(title: String, message: String, open: Option<PathBuf>, modal: bool) {
    if !cfg!(windows) {
        alert(&title, &message, open.as_deref(), modal);
        return;
    }
    let _ = std::thread::Builder::new()
        .name("guard-notify".into())
        .spawn(move || alert(&title, &message, open.as_deref(), modal));
}

/// The old blocking alert box was asked for: `notify_style` from the watcher
/// config, else the GUARD_NOTIFY_STYLE environment variable.
pub fn modal_style(configured: Option<&str>) -> bool {
    let env = std::env::var("GUARD_NOTIFY_STYLE").ok();
    configured
        .or(env.as_deref())
        .is_some_and(|s| s.trim().eq_ignore_ascii_case("modal"))
}

/// subprocess.run(..., timeout=10): true if it ran (any exit code) in time.
fn run(cmd: &mut Command) -> bool {
    run_code(cmd).is_some()
}

/// The exit code, or None when it could not start or ran past 10 seconds.
fn run_code(cmd: &mut Command) -> Option<i32> {
    let Ok(mut child) = cmd.stdin(Stdio::null()).spawn() else {
        return None;
    };
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Some(status.code().unwrap_or(-1)),
            Ok(None) if std::time::Instant::now() < deadline => {
                std::thread::sleep(std::time::Duration::from_millis(20))
            }
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    }
}

/// The toast's XML and the PowerShell that shows it: plain text, so the tests
/// check them on every platform.
#[cfg(any(windows, test))]
mod toast {
    use base64::Engine;

    /// Windows PowerShell's AppUserModelID. An unpackaged program may only raise
    /// toasts under a registered one, and this one comes with every Windows
    /// 10/11 install, so Guard needs no Start-menu shortcut of its own.
    pub const AUMID: &str =
        r"{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe";

    /// Exit code of the script when Windows has notifications from PowerShell
    /// turned off (by the user or a group policy): the alert box is used then.
    pub const DISABLED: i32 = 2;

    pub fn xml_escape(s: &str) -> String {
        let mut out = String::with_capacity(s.len());
        for c in s.chars() {
            match c {
                '&' => out.push_str("&amp;"),
                '<' => out.push_str("&lt;"),
                '>' => out.push_str("&gt;"),
                '"' => out.push_str("&quot;"),
                '\'' => out.push_str("&apos;"),
                // not allowed in XML 1.0; LoadXml would reject the whole toast
                c if (c as u32) < 0x20 && !matches!(c, '\t' | '\n' | '\r') => out.push(' '),
                c => out.push(c),
            }
        }
        out
    }

    /// file:/// URI for a Windows path (C:\x y\a.log -> file:///C:/x%20y/a.log,
    /// \\server\share\a.log -> file://server/share/a.log).
    pub fn file_uri(path: &str) -> String {
        let p = path.strip_prefix(r"\\?\").unwrap_or(path);
        let (prefix, rest) = match p.strip_prefix(r"\\") {
            Some(unc) => ("file://", unc),
            None => ("file:///", p),
        };
        let mut out = String::from(prefix);
        for b in rest.replace('\\', "/").bytes() {
            match b {
                b'A'..=b'Z'
                | b'a'..=b'z'
                | b'0'..=b'9'
                | b'-'
                | b'.'
                | b'_'
                | b'~'
                | b'/'
                | b':' => out.push(b as char),
                _ => out.push_str(&format!("%{b:02X}")),
            }
        }
        out
    }

    /// A ToastGeneric toast: the title, the message, and the path from the
    /// message's second line on its own line. Clicking it (or "Open log") opens
    /// `open` in its default app; the infected folder itself is never opened.
    pub fn toast_xml(title: &str, message: &str, open: Option<&str>) -> String {
        let (body, path) = match message.split_once('\n') {
            Some((b, p)) => (b, Some(p)),
            None => (message, None),
        };
        let uri = open.map(|o| xml_escape(&file_uri(o)));
        let mut x = String::from("<toast duration=\"long\"");
        if let Some(u) = &uri {
            x.push_str(&format!(" activationType=\"protocol\" launch=\"{u}\""));
        }
        x.push_str("><visual><binding template=\"ToastGeneric\">");
        x.push_str(&format!("<text>{}</text>", xml_escape(title)));
        x.push_str(&format!("<text>{}</text>", xml_escape(body)));
        if let Some(p) = path.filter(|p| !p.trim().is_empty()) {
            x.push_str(&format!("<text>{}</text>", xml_escape(p)));
        }
        x.push_str("</binding></visual>");
        if let Some(u) = &uri {
            x.push_str(&format!(
                "<actions><action content=\"Open log\" activationType=\"protocol\" arguments=\"{u}\"/></actions>"
            ));
        }
        x.push_str("<audio src=\"ms-winsoundevent:Notification.Default\"/></toast>");
        x
    }

    /// Windows PowerShell 5.1 script that shows the toast: exit 0 once shown,
    /// DISABLED when notifications are off, 1 when the WinRT types are missing
    /// (Server Core, Constrained Language mode) or anything else fails.
    pub fn script(xml: &str) -> String {
        let q = |s: &str| s.replace('\'', "''");
        format!(
            "$ErrorActionPreference = 'Stop'\n\
             try {{\n\
             \x20 $null = [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime]\n\
             \x20 $null = [Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime]\n\
             \x20 $notifier = [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('{aumid}')\n\
             \x20 $setting = try {{ $notifier.Setting }} catch {{ $null }}\n\
             \x20 if ($null -ne $setting -and \"$setting\" -ne 'Enabled') {{ exit {disabled} }}\n\
             \x20 $xml = New-Object Windows.Data.Xml.Dom.XmlDocument\n\
             \x20 $xml.LoadXml('{xml}')\n\
             \x20 $notifier.Show([Windows.UI.Notifications.ToastNotification]::new($xml))\n\
             \x20 exit 0\n\
             }} catch {{ exit 1 }}\n",
            aumid = q(AUMID),
            disabled = DISABLED,
            xml = q(xml),
        )
    }

    /// Windows PowerShell itself: pwsh 7 dropped the WinRT type projection.
    pub fn powershell_exe(system_root: Option<&str>) -> String {
        let root = system_root
            .filter(|r| !r.is_empty())
            .unwrap_or(r"C:\Windows");
        format!(
            r"{}\System32\WindowsPowerShell\v1.0\powershell.exe",
            root.trim_end_matches('\\')
        )
    }

    /// The arguments: the script as -EncodedCommand (base64 UTF-16LE), so no
    /// title, message or path needs command-line quoting.
    pub fn args(script: &str) -> Vec<String> {
        let utf16: Vec<u8> = script.encode_utf16().flat_map(u16::to_le_bytes).collect();
        let encoded = base64::engine::general_purpose::STANDARD.encode(utf16);
        [
            "-NoProfile",
            "-NonInteractive",
            "-WindowStyle",
            "Hidden",
            "-EncodedCommand",
        ]
        .iter()
        .map(|s| s.to_string())
        .chain([encoded])
        .collect()
    }

    /// The command line CreateProcessAsUserW takes (no argument needs quoting).
    pub fn command_line(exe: &str, args: &[String]) -> String {
        format!("\"{exe}\" {}", args.join(" "))
    }
}

#[cfg(windows)]
fn notify_windows(title: &str, message: &str, open: Option<&Path>, modal: bool) -> bool {
    if !modal && toast_windows(title, message, open) {
        return true;
    }
    message_box_windows(title, message)
}

/// The toast, raised in the active console session. False when it could not be
/// shown, so the caller falls back to the alert box.
#[cfg(windows)]
fn toast_windows(title: &str, message: &str, open: Option<&Path>) -> bool {
    use std::os::windows::process::CommandExt;
    use windows_sys::Win32::System::RemoteDesktop::{
        ProcessIdToSessionId, WTSGetActiveConsoleSessionId,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcessId, CREATE_NO_WINDOW};

    let open = open
        .and_then(|p| std::path::absolute(p).ok())
        .map(|p| p.to_string_lossy().into_owned());
    let script = toast::script(&toast::toast_xml(title, message, open.as_deref()));
    let exe = toast::powershell_exe(std::env::var("SystemRoot").ok().as_deref());
    let args = toast::args(&script);

    let mut own = 0u32;
    // SAFETY: plain Win32 calls with a valid out pointer.
    let (own_ok, console) = unsafe {
        (
            ProcessIdToSessionId(GetCurrentProcessId(), &mut own),
            WTSGetActiveConsoleSessionId(),
        )
    };
    let code = if own_ok != 0 && own != 0 {
        // already on the user's desktop (guard notify-test, the GitHub watchdog)
        run_code(
            Command::new(&exe)
                .args(&args)
                .creation_flags(CREATE_NO_WINDOW),
        )
    } else if console == 0xFFFF_FFFF {
        None // no one at the console
    } else {
        // SAFETY: see spawn_in_session
        unsafe { spawn_in_session(console, &exe, &toast::command_line(&exe, &args)) }
    };
    code == Some(0)
}

/// Runs `cmdline` hidden in `session` as its logged-in user (the watcher is
/// SYSTEM, which may take that user's token) and waits up to 10 seconds for it.
#[cfg(windows)]
unsafe fn spawn_in_session(session: u32, exe: &str, cmdline: &str) -> Option<i32> {
    use windows_sys::Win32::Foundation::{CloseHandle, WAIT_OBJECT_0};
    use windows_sys::Win32::System::Environment::{
        CreateEnvironmentBlock, DestroyEnvironmentBlock,
    };
    use windows_sys::Win32::System::RemoteDesktop::WTSQueryUserToken;
    use windows_sys::Win32::System::Threading::{
        CreateProcessAsUserW, GetExitCodeProcess, TerminateProcess, WaitForSingleObject,
        CREATE_NO_WINDOW, CREATE_UNICODE_ENVIRONMENT, PROCESS_INFORMATION, STARTUPINFOW,
    };
    let wide = |s: &str| -> Vec<u16> { s.encode_utf16().chain([0]).collect() };
    // SAFETY: every pointer passed below is to a live local (NUL-terminated
    // UTF-16 where a string is expected); each handle is closed exactly once.
    unsafe {
        let mut token = std::ptr::null_mut();
        if WTSQueryUserToken(session, &mut token) == 0 {
            return None;
        }
        let mut env = std::ptr::null_mut();
        let have_env = CreateEnvironmentBlock(&mut env, token, 0) != 0;
        let app = wide(exe);
        let mut cmd = wide(cmdline); // CreateProcessW may write to it
        let mut desktop = wide(r"winsta0\default");
        let mut si: STARTUPINFOW = std::mem::zeroed();
        si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
        si.lpDesktop = desktop.as_mut_ptr();
        let mut pi: PROCESS_INFORMATION = std::mem::zeroed();
        let flags = CREATE_NO_WINDOW
            | if have_env {
                CREATE_UNICODE_ENVIRONMENT
            } else {
                0
            };
        let ok = CreateProcessAsUserW(
            token,
            app.as_ptr(),
            cmd.as_mut_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            0,
            flags,
            if have_env { env } else { std::ptr::null() },
            std::ptr::null(),
            &si,
            &mut pi,
        );
        if have_env {
            DestroyEnvironmentBlock(env);
        }
        CloseHandle(token);
        if ok == 0 {
            return None;
        }
        CloseHandle(pi.hThread);
        let code = if WaitForSingleObject(pi.hProcess, 10_000) == WAIT_OBJECT_0 {
            let mut c = 1u32;
            GetExitCodeProcess(pi.hProcess, &mut c);
            Some(c as i32)
        } else {
            TerminateProcess(pi.hProcess, 1);
            None
        };
        CloseHandle(pi.hProcess);
        code
    }
}

/// The old alert box in the active console session (needs an OK click).
#[cfg(windows)]
fn message_box_windows(title: &str, message: &str) -> bool {
    use windows_sys::Win32::System::RemoteDesktop::{
        WTSGetActiveConsoleSessionId, WTSSendMessageW,
    };
    const MB_ICONWARNING: u32 = 0x0000_0030;
    const MB_SETFOREGROUND: u32 = 0x0001_0000;
    const MB_TOPMOST: u32 = 0x0004_0000;
    // SAFETY: plain Win32 calls with valid, NUL-terminated UTF-16 buffers that
    // outlive them; bWait = FALSE so the call doesn't block on the user.
    unsafe {
        let session = WTSGetActiveConsoleSessionId();
        if session == 0xFFFF_FFFF {
            return notify_windows_msg(title, message); // no one at the console
        }
        let t: Vec<u16> = title.encode_utf16().chain([0]).collect();
        let m: Vec<u16> = message.encode_utf16().chain([0]).collect();
        let mut response = 0i32;
        let ok = WTSSendMessageW(
            std::ptr::null_mut(), // WTS_CURRENT_SERVER_HANDLE
            session,
            t.as_ptr(),
            ((t.len() - 1) * 2) as u32, // bytes, without the NUL
            m.as_ptr(),
            ((m.len() - 1) * 2) as u32,
            MB_ICONWARNING | MB_SETFOREGROUND | MB_TOPMOST,
            0,
            &mut response,
            0,
        );
        if ok == 0 {
            return notify_windows_msg(title, message);
        }
    }
    true
}

#[cfg(windows)]
fn notify_windows_msg(title: &str, message: &str) -> bool {
    let exe = crate::util::which("msg").unwrap_or_else(|| r"C:\Windows\System32\msg.exe".into());
    run(Command::new(exe).args(["*", &format!("{title}: {message}")]))
}

#[cfg(not(windows))]
fn notify_windows(_: &str, _: &str, _: Option<&Path>, _: bool) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::toast::*;
    use base64::Engine;

    const MSG: &str = "Malicious code found in 'node_modules'. 1 critical finding(s). \
                       Do NOT open this folder.\nC:\\Users\\dev\\app\\node_modules";

    /// What PowerShell gets back from -EncodedCommand.
    fn decode(args: &[String]) -> String {
        let raw = base64::engine::general_purpose::STANDARD
            .decode(args.last().unwrap())
            .unwrap();
        let units: Vec<u16> = raw
            .chunks(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        String::from_utf16(&units).unwrap()
    }

    #[test]
    fn toast_carries_title_message_and_path() {
        let x = toast_xml(
            "Guard - Threat detected",
            MSG,
            Some(r"C:\var\lib\guard\watcher.log"),
        );
        assert!(x.starts_with(
            "<toast duration=\"long\" activationType=\"protocol\" \
                               launch=\"file:///C:/var/lib/guard/watcher.log\">"
        ));
        assert!(x.contains("<text>Guard - Threat detected</text>"));
        assert!(x.contains(
            "<text>Malicious code found in &apos;node_modules&apos;. 1 critical finding(s). \
             Do NOT open this folder.</text>"
        ));
        assert!(x.contains(r"<text>C:\Users\dev\app\node_modules</text>"));
        assert!(x.contains(
            "<action content=\"Open log\" activationType=\"protocol\" \
             arguments=\"file:///C:/var/lib/guard/watcher.log\"/>"
        ));
        assert!(x.ends_with("</toast>"));
        // well-formed: every opened tag is closed
        for tag in ["toast", "visual", "binding", "actions"] {
            assert_eq!(x.matches(&format!("<{tag}")).count(), 1, "{tag}");
            assert_eq!(x.matches(&format!("</{tag}>")).count(), 1, "{tag}");
        }
        assert_eq!(x.matches("<text>").count(), 3);
    }

    #[test]
    fn toast_without_a_log_or_a_path() {
        let x = toast_xml(
            "Guard - Allow access again",
            "Run 'guard permissions setup'.",
            None,
        );
        assert!(x.starts_with("<toast duration=\"long\">"));
        assert!(!x.contains("activationType") && !x.contains("<actions>"));
        assert_eq!(x.matches("<text>").count(), 2);
    }

    #[test]
    fn escaping() {
        assert_eq!(
            xml_escape("a<b>&\"c\"'d'\u{1}e\n"),
            "a&lt;b&gt;&amp;&quot;c&quot;&apos;d&apos; e\n"
        );
        let x = toast_xml("t", "x\n</text><script>&", None);
        assert!(x.contains("<text>&lt;/text&gt;&lt;script&gt;&amp;</text>"));
        assert_eq!(
            file_uri(r"C:\Program Data\Guard\watcher.log"),
            "file:///C:/Program%20Data/Guard/watcher.log"
        );
        assert_eq!(
            file_uri(r"\\?\C:\guard\#1\é.log"),
            "file:///C:/guard/%231/%C3%A9.log"
        );
        assert_eq!(
            file_uri(r"\\server\share\watcher.log"),
            "file://server/share/watcher.log"
        );
    }

    #[test]
    fn powershell_script_and_command_line() {
        let xml = toast_xml("Guard - Threat detected", MSG, Some(r"C:\g\watcher.log"));
        let s = script(&xml);
        assert!(s.contains("ContentType = WindowsRuntime"));
        assert!(s.contains(&format!("CreateToastNotifier('{AUMID}')")));
        assert!(s.contains(&format!("exit {DISABLED}")));
        assert!(s.contains(&format!("$xml.LoadXml('{xml}')")));
        assert!(s.contains("} catch { exit 1 }"));
        // the XML holds no quote that would end the PowerShell string early
        assert!(!xml.contains('\''));
        assert_eq!(script("it's").matches("it''s").count(), 1);

        let exe = powershell_exe(Some(r"C:\WINDOWS\"));
        assert_eq!(
            exe,
            r"C:\WINDOWS\System32\WindowsPowerShell\v1.0\powershell.exe"
        );
        assert_eq!(
            powershell_exe(None),
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
        );
        let a = args(&s);
        assert_eq!(
            a[..5],
            [
                "-NoProfile",
                "-NonInteractive",
                "-WindowStyle",
                "Hidden",
                "-EncodedCommand"
            ]
        );
        assert_eq!(decode(&a), s);
        let line = command_line(&exe, &a);
        assert!(line.starts_with(&format!("\"{exe}\" -NoProfile ")));
        assert!(!line[exe.len() + 2..].contains('"'));
        assert!(line.len() < 32_767, "CreateProcess limit");
    }

    #[test]
    fn modal_only_when_asked() {
        // GUARD_NOTIFY_STYLE is unset in the test environment
        if std::env::var_os("GUARD_NOTIFY_STYLE").is_none() {
            assert!(!super::modal_style(None));
        }
        assert!(super::modal_style(Some("modal")));
        assert!(super::modal_style(Some(" Modal ")));
        assert!(!super::modal_style(Some("toast")));
    }
}
