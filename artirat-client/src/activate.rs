use encstr::astr;
use std::path::Path;
use std::process::Command;

#[cfg(target_os = "windows")]
use std::os::windows::process::CommandExt;

#[cfg(target_os = "windows")]
const CREATE_NO_WINDOW: u32 = 0x08000000;

fn get_windir() -> String {
    std::env::var(astr!("windir")).unwrap_or_else(|_| astr!("C:\\Windows").to_string())
}

fn slmgr_path() -> String {
    format!("{}\\system32\\slmgr.vbs", get_windir())
}

fn hide_window(cmd: &mut Command) -> &mut Command {
    #[cfg(target_os = "windows")]
    {
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    cmd
}

fn run_slmgr(args: &[&str]) -> Result<(), String> {
    let path = slmgr_path();
    if !Path::new(&path).exists() {
        return Err(astr!("slmgr.vbs not found").to_string());
    }

    let output = hide_window(
        Command::new(astr!("cscript"))
            .args([astr!("//nologo")])
            .arg(&path)
            .args(args),
    )
    .output()
    .map_err(|e| format!("{} {}", astr!("cscript:"), e))?;

    let ok = output.status.success();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    if ok {
        Ok(())
    } else {
        Err(format!("{}{}", stdout, stderr))
    }
}

fn is_home_edition_error(err: &str) -> bool {
    err.contains(astr!("0xC004F015"))
        || err.contains(astr!("0xC004F069"))
        || err.to_lowercase().contains(astr!("not supported"))
        || err.to_lowercase().contains(astr!("home"))
}

fn upgrade_to_pro() -> Result<(), String> {
    let windir = get_windir();

    // Try changepk.exe (available on Windows 10/11)
    let changepk = format!("{}\\system32\\changepk.exe", windir);
    if Path::new(&changepk).exists() {
        let out = hide_window(Command::new(&changepk).args([
            astr!("/ProductKey"),
            astr!("VK7JG-NPHTM-C97JM-9MPGT-3V66T"),
        ]))
        .output()
        .map_err(|e| format!("changepk.exe: {}", e))?;
        if out.status.success() {
            return Ok(());
        }
    }

    // Fallback to DISM (online edition upgrade)
    let dism = format!("{}\\system32\\dism.exe", windir);
    if Path::new(&dism).exists() {
        let out = hide_window(
            Command::new(&dism).args([
                astr!("/online"),
                astr!("/Set-Edition:Professional"),
                astr!("/ProductKey:W269N-WFGWX-YVC9B-4J6C9-T83GX"),
                astr!("/AcceptEula"),
                astr!("/Quiet:0"),
            ]),
        )
        .output()
        .map_err(|e| format!("dism.exe: {}", e))?;
        if out.status.success() {
            return Ok(());
        }
    }

    Err(astr!("upgrade_to_pro: no method succeeded").to_string())
}

pub fn activate_windows_impl() -> Result<(), String> {
    // 1. Install volume license key (Windows 10/11 Professional VLK)
    if let Err(e) = run_slmgr(&[astr!("/ipk"), astr!("W269N-WFGWX-YVC9B-4J6C9-T83GX")]) {
        if is_home_edition_error(&e) {
            // Home edition detected - upgrade to Professional first
            upgrade_to_pro()?;
            // Retry after upgrade
            run_slmgr(&[astr!("/ipk"), astr!("W269N-WFGWX-YVC9B-4J6C9-T83GX")])?;
        } else {
            return Err(e);
        }
    }

    // 2. Set KMS host
    run_slmgr(&[astr!("/skms"), astr!("kms8.msguidea.com")])?;

    // 3. Activate Windows
    run_slmgr(&[astr!("/ato")])?;

    Ok(())
}
