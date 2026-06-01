#[cfg(target_os = "windows")]
use encstr::astr;
#[cfg(target_os = "windows")]
use std::ptr;
#[cfg(target_os = "windows")]
use winapi::shared::minwindef::HMODULE;
#[cfg(target_os = "windows")]
use winapi::um::libloaderapi::GetModuleFileNameW;
#[cfg(target_os = "windows")]
use winapi::um::libloaderapi::GetModuleHandleExW;

pub fn is_dll() -> bool {
    #[cfg(target_os = "windows")]
    {
        unsafe {
            let mut hmodule: HMODULE = ptr::null_mut();
            if GetModuleHandleExW(
                winapi::um::libloaderapi::GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
                is_dll as *const () as *const u16,
                &mut hmodule,
            ) == 0
            {
                return false;
            }
            let mut path = [0u16; winapi::shared::minwindef::MAX_PATH as usize];
            let len = GetModuleFileNameW(
                hmodule,
                path.as_mut_ptr(),
                winapi::shared::minwindef::MAX_PATH as u32,
            );
            if len == 0 {
                return false;
            }
            let s = String::from_utf16_lossy(&path[..len as usize]);
            let ext = astr!(".dll");
            s.to_lowercase().ends_with(&ext)
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        false
    }
}
