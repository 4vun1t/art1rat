#[cfg(target_os = "windows")]
use std::ptr::null_mut;
#[cfg(target_os = "windows")]
use winapi::um::libloaderapi::GetModuleHandleExW;
#[cfg(target_os = "windows")]
use winapi::um::winnt::LPCWSTR;

pub fn is_dll() -> bool {
    #[cfg(target_os = "windows")]

    unsafe {
        let mut handle = null_mut();

        // Try to get module handle of current function
        let result = GetModuleHandleExW(
            0x00000004, // GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS
            is_dll as LPCWSTR,
            &mut handle,
        );

        if result == 0 {
            return false;
        }

        // If we have a module handle, we're inside a DLL or EXE.
        // Distinguishing is trickier → see below
        true
    }
}