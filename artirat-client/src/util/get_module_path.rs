#[cfg(target_os = "windows")]
pub fn get_module_path() -> String {
    use std::ptr;
    use winapi::um::libloaderapi::{GetModuleHandleExW, GetModuleFileNameW};
    use winapi::um::libloaderapi::GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS;
    unsafe {
        let mut hmodule = ptr::null_mut();
        if GetModuleHandleExW(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
            get_module_path as *const () as *const u16,
            &mut hmodule,
        ) == 0 {
            return String::new();
        }
        let mut path = [0u16; winapi::shared::minwindef::MAX_PATH as usize];
        let len = GetModuleFileNameW(hmodule, path.as_mut_ptr(), winapi::shared::minwindef::MAX_PATH as u32);
        if len > 0 {
            String::from_utf16_lossy(&path[..len as usize])
        } else {
            String::new()
        }
    }
}

#[cfg(unix)]
pub fn get_module_path() -> String {
    unsafe {
        let mut info = std::mem::zeroed::<libc::Dl_info>();
        if libc::dladdr(get_module_path as *const libc::c_void, &mut info) != 0 {
            let s = std::ffi::CStr::from_ptr(info.dli_fname);
            s.to_string_lossy().to_string()
        } else {
            String::new()
        }
    }
}
