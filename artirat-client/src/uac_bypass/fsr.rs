#[cfg(target_os = "windows")]
use winapi::shared::minwindef::BOOL;
use winapi::shared::ntdef::PVOID;
use winapi::um::wow64apiset::{
    Wow64DisableWow64FsRedirection,
    Wow64RevertWow64FsRedirection,
};
use std::ptr::null_mut;

pub struct DisableFsRedirection {
    old_value: PVOID,
    active: bool,
}

impl DisableFsRedirection {
    pub fn new() -> Self {
        unsafe {
            let mut old: PVOID = null_mut();
            let ok: BOOL = Wow64DisableWow64FsRedirection(&mut old);
            Self {
                old_value: old,
                active: ok != 0,
            }
        }
    }
}

impl Drop for DisableFsRedirection {
    fn drop(&mut self) {
        if self.active {
            unsafe {
                Wow64RevertWow64FsRedirection(self.old_value);
            }
        }
    }
}