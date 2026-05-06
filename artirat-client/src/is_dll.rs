#[cfg(target_os = "windows")]
use std::ptr::null_mut;
#[cfg(target_os = "windows")]
use winapi::um::libloaderapi::GetModuleHandleExW;
#[cfg(target_os = "windows")]
use winapi::um::winnt::LPCWSTR;

pub fn is_dll() -> bool {
    return false;
}