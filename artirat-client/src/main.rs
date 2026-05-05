#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]
use anyhow::Result;
mod lib;

/// Actual binary entrypoint (thin wrapper)
#[tokio::main]
async fn main() -> Result<()> {
    lib::netclient().await?;
    Ok(())
}