#![windows_subsystem = "windows"]

mod lib;
use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    lib::netclient().await;
    Ok(())
}
