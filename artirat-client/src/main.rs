#![windows_subsystem = "windows"]
#![allow(special_module_name)]

mod lib;
use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    lib::netclient().await;
    Ok(())
}
