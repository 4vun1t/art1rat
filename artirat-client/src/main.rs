#![windows_subsystem = "windows"]

use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    artirat_client::netclient().await;
    Ok(())
}
