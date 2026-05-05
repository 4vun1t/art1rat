mod lib;
use anyhow::Result;

/// Actual binary entrypoint (thin wrapper)
#[tokio::main]
async fn main() -> Result<()> {
    let _ = lib::netclient().await?;
    Ok(())
}