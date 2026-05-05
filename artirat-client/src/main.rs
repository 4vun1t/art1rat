mod lib;
use anyhow::Result;

/// Actual binary entrypoint (thin wrapper)
#[tokio::main]
async fn main() -> Result<()> {
    lib::netclient().await?;
    Ok(())
}