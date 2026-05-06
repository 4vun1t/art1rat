use anyhow::Result;

// import your library function
use artirat_server::run_hidden_service;

#[tokio::main]
async fn main() -> Result<()> {
    println!("[*] Starting hidden service...");

    if let Err(e) = run_hidden_service().await {
        eprintln!("[!] Fatal error: {}", e);
    }

    Ok(())
}