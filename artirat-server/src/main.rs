use std::path::PathBuf;
use anyhow::Result;
use tokio::signal;

use artirat_server::{run_server, host_shell, ServerConfig};

#[tokio::main]
async fn main() -> Result<()> {
    // --- Config ---
    let cfg = ServerConfig {
        data_dir: PathBuf::from("/etc/artirat_config"),
        nickname: "artirat-node".to_string(),
    };

    println!("[*] Starting ArtiRat server...");

    // Run server + shell concurrently
    let server_task = tokio::spawn({
        let cfg = cfg.clone();
        async move {
            if let Err(e) = run_server(cfg).await {
                eprintln!("[!] Server error: {e}");
            }
        }
    });

    let shell_task = tokio::spawn(async move {
        if let Err(e) = run_server(cfg).await {
            eprintln!("[!] Shell error: {e}");
        }
    });

    println!("[*] Server + shell running");
    println!("[*] Press Ctrl+C to exit");

    // Wait for Ctrl+C
    signal::ctrl_c().await?;
    println!("\n[*] Shutting down...");

    // Optional: cancel tasks
    server_task.abort();
    shell_task.abort();

    Ok(())
}