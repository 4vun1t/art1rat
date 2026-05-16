use std::time::Duration;
use tokio::net::TcpStream;

const TIMEOUT_SECS: u64 = 3;
const CONCURRENT: usize = 200;

pub const COMMON_PORTS: &[u16] = &[
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1433, 1521, 2049,
    3306, 3389, 5432, 5900, 5985, 5986, 6379, 8080, 8443, 27017,
];

pub async fn scan_tcp(host: &str, ports: &[u16]) -> Vec<u16> {
    let host = host.to_string();
    let mut open = Vec::new();

    for chunk in ports.chunks(CONCURRENT) {
        let mut tasks = Vec::with_capacity(chunk.len());
        for &port in chunk {
            let h = host.clone();
            tasks.push(tokio::spawn(async move {
                let addr = format!("{}:{}", h, port);
                TcpStream::connect(&addr).await.is_ok().then_some(port)
            }));
        }
        for task in tasks {
            if let Ok(Some(p)) = task.await {
                open.push(p);
            }
        }
    }

    open.sort();
    open
}

pub async fn scan_udp(host: &str, ports: &[u16]) -> Vec<u16> {
    let host = host.to_string();
    let mut open = Vec::new();

    for chunk in ports.chunks(CONCURRENT) {
        let mut tasks = Vec::with_capacity(chunk.len());
        for &port in chunk {
            let h = host.clone();
            tasks.push(tokio::spawn(async move {
                check_udp(&h, port).await
            }));
        }
        for task in tasks {
            if let Ok(Some(p)) = task.await {
                open.push(p);
            }
        }
    }

    open.sort();
    open
}

async fn check_udp(host: &str, port: u16) -> Option<u16> {
    use tokio::net::UdpSocket;
    use tokio::time::timeout;

    let addr = format!("{}:{}", host, port);
    let socket = UdpSocket::bind("0.0.0.0:0").await.ok()?;
    socket.connect(&addr).await.ok()?;
    socket.send(&[0x00]).await.ok()?;

    let mut buf = [0u8; 1];
    match timeout(Duration::from_secs(TIMEOUT_SECS), socket.recv(&mut buf)).await {
        Ok(Ok(_)) => Some(port),
        Ok(Err(ref e)) if e.kind() == std::io::ErrorKind::ConnectionRefused => None,
        _ => Some(port),
    }
}

#[cfg(unix)]
pub async fn scan_sctp(host: &str, ports: &[u16]) -> Vec<u16> {
    let host = host.to_string();
    let ports = ports.to_vec();

    tokio::task::spawn_blocking(move || {
        let mut open = Vec::new();
        let ip = resolve_host(&host);
        if ip.is_none() {
            return open;
        }
        let ip = ip.unwrap();

        for chunk in ports.chunks(CONCURRENT) {
            let mut handles = Vec::new();
            for &port in chunk {
                let ip = ip;
                handles.push(std::thread::spawn(move || {
                    sctp_connect(ip, port)
                }));
            }
            for h in handles {
                if let Ok(Some(p)) = h.join() {
                    open.push(p);
                }
            }
        }

        open.sort();
        open
    }).await.unwrap_or_default()
}

#[cfg(unix)]
fn resolve_host(host: &str) -> Option<std::net::IpAddr> {
    use std::net::ToSocketAddrs;
    (host, 0).to_socket_addrs()
        .ok()?
        .next()
        .map(|a| a.ip())
}

#[cfg(unix)]
fn sctp_connect(ip: std::net::IpAddr, port: u16) -> Option<u16> {
    let domain = match ip {
        std::net::IpAddr::V4(_) => libc::AF_INET,
        std::net::IpAddr::V6(_) => libc::AF_INET6,
    };

    let fd = unsafe { libc::socket(domain, libc::SOCK_STREAM, libc::IPPROTO_SCTP) };
    if fd < 0 {
        return None;
    }

    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL, 0);
        libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
    }

    let sa = make_sockaddr(ip, port);
    let ret = unsafe {
        libc::connect(fd, &sa as *const _ as *const libc::sockaddr, sa.len() as u32)
    };

    let ok = if ret == 0 {
        true
    } else {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::EINPROGRESS) {
            poll_connect(fd, Duration::from_secs(TIMEOUT_SECS))
        } else {
            false
        }
    };

    unsafe { libc::close(fd); }
    ok.then_some(port)
}

#[cfg(unix)]
fn make_sockaddr(ip: std::net::IpAddr, port: u16) -> libc::sockaddr_storage {
    use std::mem;
    let mut storage: libc::sockaddr_storage = unsafe { mem::zeroed() };
    match ip {
        std::net::IpAddr::V4(v4) => {
            let sa = libc::sockaddr_in {
                sin_family: libc::AF_INET as u16,
                sin_port: port.to_be(),
                sin_addr: libc::in_addr { s_addr: u32::from(v4).to_be() },
                sin_zero: [0u8; 8],
            };
            unsafe {
                std::ptr::write_unaligned(&mut storage as *mut _ as *mut libc::sockaddr_in, sa);
            }
        }
        std::net::IpAddr::V6(v6) => {
            let sa = libc::sockaddr_in6 {
                sin6_family: libc::AF_INET6 as u16,
                sin6_port: port.to_be(),
                sin6_flowinfo: 0,
                sin6_addr: libc::in6_addr { s6_addr: v6.octets() },
                sin6_scope_id: 0,
            };
            unsafe {
                std::ptr::write_unaligned(&mut storage as *mut _ as *mut libc::sockaddr_in6, sa);
            }
        }
    }
    storage
}

#[cfg(unix)]
fn poll_connect(fd: libc::c_int, timeout: Duration) -> bool {
    let mut pfd = libc::pollfd {
        fd,
        events: libc::POLLOUT,
        revents: 0,
    };

    let ms = timeout.as_millis().min(i32::MAX as u128) as i32;
    let ret = unsafe { libc::poll(&mut pfd, 1, ms) };

    if ret > 0 && (pfd.revents & libc::POLLOUT) != 0 {
        let mut err: libc::c_int = 0;
        let mut err_len = std::mem::size_of::<libc::c_int>() as u32;
        let r = unsafe {
            libc::getsockopt(fd, libc::SOL_SOCKET, libc::SO_ERROR, &mut err as *mut _ as *mut _, &mut err_len)
        };
        r == 0 && err == 0
    } else {
        false
    }
}
