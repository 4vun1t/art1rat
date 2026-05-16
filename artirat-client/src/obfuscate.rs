use std::sync::OnceLock;
use std;
pub const XOR_KEY: u8 = 0xAA;

pub const fn xorb<const N: usize>(data: &[u8; N], key: u8) -> [u8; N] {
    let mut out = [0u8; N];
    let mut i = 0;
    while i < N {
        out[i] = data[i] ^ key;
        i += 1;
    }
    out
}

pub fn dec<const N: usize>(data: &[u8; N], key: u8) -> String {
    let mut s = String::with_capacity(N);
    for &b in data {
        s.push((b ^ key) as char);
    }
    s
}

pub fn dec_slice(data: &[u8], key: u8) -> String {
    data.iter().map(|b| (b ^ key) as char).collect()
}

pub struct EncStr<const N: usize> {
    data: [u8; N],
    cache: OnceLock<String>,
}

impl<const N: usize> EncStr<N> {
    pub const fn new(data: [u8; N]) -> Self {
        Self { data, cache: OnceLock::new() }
    }

    pub fn get(&self) -> &str {
        self.cache.get_or_init(|| dec(&self.data, XOR_KEY))
    }
}

pub fn rand_range(min: u64, max: u64) -> u64 {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    min + (nanos as u64) % (max - min + 1)
}

// === Sleep jitter ===

pub fn sleep_jitter(min_ms: u64, max_ms: u64) {
    let delay = rand_range(min_ms, max_ms);
    #[cfg(target_os = "windows")]
    unsafe {
        use std::ffi::CString;
        let ms = delay as i64;
        let mut delay_int: i64 = -(ms * 10000);
        let ntdll = winapi::um::libloaderapi::GetModuleHandleA(
            CString::new(cryptify::encrypt_string!("ntdll.dll")).unwrap().as_ptr(),
        );
        if ntdll.is_null() {
            std::thread::sleep(std::time::Duration::from_millis(delay));
            return;
        }
        let nt_delay = winapi::um::libloaderapi::GetProcAddress(
            ntdll,
            CString::new(cryptify::encrypt_string!("NtDelayExecution")).unwrap().as_ptr(),
        );
        if nt_delay.is_null() {
            std::thread::sleep(std::time::Duration::from_millis(delay));
            return;
        }
        type NtDelayExec = unsafe extern "system" fn(i32, *mut i64) -> i32;
        let func: NtDelayExec = std::mem::transmute(nt_delay);
        func(0, &mut delay_int);
    }
    #[cfg(not(target_os = "windows"))]
    std::thread::sleep(std::time::Duration::from_millis(delay));
}

// === DJB2 hash ===

pub fn hash_name(data: &[u8]) -> u32 {
    let mut h: u32 = 5381;
    for &b in data {
        h = h.wrapping_mul(33).wrapping_add(b as u32);
    }
    h
}

pub fn opaque_true() -> bool {
    let x: u64 = 0x1234567890ABCDEF;
    let y: u64 = 0xFEDCBA0987654321;
    (x ^ y) > 0
}

pub fn opaque_false() -> bool {
    let x: u64 = 0x1234567890ABCDEF;
    let y: u64 = 0xFEDCBA0987654321;
    (x & y) == 0
}
fn random_int(min: u64, max: u64) -> u64 {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    min + (nanos as u64) % (max - min + 1)
}

pub fn sleep_jitter_range(min_ms: u64, max_ms: u64) {
    for _ in 0..1 {
        if opaque_true() {
            let _junk = opaque_false();
            sleep_jitter(min_ms, max_ms);
        }
    }
}

pub fn sleep_jitter_default() {
    let min_ms = random_int(3, 18);                                                                     
    let max_ms = random_int(27, 120);                                                         
    println!("{}\t{} ms", cryptify::encrypt_string!("Minimum sleep time"), min_ms);
    println!("{}\t{} ms", cryptify::encrypt_string!("Maximum sleep time"), max_ms);

    let _ = sleep_jitter_range(min_ms,max_ms);
}
