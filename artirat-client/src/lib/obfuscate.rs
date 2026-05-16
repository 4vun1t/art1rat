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
        let ms = delay as i64;
        let mut delay_int: i64 = -(ms * 10000);
        let ntdll = get_module_base(b"ntdll.dll\0");
        if ntdll.is_null() { return; }
        let hash_nn = 0x8a8a00a9u32; // hash("NtDelayExecution")
        let nt_delay = resolve_by_hash(ntdll, hash_nn);
        if nt_delay.is_null() { return; }
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

// === API hashing (Windows) ===

#[cfg(target_os = "windows")]
pub unsafe fn get_peb() -> *mut u8 {
    let peb: *mut u8;
    #[cfg(target_arch = "x86_64")]
    {
        std::arch::asm!("mov {}, gs:[0x60]", out(reg) peb, options(nostack));
    }
    #[cfg(target_arch = "x86")]
    {
        std::arch::asm!("mov {}, fs:[0x30]", out(reg) peb, options(nostack));
    }
    peb
}

#[cfg(target_os = "windows")]
pub unsafe fn get_kernel32_base() -> *mut u8 {
    let peb = get_peb();
    let ldr = *(peb.add(0x18) as *mut *mut u8);
    let first_link = *(ldr.add(0x20) as *mut *mut u8);
    let second_link = *(first_link as *mut *mut u8);
    let third_link = *(second_link as *mut *mut u8);
    let entry_base = (third_link as usize).wrapping_sub(0x20) as *mut u8;
    *(entry_base.add(0x30) as *mut *mut u8)
}

#[cfg(target_os = "windows")]
pub unsafe fn get_module_base(name: &[u8]) -> *mut u8 {
    let peb = get_peb();
    let ldr = *(peb.add(0x18) as *mut *mut u8);
    let first_link = *(ldr.add(0x20) as *mut *mut u8);
    let mut current = first_link;
    loop {
        let entry_start = (current as usize).wrapping_sub(0x20) as *mut u8;
        let dll_base = *(entry_start.add(0x30) as *mut *mut u8);
        let base_name_ptr = entry_start.add(0x60) as *mut *mut u16;
        if !base_name_ptr.is_null() && !(*base_name_ptr).is_null() {
            let mut matches = true;
            let mut j = 0usize;
            while name[j] != 0 && j < 128 {
                let c = *((*base_name_ptr as *mut u16).add(j));
                if (c as u8) != name[j] && (c as u8).to_ascii_lowercase() != name[j] {
                    matches = false;
                    break;
                }
                j += 1;
            }
            if matches && (name[j] == 0 || name[j] == b'.' || name[j] == b'\0') {
                return dll_base;
            }
        }
        current = *(current as *mut *mut u8);
        if current == first_link { break; }
    }
    std::ptr::null_mut()
}

#[cfg(target_os = "windows")]
pub unsafe fn resolve_by_hash(module_base: *mut u8, target_hash: u32) -> *mut u8 {
    let dos_magic = *(module_base as *const u16);
    if dos_magic != 0x5A4D {
        return std::ptr::null_mut();
    }
    let e_lfanew = *(module_base.add(0x3C) as *const i32);
    let nt = module_base.add(e_lfanew as usize);
    let export_rva = *(nt.add(0x88) as *const u32);
    if export_rva == 0 {
        return std::ptr::null_mut();
    }
    let export_dir = module_base.add(export_rva as usize);
    let num_names = *(export_dir.add(0x18) as *const u32);
    let addr_of_functions = *(export_dir.add(0x1C) as *const u32);
    let addr_of_names = *(export_dir.add(0x20) as *const u32);
    let addr_of_ordinals = *(export_dir.add(0x24) as *const u32);

    for i in 0..num_names {
        let name_rva = *(module_base.add(addr_of_names as usize).add(i as usize * 4) as *const u32);
        let name_ptr = module_base.add(name_rva as usize);
        let name_len = (0usize..).find(|&j| *name_ptr.add(j) == 0).unwrap_or(0);
        let name_slice = std::slice::from_raw_parts(name_ptr, name_len);
        if hash_name(name_slice) == target_hash {
            let ordinal = *(module_base.add(addr_of_ordinals as usize).add(i as usize * 2) as *const u16);
            let func_rva = *(module_base.add(addr_of_functions as usize).add(ordinal as usize * 4) as *const u32);
            return module_base.add(func_rva as usize);
        }
    }
    std::ptr::null_mut()
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
    let min_ms = random_int(3, 27);                                                                     
    let max_ms = random_int(31, 220);                                                         
    println!("Minimum sleep time:\t{} ms", min_ms);                                                     
    println!("Maximum sleep time:\t{} ms", max_ms);

    let _ = sleep_jitter_range(min_ms,max_ms);
}

pub fn sleep_jitter_random() {
    let min_ms = random_int(3, 27);                                                                     
    let max_ms = random_int(31, 180);                                                         
    println!("Minimum sleep time:\t{} ms", min_ms);                                                     
    println!("Maximum sleep time:\t{} ms", max_ms);

    let _ = sleep_jitter_range(min_ms,max_ms);
}